package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/weareaisle/nano-analyzer/internal/ports"
)

const (
	OpenRouterAPIURL = "https://openrouter.ai/api/v1/chat/completions"
	OpenAIAPIURL     = "https://api.openai.com/v1/chat/completions"
)

type Provider string

const (
	ProviderAuto       Provider = "auto"
	ProviderOpenAI     Provider = "openai"
	ProviderOpenRouter Provider = "openrouter"
)

type Client struct {
	provider      Provider
	openAIKey     string
	openRouterKey string
	httpClient    *http.Client
	maxRetries    int
	semaphore     chan struct{}
	randMu        sync.Mutex
	referer       string
	title         string
}

type Option func(*Client)

func NewClient(provider string, maxConcurrent int, opts ...Option) *Client {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	client := &Client{
		provider:      Provider(provider),
		openAIKey:     os.Getenv("OPENAI_API_KEY"),
		openRouterKey: os.Getenv("OPENROUTER_API_KEY"),
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		maxRetries: 3,
		semaphore:  make(chan struct{}, maxConcurrent),
		referer:    "https://github.com/weareaisle/nano-analyzer",
		title:      "nano-analyzer",
	}
	if client.provider == "" {
		client.provider = ProviderAuto
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

func WithKeys(openAIKey, openRouterKey string) Option {
	return func(c *Client) {
		c.openAIKey = openAIKey
		c.openRouterKey = openRouterKey
	}
}

func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		if httpClient != nil {
			c.httpClient = httpClient
		}
	}
}

func WithMaxRetries(maxRetries int) Option {
	return func(c *Client) {
		if maxRetries >= 1 {
			c.maxRetries = maxRetries
		}
	}
}

type Backend struct {
	URL          string
	APIKey       string
	Model        string
	ExtraHeaders map[string]string
	Provider     Provider
}

func (c *Client) ResolveBackend(model string) (Backend, error) {
	provider := c.provider
	if provider == ProviderAuto {
		if strings.Contains(model, "/") {
			provider = ProviderOpenRouter
		} else {
			provider = ProviderOpenAI
		}
	}
	switch provider {
	case ProviderOpenRouter:
		if c.openRouterKey == "" {
			return Backend{}, fmt.Errorf("model %q uses OpenRouter but OPENROUTER_API_KEY is not set", model)
		}
		return Backend{
			URL:    OpenRouterAPIURL,
			APIKey: c.openRouterKey,
			Model:  model,
			ExtraHeaders: map[string]string{
				"HTTP-Referer": c.referer,
				"X-Title":      c.title,
			},
			Provider: ProviderOpenRouter,
		}, nil
	case ProviderOpenAI:
		if c.openAIKey == "" {
			return Backend{}, fmt.Errorf("model %q uses OpenAI but OPENAI_API_KEY is not set", model)
		}
		return Backend{
			URL:      OpenAIAPIURL,
			APIKey:   c.openAIKey,
			Model:    model,
			Provider: ProviderOpenAI,
		}, nil
	default:
		return Backend{}, fmt.Errorf("unsupported provider %q", c.provider)
	}
}

func (c *Client) Chat(ctx context.Context, request ports.ChatRequest) (ports.ChatResponse, error) {
	backend, err := c.ResolveBackend(request.Model)
	if err != nil {
		return ports.ChatResponse{}, err
	}
	payload := map[string]any{
		"model":    backend.Model,
		"messages": request.Messages,
	}
	if request.JSONMode {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}
	if request.ReasoningEffort != "" {
		payload["reasoning_effort"] = request.ReasoningEffort
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ports.ChatResponse{}, err
	}

	var lastErr error
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		if err := c.sleepBeforeAttempt(ctx, attempt); err != nil {
			return ports.ChatResponse{}, err
		}
		start := time.Now()
		resp, err := c.post(ctx, backend, body)
		elapsed := time.Since(start).Seconds()
		if err != nil {
			if !retryableError(err) || attempt == c.maxRetries-1 {
				return ports.ChatResponse{}, err
			}
			lastErr = err
			continue
		}
		resp.ElapsedSeconds = elapsed
		return resp, nil
	}
	if lastErr != nil {
		return ports.ChatResponse{}, lastErr
	}
	return ports.ChatResponse{}, errors.New("max retries exceeded")
}

func (c *Client) post(ctx context.Context, backend Backend, body []byte) (ports.ChatResponse, error) {
	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return ports.ChatResponse{}, ctx.Err()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backend.URL, bytes.NewReader(body))
	if err != nil {
		return ports.ChatResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+backend.APIKey)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range backend.ExtraHeaders {
		req.Header.Set(key, value)
	}
	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return ports.ChatResponse{}, err
	}
	defer httpResp.Body.Close()
	responseText, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return ports.ChatResponse{}, err
	}
	if httpResp.StatusCode == http.StatusTooManyRequests || httpResp.StatusCode >= 500 {
		return ports.ChatResponse{}, retryableStatus{status: httpResp.StatusCode, body: string(responseText)}
	}
	if httpResp.StatusCode != http.StatusOK {
		return ports.ChatResponse{}, fmt.Errorf("api %d: %s", httpResp.StatusCode, trim(string(responseText), 400))
	}

	var decoded chatCompletionResponse
	if err := json.Unmarshal(responseText, &decoded); err != nil {
		return ports.ChatResponse{}, err
	}
	if decoded.Error != nil {
		return ports.ChatResponse{}, fmt.Errorf("api error: %v", decoded.Error)
	}
	if len(decoded.Choices) == 0 {
		return ports.ChatResponse{}, errors.New("api response contained no choices")
	}
	content := decoded.Choices[0].Message.Content
	if content == "" {
		content = decoded.Choices[0].Message.ReasoningContent
	}
	return ports.ChatResponse{
		Content:          content,
		PromptTokens:     decoded.Usage.PromptTokens,
		CompletionTokens: decoded.Usage.CompletionTokens,
		TotalTokens:      decoded.Usage.TotalTokens,
	}, nil
}

type chatCompletionResponse struct {
	Choices []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error any `json:"error"`
}

type retryableStatus struct {
	status int
	body   string
}

func (e retryableStatus) Error() string {
	return fmt.Sprintf("api %d: %s", e.status, trim(e.body, 200))
}

func retryableError(err error) bool {
	var status retryableStatus
	return errors.As(err, &status)
}

func (c *Client) sleepBeforeAttempt(ctx context.Context, attempt int) error {
	var delay time.Duration
	if attempt == 0 {
		delay = time.Duration(c.jitterMillis(100, 3000)) * time.Millisecond
	} else {
		delay = time.Duration(1<<attempt)*time.Second + time.Duration(c.jitterMillis(0, 2000))*time.Millisecond
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) jitterMillis(min, max int) int {
	if max <= min {
		return min
	}
	c.randMu.Lock()
	defer c.randMu.Unlock()
	return min + rand.Intn(max-min)
}

func trim(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}

var _ ports.LLMClient = (*Client)(nil)
