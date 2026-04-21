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
	provider       Provider
	openAIKey      string
	openRouterKey  string
	httpClient     *http.Client
	maxRetries     int
	semaphore      chan struct{}
	randMu         sync.Mutex
	stateMu        sync.Mutex
	rateLimitUntil time.Time
	referer        string
	title          string
	logf           func(format string, args ...any)
	now            func() time.Time
	sleep          func(context.Context, time.Duration) error
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
		now:        time.Now,
		sleep:      sleepContext,
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

func WithLogger(logf func(format string, args ...any)) Option {
	return func(c *Client) {
		c.logf = logf
	}
}

func WithNow(now func() time.Time) Option {
	return func(c *Client) {
		if now != nil {
			c.now = now
		}
	}
}

func WithSleep(sleep func(context.Context, time.Duration) error) Option {
	return func(c *Client) {
		if sleep != nil {
			c.sleep = sleep
		}
	}
}

func (c *Client) SetLogger(logf func(format string, args ...any)) {
	c.logf = logf
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
	for attempt := 0; attempt < c.maxRetries; {
		if err := c.sleepBeforeAttempt(ctx, attempt); err != nil {
			return ports.ChatResponse{}, err
		}
		start := time.Now()
		resp, err := c.post(ctx, backend, body)
		elapsed := time.Since(start).Seconds()
		if err != nil {
			if status, ok := asRetryableStatus(err); ok && status.rateLimited {
				if wait := c.noteRateLimit(status); wait > 0 {
					if err := c.sleep(ctx, wait); err != nil {
						return ports.ChatResponse{}, err
					}
				}
				lastErr = err
				continue
			}
			if !retryableError(err) || attempt == c.maxRetries-1 {
				return ports.ChatResponse{}, err
			}
			lastErr = err
			attempt++
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
	if err := c.acquireSlot(ctx); err != nil {
		return ports.ChatResponse{}, err
	}
	defer func() { <-c.semaphore }()

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
		return ports.ChatResponse{}, retryableStatus{
			status:      httpResp.StatusCode,
			body:        string(responseText),
			rateLimited: isRateLimitResponse(httpResp.StatusCode, responseText),
		}
	}
	if isRateLimitResponse(httpResp.StatusCode, responseText) {
		return ports.ChatResponse{}, retryableStatus{
			status:      httpResp.StatusCode,
			body:        string(responseText),
			rateLimited: true,
		}
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
	status      int
	body        string
	rateLimited bool
}

func (e retryableStatus) Error() string {
	return fmt.Sprintf("api %d: %s", e.status, trim(e.body, 200))
}

func retryableError(err error) bool {
	var status retryableStatus
	return errors.As(err, &status)
}

func asRetryableStatus(err error) (retryableStatus, bool) {
	var status retryableStatus
	if errors.As(err, &status) {
		return status, true
	}
	return retryableStatus{}, false
}

func (c *Client) sleepBeforeAttempt(ctx context.Context, attempt int) error {
	if err := c.waitForRateLimitReset(ctx); err != nil {
		return err
	}
	var delay time.Duration
	if attempt == 0 {
		delay = time.Duration(c.jitterMillis(100, 3000)) * time.Millisecond
	} else {
		delay = time.Duration(1<<attempt)*time.Second + time.Duration(c.jitterMillis(0, 2000))*time.Millisecond
	}
	if delay <= 0 {
		return nil
	}
	return c.sleep(ctx, delay)
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

func (c *Client) waitForRateLimitReset(ctx context.Context) error {
	wait := c.rateLimitWait()
	if wait <= 0 {
		return nil
	}
	return c.sleep(ctx, wait)
}

func (c *Client) acquireSlot(ctx context.Context) error {
	for {
		if err := c.waitForRateLimitReset(ctx); err != nil {
			return err
		}
		select {
		case c.semaphore <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		if wait := c.rateLimitWait(); wait > 0 {
			<-c.semaphore
			if err := c.sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return nil
	}
}

func (c *Client) rateLimitWait() time.Duration {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	wait := c.rateLimitUntil.Sub(c.now())
	if wait <= 0 {
		c.rateLimitUntil = time.Time{}
		return 0
	}
	return wait
}

func (c *Client) noteRateLimit(status retryableStatus) time.Duration {
	now := c.now()
	until := nextMinuteBoundary(now)
	wait := until.Sub(now)
	if wait <= 0 {
		wait = time.Second
		until = now.Add(wait)
	}

	var extended bool
	c.stateMu.Lock()
	if until.After(c.rateLimitUntil) {
		c.rateLimitUntil = until
		extended = true
	}
	c.stateMu.Unlock()

	if extended && c.logf != nil {
		c.logf(
			"llm: rate limited (api %d); retrying at %s (%s)",
			status.status,
			until.Format("15:04:05"),
			wait.Round(time.Second),
		)
	}
	return wait
}

func nextMinuteBoundary(now time.Time) time.Time {
	return now.Truncate(time.Minute).Add(time.Minute)
}

func isRateLimitResponse(statusCode int, body []byte) bool {
	text := strings.ToLower(string(body))
	if strings.Contains(text, "insufficient_quota") || strings.Contains(text, "quota exceeded") {
		return false
	}
	if statusCode == http.StatusTooManyRequests {
		return strings.Contains(text, "rate limit") ||
			strings.Contains(text, "too many requests") ||
			strings.Contains(text, "requests per min") ||
			strings.Contains(text, "rpm") ||
			text == ""
	}
	return strings.Contains(text, "rate limit reached") || strings.Contains(text, "too many requests")
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ ports.LLMClient = (*Client)(nil)
