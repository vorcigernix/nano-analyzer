package llm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/weareaisle/nano-analyzer/internal/ports"
)

func TestResolveBackendAutoOpenAI(t *testing.T) {
	client := NewClient("auto", 1, WithKeys("openai-key", "router-key"))
	backend, err := client.ResolveBackend("gpt-4o-mini")
	if err != nil {
		t.Fatal(err)
	}
	if backend.Provider != ProviderOpenAI || backend.APIKey != "openai-key" {
		t.Fatalf("unexpected backend: %+v", backend)
	}
}

func TestResolveBackendAutoOpenRouter(t *testing.T) {
	client := NewClient("auto", 1, WithKeys("openai-key", "router-key"))
	backend, err := client.ResolveBackend("qwen/qwen3-32b")
	if err != nil {
		t.Fatal(err)
	}
	if backend.Provider != ProviderOpenRouter || backend.APIKey != "router-key" {
		t.Fatalf("unexpected backend: %+v", backend)
	}
}

func TestResolveBackendMissingKey(t *testing.T) {
	client := NewClient("openai", 1, WithKeys("", "router-key"))
	if _, err := client.ResolveBackend("gpt-4o-mini"); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestIsRateLimitResponse(t *testing.T) {
	if !isRateLimitResponse(http.StatusTooManyRequests, []byte(`{"error":{"message":"Rate limit reached for requests per min"}}`)) {
		t.Fatal("expected rate limit response to be detected")
	}
	if isRateLimitResponse(http.StatusTooManyRequests, []byte(`{"error":{"type":"insufficient_quota","message":"You exceeded your current quota"}}`)) {
		t.Fatal("did not expect insufficient quota to be treated as minute-based rate limiting")
	}
}

func TestChatWaitsForRateLimitAndRetries(t *testing.T) {
	var sleeps []time.Duration
	var logs []string
	now := time.Date(2026, 4, 21, 19, 12, 34, 0, time.UTC)
	currentNow := now

	client := NewClient(
		"openai",
		1,
		WithKeys("openai-key", ""),
		WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			if strings.Contains(string(body), `"model":"gpt-5.4-nano"`) {
				if len(sleeps) == 1 {
					return jsonResponse(http.StatusTooManyRequests, `{"error":{"message":"Rate limit reached for requests per min"}}`), nil
				}
				return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`), nil
			}
			return jsonResponse(http.StatusOK, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`), nil
		})}),
		WithNow(func() time.Time { return currentNow }),
		WithSleep(func(ctx context.Context, delay time.Duration) error {
			_ = ctx
			sleeps = append(sleeps, delay)
			currentNow = currentNow.Add(delay)
			return nil
		}),
		WithLogger(func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		}),
	)

	resp, err := client.Chat(context.Background(), ports.ChatRequest{
		Model:    "gpt-5.4-nano",
		Messages: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Content != "ok" {
		t.Fatalf("unexpected response content %q", resp.Content)
	}
	if len(sleeps) < 2 {
		t.Fatalf("expected attempt jitter and rate-limit sleep, got %#v", sleeps)
	}
	rateLimitedAt := now.Add(sleeps[0])
	if want := nextMinuteBoundary(rateLimitedAt).Sub(rateLimitedAt); sleeps[1] != want {
		t.Fatalf("expected rate-limit sleep %s, got %#v", want, sleeps)
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "rate limit") {
		t.Fatalf("expected rate-limit log, got %#v", logs)
	}
}

func TestAcquireSlotWaitsIfRateLimitAppearsWhileQueued(t *testing.T) {
	now := time.Date(2026, 4, 21, 19, 12, 34, 0, time.UTC)
	currentNow := now
	var mu sync.Mutex
	var sleeps []time.Duration
	firstCheck := make(chan struct{})
	firstCheckOnce := sync.Once{}

	client := NewClient(
		"openai",
		1,
		WithNow(func() time.Time {
			firstCheckOnce.Do(func() { close(firstCheck) })
			mu.Lock()
			defer mu.Unlock()
			return currentNow
		}),
		WithSleep(func(ctx context.Context, delay time.Duration) error {
			_ = ctx
			mu.Lock()
			defer mu.Unlock()
			sleeps = append(sleeps, delay)
			currentNow = currentNow.Add(delay)
			return nil
		}),
	)

	client.semaphore <- struct{}{}
	done := make(chan error, 1)
	go func() {
		done <- client.acquireSlot(context.Background())
	}()

	<-firstCheck
	client.stateMu.Lock()
	client.rateLimitUntil = nextMinuteBoundary(now)
	client.stateMu.Unlock()
	<-client.semaphore

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for queued acquireSlot call")
	}

	mu.Lock()
	gotSleeps := append([]time.Duration(nil), sleeps...)
	mu.Unlock()

	wantWait := nextMinuteBoundary(now).Sub(now)
	if len(gotSleeps) != 1 || gotSleeps[0] != wantWait {
		t.Fatalf("expected queued caller to sleep for %s, got %#v", wantWait, gotSleeps)
	}

	<-client.semaphore
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
