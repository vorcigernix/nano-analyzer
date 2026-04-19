package llm

import "testing"

func TestResolveBackendAutoOpenAI(t *testing.T) {
	client := NewClient("auto", 1, WithKeys("openai-key", "router-key"))
	backend, err := client.ResolveBackend("gpt-5-nano")
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
	if _, err := client.ResolveBackend("gpt-5-nano"); err == nil {
		t.Fatal("expected missing key error")
	}
}
