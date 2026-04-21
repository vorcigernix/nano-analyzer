package app

import "testing"

func TestDefaultConfigUsesGPT54Nano(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Model != "gpt-5.4-nano" {
		t.Fatalf("DefaultConfig().Model = %q, want %q", cfg.Model, "gpt-5.4-nano")
	}
}
