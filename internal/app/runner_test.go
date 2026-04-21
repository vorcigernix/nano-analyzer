package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/weareaisle/nano-analyzer/internal/adapters/output"
	"github.com/weareaisle/nano-analyzer/internal/domain"
	"github.com/weareaisle/nano-analyzer/internal/ports"
)

type fakeLLM struct {
	mu        sync.Mutex
	responses []string
}

func (f *fakeLLM) Chat(ctx context.Context, request ports.ChatRequest) (ports.ChatResponse, error) {
	_ = ctx
	_ = request
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.responses) == 0 {
		return ports.ChatResponse{Content: `{"verdict":"VALID","reasoning":"arbiter"}`}, nil
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	return ports.ChatResponse{Content: resp, TotalTokens: 10, ElapsedSeconds: 0.1}, nil
}

type fakeSearcher struct{}

func (fakeSearcher) Search(ctx context.Context, pattern string) ([]ports.SearchMatch, error) {
	_ = ctx
	return []ports.SearchMatch{{Path: "src/vuln.c", Line: 1, Text: "#define MAX 8 // " + pattern}}, nil
}

func TestRunnerEndToEndWithFakeAdapters(t *testing.T) {
	repo := t.TempDir()
	srcDir := filepath.Join(repo, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(srcDir, "vuln.c")
	if err := os.WriteFile(sourcePath, []byte("void parse(char *s){char b[8]; strcpy(b,s);}"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(repo, "out")
	cfg := DefaultConfig()
	cfg.Paths = []string{srcDir}
	cfg.RepoDir = repo
	cfg.OutputDir = outDir
	cfg.Parallel = 1
	cfg.TriageParallel = 1
	cfg.TriageRounds = 1
	cfg.FailMode = "validated"
	cfg.FailOn = domain.SeverityHigh
	cfg.FailConfidence = 1
	cfg.Formats = ParseFormats("json,markdown,sarif")

	llm := &fakeLLM{responses: []string{
		"Context. GREP: MAX",
		`[{"severity":"high","title":"Stack buffer overflow","function":"parse()","description":"strcpy into b[8]"}]`,
		`{"verdict":"VALID","reasoning":"attacker controls s","crux":"strcpy is unbounded","grep":"strcpy"}`,
	}}
	runner := Runner{
		LLM:      llm,
		Searcher: fakeSearcher{},
		Writer:   output.NewWriter(outDir, cfg.Formats, ""),
	}
	summary, err := runner.Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.ShouldFail {
		t.Fatal("expected validated high finding to fail")
	}
	if summary.FilesScanned != 1 || len(summary.Triage) != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	for _, path := range []string{
		filepath.Join(outDir, "summary.json"),
		filepath.Join(outDir, "summary.md"),
		filepath.Join(outDir, "pr-comment.md"),
		filepath.Join(outDir, "results.sarif"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	content, err := os.ReadFile(filepath.Join(outDir, "triage_survivors.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Stack buffer overflow") {
		t.Fatalf("survivor output missing finding: %s", string(content))
	}
}

func TestRunnerLogsLiveProgress(t *testing.T) {
	repo := t.TempDir()
	srcDir := filepath.Join(repo, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(srcDir, "vuln.c")
	if err := os.WriteFile(sourcePath, []byte("void parse(char *s){char b[8]; strcpy(b,s);}"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(repo, "out")
	cfg := DefaultConfig()
	cfg.Paths = []string{srcDir}
	cfg.RepoDir = repo
	cfg.OutputDir = outDir
	cfg.Parallel = 1
	cfg.TriageParallel = 1
	cfg.TriageRounds = 1
	cfg.VerboseTriage = true
	cfg.Formats = ParseFormats("json")

	llm := &fakeLLM{responses: []string{
		"Context. GREP: MAX",
		`[{"severity":"high","title":"Stack buffer overflow","function":"parse()","description":"strcpy into b[8]"}]`,
		`{"verdict":"VALID","reasoning":"attacker controls s","crux":"strcpy is unbounded","grep":"strcpy"}`,
	}}
	var logs []string
	runner := Runner{
		LLM:      llm,
		Searcher: fakeSearcher{},
		Writer:   output.NewWriter(outDir, cfg.Formats, ""),
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
	}
	if _, err := runner.Run(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}

	expected := []string{
		"scan: starting 1 file(s) with 1 worker(s)",
		"scan 1/1 vuln.c high findings=1 totals issues=1 c=0 h=1 m=0 l=0 i=0 err=0",
		"scan: complete 1/1 totals issues=1 c=0 h=1 m=0 l=0 i=0 err=0",
		"triage: evaluating 1 finding(s) at or above medium with 1 worker(s)",
		"triage 1/1 vuln.c Stack buffer overflow: VALID 100% rounds=V totals valid=1 invalid=0 uncertain=0 error=0",
		"triage: complete 1/1 totals valid=1 invalid=0 uncertain=0 error=0",
	}
	for _, want := range expected {
		if !containsLogLine(logs, want) {
			t.Fatalf("missing log line %q in %#v", want, logs)
		}
	}
}

func containsLogLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}
