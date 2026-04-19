package github

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestChangedFilesFromPullRequestEvent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	repo := t.TempDir()
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(repo, "a.c"), []byte("int a;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "base")
	base := gitOutput(t, repo, "rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(repo, "a.c"), []byte("int a = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "b.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "head")
	head := gitOutput(t, repo, "rev-parse", "HEAD")

	eventPath := filepath.Join(repo, "event.json")
	event := `{"pull_request":{"base":{"sha":"` + base + `"},"head":{"sha":"` + head + `"}}}`
	if err := os.WriteFile(eventPath, []byte(event), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", eventPath)

	got, err := NewChangedFileDetector().ChangedFiles(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"a.c", "b.go"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ChangedFiles() = %#v, want %#v", got, want)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v failed: %v", args, err)
	}
	return string(output[:len(output)-1])
}
