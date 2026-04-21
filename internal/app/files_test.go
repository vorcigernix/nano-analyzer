package app

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFilterChangedPaths(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, "src")
	tests := []string{
		filepath.Join(repo, "src", "a.c"),
		filepath.Join(repo, "docs", "note.md"),
		filepath.Join(repo, "src", "nested", "b.go"),
	}
	changed := []string{"src/a.c", "docs/note.md", "src/nested/b.go"}
	got := filterChangedPaths(changed, []string{src}, repo)
	want := []string{tests[0], tests[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterChangedPaths() = %#v, want %#v", got, want)
	}
}

func TestSupportedExtension(t *testing.T) {
	if !SupportedExtension("main.go", DefaultExtensions) {
		t.Fatal("expected .go to be supported")
	}
	if SupportedExtension("README.md", DefaultExtensions) {
		t.Fatal("did not expect .md to be supported")
	}
}

func TestNormalizeMakesRepoDirAbsolute(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Paths = []string{"."}
	cfg.RepoDir = "."
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.RepoDir) {
		t.Fatalf("expected absolute repo dir, got %s", cfg.RepoDir)
	}
}

func TestNormalizeMakesOutputDirAbsolute(t *testing.T) {
	tmp := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	cfg := DefaultConfig()
	cfg.Paths = []string{"."}
	cfg.RepoDir = "."
	cfg.OutputDir = "results"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs("results")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutputDir != want {
		t.Fatalf("expected output dir %s, got %s", want, cfg.OutputDir)
	}
}

func TestDefaultOutputRootUsesCurrentWorkingDirectory(t *testing.T) {
	tmp := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	}()

	root, err := DefaultOutputRoot()
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs("nano-analyzer-results")
	if err != nil {
		t.Fatal(err)
	}
	if root != want {
		t.Fatalf("expected output root %s, got %s", want, root)
	}
}

func TestDefaultOutputRootReturnsAbsolutePath(t *testing.T) {
	root, err := DefaultOutputRoot()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(root) {
		t.Fatalf("expected absolute output root, got %s", root)
	}
	if _, err := os.Stat(filepath.Dir(root)); err != nil {
		t.Fatalf("expected parent dir to exist: %v", err)
	}
}

func TestDiscoverSourceFilesSkipsGitignoredFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}

	repo := t.TempDir()
	runGit(t, repo, "init")

	writeTestFile(t, filepath.Join(repo, ".gitignore"), "ignored.go\nignored-dir/\n")
	writeTestFile(t, filepath.Join(repo, "tracked.go"), "package main\n")
	writeTestFile(t, filepath.Join(repo, "ignored.go"), "package ignored\n")
	writeTestFile(t, filepath.Join(repo, "ignored-dir", "inside.go"), "package ignored\n")

	cfg := DefaultConfig()
	cfg.Paths = []string{repo}
	cfg.RepoDir = repo

	files, skipped, err := DiscoverSourceFiles(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 scannable file, got %d", len(files))
	}
	if files[0].DisplayName != "tracked.go" {
		t.Fatalf("expected tracked.go to be scanned, got %s", files[0].DisplayName)
	}

	assertSkippedReason(t, skipped, filepath.Join(repo, "ignored.go"), "gitignore")
	assertSkippedReason(t, skipped, filepath.Join(repo, "ignored-dir", "inside.go"), "gitignore")
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertSkippedReason(t *testing.T, skipped []SkippedFile, path, reason string) {
	t.Helper()
	for _, entry := range skipped {
		if entry.Path == path && entry.Reason == reason {
			return
		}
	}
	t.Fatalf("expected skipped entry %s (%s), got %#v", path, reason, skipped)
}
