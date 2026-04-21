package app

import (
	"os"
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
	t.Chdir(tmp)

	cfg := DefaultConfig()
	cfg.Paths = []string{"."}
	cfg.RepoDir = "."
	cfg.OutputDir = "results"
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "results")
	if cfg.OutputDir != want {
		t.Fatalf("expected output dir %s, got %s", want, cfg.OutputDir)
	}
}

func TestDefaultOutputRootUsesCurrentWorkingDirectory(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)

	root, err := DefaultOutputRoot()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "nano-analyzer-results")
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
