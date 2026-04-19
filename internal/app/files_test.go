package app

import (
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
