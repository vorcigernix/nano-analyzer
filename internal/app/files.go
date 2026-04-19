package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/weareaisle/nano-analyzer/internal/domain"
	"github.com/weareaisle/nano-analyzer/internal/ports"
)

type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func DiscoverSourceFiles(ctx context.Context, cfg Config, detector ports.ChangedFileDetector) ([]domain.SourceFile, []SkippedFile, error) {
	candidates, err := candidatePaths(ctx, cfg, detector)
	if err != nil {
		return nil, nil, err
	}
	files := make([]domain.SourceFile, 0, len(candidates))
	skipped := make([]SkippedFile, 0)

	basePath := cfg.RepoDir
	if len(cfg.Paths) == 1 {
		if info, err := os.Stat(cfg.Paths[0]); err == nil && info.IsDir() && cfg.Scope != "changed" {
			basePath, _ = filepath.Abs(cfg.Paths[0])
		}
	}

	for _, candidate := range candidates {
		select {
		case <-ctx.Done():
			return nil, skipped, ctx.Err()
		default:
		}
		source, skip, err := sourceFile(candidate, basePath, cfg.Extensions, cfg.MaxChars)
		if err != nil {
			return nil, skipped, err
		}
		if skip != nil {
			skipped = append(skipped, *skip)
			continue
		}
		files = append(files, source)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].DisplayName < files[j].DisplayName })
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	return files, skipped, nil
}

func candidatePaths(ctx context.Context, cfg Config, detector ports.ChangedFileDetector) ([]string, error) {
	if cfg.Scope == "changed" {
		if detector == nil {
			return nil, errors.New("changed-file detector is required for changed scope")
		}
		changed, err := detector.ChangedFiles(ctx, cfg.RepoDir)
		if err != nil {
			return nil, err
		}
		if len(changed) == 0 {
			return nil, nil
		}
		return filterChangedPaths(changed, cfg.Paths, cfg.RepoDir), nil
	}

	var candidates []string
	for _, root := range cfg.Paths {
		info, err := os.Lstat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			candidates = append(candidates, root)
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "target" || name == "dist" || name == "build" {
					return filepath.SkipDir
				}
				return nil
			}
			candidates = append(candidates, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(candidates)
	return candidates, nil
}

func filterChangedPaths(changed []string, roots []string, repoDir string) []string {
	absRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		absRoots = append(absRoots, filepath.Clean(abs))
	}
	var candidates []string
	seen := map[string]bool{}
	for _, path := range changed {
		if path == "" {
			continue
		}
		abs := path
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(repoDir, path)
		}
		abs = filepath.Clean(abs)
		if !withinAnyRoot(abs, absRoots) || seen[abs] {
			continue
		}
		seen[abs] = true
		candidates = append(candidates, abs)
	}
	sort.Strings(candidates)
	return candidates
}

func withinAnyRoot(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func sourceFile(path, basePath string, extensions map[string]bool, maxChars int) (domain.SourceFile, *SkippedFile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: "unreadable"}, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: "symlink"}, nil
	}
	if info.IsDir() {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: "directory"}, nil
	}
	if !SupportedExtension(path, extensions) {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: "extension"}, nil
	}
	if info.Size() > int64(maxChars) {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: fmt.Sprintf("too large (%d bytes)", info.Size())}, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: "unreadable"}, nil
	}
	if len(content) > maxChars {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: fmt.Sprintf("too large (%d chars)", len(content))}, nil
	}
	if !isLikelyText(content) {
		return domain.SourceFile{}, &SkippedFile{Path: path, Reason: "binary"}, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return domain.SourceFile{}, nil, err
	}
	display := abs
	if rel, err := filepath.Rel(basePath, abs); err == nil && !strings.HasPrefix(rel, "..") {
		display = rel
	}
	return domain.SourceFile{
		Path:        abs,
		DisplayName: filepath.ToSlash(display),
		Content:     string(content),
		Lines:       strings.Count(string(content), "\n"),
		Chars:       len(content),
	}, nil, nil
}

func isLikelyText(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return false
		}
	}
	return true
}
