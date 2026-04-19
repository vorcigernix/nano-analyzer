package github

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ChangedFileDetector struct{}

func NewChangedFileDetector() ChangedFileDetector {
	return ChangedFileDetector{}
}

func (ChangedFileDetector) ChangedFiles(ctx context.Context, repoDir string) ([]string, error) {
	base, head, err := refsFromEvent()
	if err != nil {
		return gitDiff(ctx, repoDir, "HEAD~1", "HEAD")
	}
	if base == "" || head == "" {
		return gitDiff(ctx, repoDir, "HEAD~1", "HEAD")
	}
	files, err := gitDiff(ctx, repoDir, base, head)
	if err == nil {
		return files, nil
	}
	fallback, fallbackErr := gitDiff(ctx, repoDir, "HEAD~1", "HEAD")
	if fallbackErr == nil {
		return fallback, nil
	}
	return nil, err
}

func refsFromEvent() (string, string, error) {
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return "", "", errors.New("GITHUB_EVENT_PATH is not set")
	}
	content, err := os.ReadFile(eventPath)
	if err != nil {
		return "", "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(content, &payload); err != nil {
		return "", "", err
	}
	if pr, ok := payload["pull_request"].(map[string]any); ok {
		base := nestedString(pr, "base", "sha")
		head := nestedString(pr, "head", "sha")
		return base, head, nil
	}
	before, _ := payload["before"].(string)
	after, _ := payload["after"].(string)
	return before, after, nil
}

func gitDiff(ctx context.Context, repoDir, base, head string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "--diff-filter=AM", base, head)
	cmd.Dir = repoDir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		files = append(files, filepath.ToSlash(line))
	}
	return files, nil
}

func nestedString(obj map[string]any, keys ...string) string {
	var current any = obj
	for _, key := range keys {
		next, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = next[key]
	}
	value, _ := current.(string)
	return value
}
