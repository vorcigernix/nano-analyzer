package search

import (
	"bufio"
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/weareaisle/nano-analyzer/internal/ports"
)

type GrepSearcher struct {
	RepoDir string
	RGPath  string
	Timeout time.Duration
}

func NewGrepSearcher(repoDir string) *GrepSearcher {
	return &GrepSearcher{
		RepoDir: repoDir,
		RGPath:  "rg",
		Timeout: 60 * time.Second,
	}
}

func (s *GrepSearcher) Search(ctx context.Context, pattern string) ([]ports.SearchMatch, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, nil
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.RGPath, "--no-heading", "-n", "--fixed-strings", pattern)
	cmd.Dir = s.RepoDir
	output, err := cmd.Output()
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseRGOutput(output), nil
}

func parseRGOutput(output []byte) []ports.SearchMatch {
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	matches := make([]ports.SearchMatch, 0)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		lineNo, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		matches = append(matches, ports.SearchMatch{
			Path: filepath.ToSlash(parts[0]),
			Line: lineNo,
			Text: parts[2],
		})
	}
	return matches
}

var _ ports.Searcher = (*GrepSearcher)(nil)
