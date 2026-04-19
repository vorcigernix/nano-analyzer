package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

const (
	DefaultModel           = "gpt-5.4-nano"
	DefaultParallel        = 50
	DefaultTriageParallel  = 50
	DefaultMaxChars        = 200_000
	DefaultTriageRounds    = 5
	DefaultTriageThreshold = domain.SeverityMedium
	DefaultFailOn          = domain.SeverityHigh
	DefaultFailConfidence  = 0.70
)

var DefaultExtensions = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true,
	".hpp": true, ".hxx": true, ".java": true, ".py": true, ".go": true,
	".rs": true, ".js": true, ".ts": true, ".rb": true, ".swift": true,
	".m": true, ".mm": true, ".cs": true, ".php": true, ".pl": true,
	".sh": true, ".x": true,
}

type Config struct {
	Paths             []string
	Model             string
	Provider          string
	OutputDir         string
	Formats           map[string]bool
	Parallel          int
	MaxConnections    int
	MaxChars          int
	TriageMode        string
	TriageThreshold   domain.Severity
	TriageRounds      int
	TriageParallel    int
	MinConfidence     float64
	FailOn            domain.Severity
	FailConfidence    float64
	FailMode          string
	Scope             string
	Project           string
	RepoDir           string
	VerboseTriage     bool
	Extensions        map[string]bool
	GitHubStepSummary string
}

func DefaultConfig() Config {
	return Config{
		Model:           DefaultModel,
		Provider:        "auto",
		Formats:         ParseFormats("json,markdown,sarif"),
		Parallel:        DefaultParallel,
		MaxChars:        DefaultMaxChars,
		TriageMode:      "enabled",
		TriageThreshold: DefaultTriageThreshold,
		TriageRounds:    DefaultTriageRounds,
		TriageParallel:  DefaultTriageParallel,
		MinConfidence:   0,
		FailOn:          DefaultFailOn,
		FailConfidence:  DefaultFailConfidence,
		FailMode:        "never",
		Scope:           "all",
		Extensions:      DefaultExtensions,
	}
}

func ParseFormats(value string) map[string]bool {
	formats := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			formats[part] = true
		}
	}
	return formats
}

func (c *Config) Normalize() error {
	if len(c.Paths) == 0 {
		c.Paths = []string{"."}
	}
	if c.Model == "" {
		c.Model = DefaultModel
	}
	if c.Provider == "" {
		c.Provider = "auto"
	}
	switch c.Provider {
	case "auto", "openai", "openrouter":
	default:
		return fmt.Errorf("unsupported provider %q", c.Provider)
	}
	if len(c.Formats) == 0 {
		c.Formats = ParseFormats("json,markdown,sarif")
	}
	if c.Parallel <= 0 {
		c.Parallel = DefaultParallel
	}
	if c.TriageParallel <= 0 {
		c.TriageParallel = DefaultTriageParallel
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = c.Parallel + c.TriageParallel
	}
	if c.MaxChars <= 0 {
		c.MaxChars = DefaultMaxChars
	}
	switch c.TriageMode {
	case "", "enabled":
		c.TriageMode = "enabled"
	case "disabled":
	default:
		return fmt.Errorf("unsupported triage mode %q", c.TriageMode)
	}
	if c.TriageRounds <= 0 {
		c.TriageRounds = DefaultTriageRounds
	}
	if c.FailConfidence < 0 || c.FailConfidence > 1 {
		return fmt.Errorf("fail confidence must be between 0 and 1")
	}
	if c.MinConfidence < 0 || c.MinConfidence > 1 {
		return fmt.Errorf("min confidence must be between 0 and 1")
	}
	switch c.FailMode {
	case "", "never":
		c.FailMode = "never"
	case "validated", "raw":
	default:
		return fmt.Errorf("unsupported fail mode %q", c.FailMode)
	}
	switch c.Scope {
	case "", "all":
		c.Scope = "all"
	case "changed":
	default:
		return fmt.Errorf("unsupported scope %q", c.Scope)
	}
	if len(c.Extensions) == 0 {
		c.Extensions = DefaultExtensions
	}
	if c.RepoDir == "" {
		repo, err := inferRepoDir(c.Paths[0])
		if err != nil {
			return err
		}
		c.RepoDir = repo
	}
	absRepo, err := filepath.Abs(c.RepoDir)
	if err != nil {
		return err
	}
	c.RepoDir = absRepo
	if c.Project == "" {
		c.Project = filepath.Base(c.RepoDir)
		if c.Project == "." || c.Project == string(filepath.Separator) || c.Project == "" {
			c.Project = "project"
		}
	}
	return nil
}

func DefaultOutputRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, "nano-analyzer-results"), nil
}

func inferRepoDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return filepath.Abs(path)
	}
	return filepath.Abs(filepath.Dir(path))
}

func SupportedExtension(path string, extensions map[string]bool) bool {
	return extensions[strings.ToLower(filepath.Ext(path))]
}
