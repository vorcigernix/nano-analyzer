package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/weareaisle/nano-analyzer/internal/adapters/github"
	"github.com/weareaisle/nano-analyzer/internal/adapters/llm"
	"github.com/weareaisle/nano-analyzer/internal/adapters/output"
	"github.com/weareaisle/nano-analyzer/internal/adapters/search"
	"github.com/weareaisle/nano-analyzer/internal/app"
	"github.com/weareaisle/nano-analyzer/internal/domain"
)

const version = "0.2.11"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printRootUsage()
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "version", "--version", "-version":
		fmt.Println(version)
		return 0
	case "help", "--help", "-h":
		printRootUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printRootUsage()
		return 2
	}
}

func runScan(args []string) int {
	cfg := app.DefaultConfig()
	formatValue := "json,markdown,sarif"
	triageThreshold := string(cfg.TriageThreshold)
	failOn := string(cfg.FailOn)
	var quiet bool

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.Model, "model", cfg.Model, "model for context, scan, and triage stages")
	fs.StringVar(&cfg.Provider, "provider", cfg.Provider, "provider: auto, openai, openrouter")
	fs.StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "output directory; defaults to ./nano-analyzer-results/<timestamp>")
	fs.StringVar(&formatValue, "format", formatValue, "comma-separated outputs: json,markdown,sarif")
	fs.IntVar(&cfg.Parallel, "parallel", cfg.Parallel, "max concurrent file scans")
	fs.IntVar(&cfg.MaxConnections, "max-connections", cfg.MaxConnections, "max total concurrent API calls")
	fs.IntVar(&cfg.MaxChars, "max-chars", cfg.MaxChars, "skip files larger than this many bytes/chars")
	fs.StringVar(&cfg.TriageMode, "triage", cfg.TriageMode, "triage mode: enabled, disabled")
	fs.StringVar(&triageThreshold, "triage-threshold", triageThreshold, "triage findings at or above severity: critical, high, medium, low")
	fs.IntVar(&cfg.TriageRounds, "triage-rounds", cfg.TriageRounds, "triage rounds per finding")
	fs.IntVar(&cfg.TriageParallel, "triage-parallel", cfg.TriageParallel, "max concurrent triage findings")
	fs.Float64Var(&cfg.MinConfidence, "min-confidence", cfg.MinConfidence, "minimum confidence for survivor reporting")
	fs.StringVar(&failOn, "fail-on", failOn, "fail on findings at or above severity: critical, high, medium, low")
	fs.Float64Var(&cfg.FailConfidence, "fail-confidence", cfg.FailConfidence, "minimum confidence required to fail")
	fs.StringVar(&cfg.FailMode, "fail-mode", cfg.FailMode, "failure mode: never, validated, raw")
	fs.StringVar(&cfg.Scope, "scope", cfg.Scope, "scan scope: all, changed")
	fs.StringVar(&cfg.Project, "project", cfg.Project, "project name used in triage prompts")
	fs.StringVar(&cfg.RepoDir, "repo-dir", cfg.RepoDir, "repository root for grep and changed-file lookups")
	fs.StringVar(&cfg.GitHubStepSummary, "github-step-summary", os.Getenv("GITHUB_STEP_SUMMARY"), "GitHub step summary path")
	fs.BoolVar(&cfg.VerboseTriage, "verbose-triage", cfg.VerboseTriage, "show extra triage progress")
	fs.BoolVar(&quiet, "quiet", false, "suppress progress logs")
	fs.Usage = printScanUsage(fs)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	cfg.Paths = fs.Args()
	cfg.Formats = app.ParseFormats(formatValue)
	cfg.TriageThreshold = domain.NormalizeSeverity(triageThreshold)
	cfg.FailOn = domain.NormalizeSeverity(failOn)
	if err := cfg.Normalize(); err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 2
	}

	llmClient := llm.NewClient(cfg.Provider, cfg.MaxConnections)
	writer := output.NewWriter(cfg.OutputDir, cfg.Formats, cfg.GitHubStepSummary)
	runner := app.Runner{
		LLM:             llmClient,
		Searcher:        search.NewGrepSearcher(cfg.RepoDir),
		ChangedDetector: github.NewChangedFileDetector(),
		Writer:          writer,
	}
	var progress *terminalProgress
	if !quiet {
		progress = newTerminalProgress(os.Stderr)
		runner.Logf = progress.Logf
		llmClient.SetLogger(progress.Logf)
	}
	summary, err := runner.Run(context.Background(), cfg)
	if progress != nil {
		progress.Close()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 2
	}
	counts := domain.NewSeverityCounts()
	totalFindings := 0
	for _, result := range summary.Results {
		for _, sev := range domain.SeverityOrder {
			counts[sev] += result.Severities[sev]
		}
		totalFindings += len(result.Findings)
	}
	fmt.Printf(
		"nano-analyzer: scanned %d files, findings %d (critical=%d high=%d medium=%d low=%d informational=%d), output %s\n",
		summary.FilesScanned,
		totalFindings,
		counts[domain.SeverityCritical],
		counts[domain.SeverityHigh],
		counts[domain.SeverityMedium],
		counts[domain.SeverityLow],
		counts[domain.SeverityInformational],
		summary.OutputDir,
	)
	if summary.ErrorFiles > 0 {
		fmt.Fprintf(os.Stderr, "nano-analyzer: %d file(s) failed to scan\n", summary.ErrorFiles)
		return 2
	}
	if summary.ShouldFail {
		fmt.Fprintf(os.Stderr, "nano-analyzer: failure threshold met by %d finding(s)\n", len(summary.FailureFindings))
		return 1
	}
	return 0
}

func printRootUsage() {
	fmt.Fprintf(os.Stderr, "nano-analyzer %s\n\n", version)
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  nano-analyzer scan [flags] <path...>")
	fmt.Fprintln(os.Stderr, "  nano-analyzer version")
}

func printScanUsage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  nano-analyzer scan [flags] <path...>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  nano-analyzer scan ./src")
		fmt.Fprintln(os.Stderr, "  nano-analyzer scan --scope changed --fail-mode validated --fail-on high .")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
	}
}
