package output

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/weareaisle/nano-analyzer/internal/domain"
	"github.com/weareaisle/nano-analyzer/internal/ports"
)

type Writer struct {
	OutputDir         string
	Formats           map[string]bool
	GitHubStepSummary string
}

func NewWriter(outputDir string, formats map[string]bool, stepSummary string) *Writer {
	return &Writer{
		OutputDir:         outputDir,
		Formats:           formats,
		GitHubStepSummary: stepSummary,
	}
}

func (w *Writer) WriteRun(ctx context.Context, summary domain.Summary) error {
	_ = ctx
	outDir := w.OutputDir
	if outDir == "" {
		outDir = summary.OutputDir
	}
	if outDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if w.format("json") {
		if err := w.writeJSON(outDir, summary); err != nil {
			return err
		}
	}
	if w.format("markdown") {
		if err := w.writeMarkdown(outDir, summary); err != nil {
			return err
		}
	}
	if w.format("sarif") {
		if err := writeFileJSON(filepath.Join(outDir, "results.sarif"), BuildSARIF(summary)); err != nil {
			return err
		}
	}
	if w.GitHubStepSummary != "" {
		if err := appendGitHubSummary(w.GitHubStepSummary, summary); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) format(name string) bool {
	if len(w.Formats) == 0 {
		return true
	}
	return w.Formats[name]
}

func (w *Writer) writeJSON(outDir string, summary domain.Summary) error {
	if err := writeFileJSON(filepath.Join(outDir, "summary.json"), summary); err != nil {
		return err
	}
	for _, result := range summary.Results {
		if result.Status != "ok" {
			continue
		}
		safe := safeName(result.DisplayName)
		if err := writeFileJSON(filepath.Join(outDir, "results", safe+".json"), result); err != nil {
			return err
		}
	}
	if len(summary.Triage) > 0 {
		if err := writeFileJSON(filepath.Join(outDir, "triage.json"), summary.Triage); err != nil {
			return err
		}
	}
	return nil
}

func (w *Writer) writeMarkdown(outDir string, summary domain.Summary) error {
	if err := writeFile(filepath.Join(outDir, "summary.md"), []byte(markdownSummary(summary))); err != nil {
		return err
	}
	for _, result := range summary.Results {
		if result.Status != "ok" {
			continue
		}
		safe := safeName(result.DisplayName)
		if err := writeFile(filepath.Join(outDir, "reports", safe+".md"), []byte("# Scan: "+result.DisplayName+"\n\n"+result.Report)); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(outDir, "contexts", safe+".context.md"), []byte("# Context: "+result.DisplayName+"\n\n"+result.Context)); err != nil {
			return err
		}
	}
	if len(summary.Triage) > 0 {
		if err := writeFile(filepath.Join(outDir, "triage_survivors.md"), []byte(markdownTriageSurvivors(summary))); err != nil {
			return err
		}
		for idx, triage := range summary.Triage {
			path := filepath.Join(outDir, "triages", fmt.Sprintf("T%04d_%s_%s.md", idx+1, safeName(triage.File), safeName(triage.FindingTitle)))
			if err := writeFile(path, []byte(markdownTriageDetail(idx+1, triage))); err != nil {
				return err
			}
			summary.Triage[idx].TriagePath = path
		}
		valid := validSurvivors(summary)
		for idx, triage := range valid {
			path := filepath.Join(outDir, "findings", fmt.Sprintf("VULN-%03d_%s.md", idx+1, safeName(triage.File)))
			if err := writeFile(path, []byte(markdownFinding(idx+1, summary, triage))); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeFileJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFile(path, data)
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func markdownSummary(summary domain.Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nano-analyzer scan results\n\n")
	fmt.Fprintf(&b, "- **Target**: `%s`\n", strings.Join(summary.Target, ", "))
	fmt.Fprintf(&b, "- **Date**: `%s`\n", summary.Timestamp)
	fmt.Fprintf(&b, "- **Model**: `%s`\n", summary.Model)
	fmt.Fprintf(&b, "- **Files scanned**: `%d`\n", summary.FilesScanned)
	fmt.Fprintf(&b, "- **Files skipped**: `%d`\n", summary.FilesSkipped)
	fmt.Fprintf(&b, "- **Wall time**: `%.1fs`\n", summary.WallTime)
	if summary.ShouldFail {
		fmt.Fprintf(&b, "- **CI result**: failed policy threshold\n")
	} else {
		fmt.Fprintf(&b, "- **CI result**: passed policy threshold\n")
	}
	fmt.Fprintf(&b, "\n| File | Lines | Critical | High | Medium | Low | Status |\n")
	fmt.Fprintf(&b, "|------|-------|----------|------|--------|-----|--------|\n")
	for _, result := range summary.Results {
		s := result.Severities
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %s |\n",
			result.DisplayName,
			result.Lines,
			s[domain.SeverityCritical],
			s[domain.SeverityHigh],
			s[domain.SeverityMedium],
			s[domain.SeverityLow],
			result.Status,
		)
	}
	if len(summary.FailureFindings) > 0 {
		fmt.Fprintf(&b, "\n## Policy failures\n\n")
		for _, triage := range summary.FailureFindings {
			fmt.Fprintf(&b, "- `%s`: **%s** %.0f%% - %s\n", triage.File, triage.Finding.Severity, triage.Confidence*100, triage.FindingTitle)
		}
	}
	return b.String()
}

func markdownTriageSurvivors(summary domain.Summary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# nano-analyzer triage survivors\n\n")
	fmt.Fprintf(&b, "- **Target**: `%s`\n", strings.Join(summary.Target, ", "))
	fmt.Fprintf(&b, "- **Date**: `%s`\n", summary.Timestamp)
	fmt.Fprintf(&b, "- **Model**: `%s`\n\n", summary.Model)
	for _, triage := range validSurvivors(summary) {
		fmt.Fprintf(&b, "## %s: %s\n\n", triage.File, triage.FindingTitle)
		fmt.Fprintf(&b, "- **Severity**: `%s`\n", triage.Finding.Severity)
		fmt.Fprintf(&b, "- **Confidence**: `%.0f%% [%s]`\n\n", triage.Confidence*100, triage.Verdicts)
		fmt.Fprintf(&b, "%s\n\n---\n\n", triage.Reasoning)
	}
	return b.String()
}

func markdownTriageDetail(idx int, triage domain.TriageResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Triage T%04d: %s\n\n", idx, triage.FindingTitle)
	fmt.Fprintf(&b, "- **File**: `%s`\n", triage.File)
	fmt.Fprintf(&b, "- **Verdict**: `%s`\n", triage.Verdict)
	fmt.Fprintf(&b, "- **Confidence**: `%.0f%% [%s]`\n\n", triage.Confidence*100, triage.Verdicts)
	fmt.Fprintf(&b, "## Finding\n\n%s\n\n", triage.Finding.Description)
	fmt.Fprintf(&b, "## Triage rounds\n\n")
	for _, round := range triage.AllRounds {
		fmt.Fprintf(&b, "### Round %d: %s\n\n", round.Round, round.Verdict)
		fmt.Fprintf(&b, "%s\n\n", round.Reasoning)
		if round.GrepResults != "" {
			fmt.Fprintf(&b, "#### Grep results\n\n%s\n\n", round.GrepResults)
		}
	}
	return b.String()
}

func markdownFinding(idx int, summary domain.Summary, triage domain.TriageResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# VULN-%03d: %s\n\n", idx, triage.FindingTitle)
	fmt.Fprintf(&b, "- **File**: `%s`\n", triage.File)
	fmt.Fprintf(&b, "- **Severity**: `%s`\n", triage.Finding.Severity)
	fmt.Fprintf(&b, "- **Confidence**: `%.0f%% [%s]`\n", triage.Confidence*100, triage.Verdicts)
	fmt.Fprintf(&b, "- **Date**: `%s`\n\n", summary.Timestamp)
	fmt.Fprintf(&b, "## Scanner finding\n\n%s\n\n", triage.Finding.Description)
	fmt.Fprintf(&b, "## Triage reasoning\n\n%s\n", triage.Reasoning)
	return b.String()
}

func validSurvivors(summary domain.Summary) []domain.TriageResult {
	var survivors []domain.TriageResult
	for _, triage := range summary.Triage {
		if triage.Verdict == domain.VerdictValid {
			if summary.MinConfidence > 0 && triage.Confidence < summary.MinConfidence {
				continue
			}
			survivors = append(survivors, triage)
		}
	}
	sort.SliceStable(survivors, func(i, j int) bool {
		if survivors[i].Confidence != survivors[j].Confidence {
			return survivors[i].Confidence > survivors[j].Confidence
		}
		return survivors[i].File < survivors[j].File
	})
	return survivors
}

func appendGitHubSummary(path string, summary domain.Summary) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## nano-analyzer\n\n")
	fmt.Fprintf(&b, "- Files scanned: `%d`\n", summary.FilesScanned)
	fmt.Fprintf(&b, "- Files skipped: `%d`\n", summary.FilesSkipped)
	fmt.Fprintf(&b, "- Output: `%s`\n", summary.OutputDir)
	if summary.ShouldFail {
		fmt.Fprintf(&b, "- Result: failing policy threshold\n")
	} else {
		fmt.Fprintf(&b, "- Result: passing policy threshold\n")
	}
	if len(summary.FailureFindings) > 0 {
		fmt.Fprintf(&b, "\n### Validated failures\n\n")
		for _, triage := range summary.FailureFindings {
			fmt.Fprintf(&b, "- `%s`: **%s** %.0f%% - %s\n", triage.File, triage.Finding.Severity, triage.Confidence*100, triage.FindingTitle)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String() + "\n")
	return err
}

func safeName(value string) string {
	value = strings.ReplaceAll(value, string(filepath.Separator), "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.ReplaceAll(value, "\\", "_")
	value = regexp.MustCompile(`[^\w.\-]+`).ReplaceAllString(value, "_")
	value = strings.Trim(value, "_")
	if value == "" {
		return "unnamed"
	}
	if len(value) > 120 {
		value = value[:120]
	}
	return value
}

var _ ports.OutputWriter = (*Writer)(nil)
