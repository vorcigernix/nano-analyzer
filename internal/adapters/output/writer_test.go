package output

import (
	"strings"
	"testing"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

func TestMarkdownPRCommentIncludesValidatedFindings(t *testing.T) {
	summary := domain.Summary{
		Model:        "gpt-4o-mini",
		FilesScanned: 1,
		Results: []domain.ScanResult{{
			DisplayName: "src/vuln.c",
			Severities: map[domain.Severity]int{
				domain.SeverityHigh: 1,
			},
			Status: "ok",
		}},
		Triage: []domain.TriageResult{{
			FindingTitle: "Stack buffer overflow",
			File:         "src/vuln.c",
			Verdict:      domain.VerdictValid,
			Confidence:   1,
			Verdicts:     "1/1",
			Reasoning:    "strcpy writes attacker data into a fixed buffer",
			Finding: domain.Finding{
				Severity:    domain.SeverityHigh,
				Title:       "Stack buffer overflow",
				Description: "strcpy into b[8]",
			},
		}},
		ShouldFail: true,
	}

	comment := markdownPRComment(summary)
	for _, want := range []string{
		"## nano-analyzer security audit",
		"### Validated Findings",
		"Stack buffer overflow",
		"strcpy into b[8]",
		"<details><summary>Triage reasoning</summary>",
	} {
		if !strings.Contains(comment, want) {
			t.Fatalf("PR comment missing %q:\n%s", want, comment)
		}
	}
}

func TestMarkdownPRCommentFallsBackToRawFindings(t *testing.T) {
	summary := domain.Summary{
		Model:        "gpt-4o-mini",
		FilesScanned: 1,
		Results: []domain.ScanResult{{
			DisplayName: "src/raw|finding.c",
			Findings: []domain.Finding{{
				Severity:    domain.SeverityMedium,
				Title:       "Unchecked length",
				Function:    "parse()",
				Description: "length reaches copy",
			}},
			Severities: map[domain.Severity]int{
				domain.SeverityMedium: 1,
			},
			Status: "ok",
		}},
	}

	comment := markdownPRComment(summary)
	for _, want := range []string{
		"### Raw Findings",
		"src/raw\\|finding.c",
		"Unchecked length",
		"length reaches copy",
	} {
		if !strings.Contains(comment, want) {
			t.Fatalf("PR comment missing %q:\n%s", want, comment)
		}
	}
}
