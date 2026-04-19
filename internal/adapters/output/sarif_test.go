package output

import (
	"testing"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

func TestBuildSARIF(t *testing.T) {
	summary := domain.Summary{
		Results: []domain.ScanResult{{
			DisplayName: "src/vuln.c",
			Findings: []domain.Finding{{
				Severity:    domain.SeverityHigh,
				Title:       "Stack overflow",
				Description: "memcpy overflow",
			}},
		}},
	}
	log := BuildSARIF(summary)
	if log.Version != "2.1.0" {
		t.Fatalf("unexpected SARIF version %s", log.Version)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("unexpected SARIF results: %+v", log)
	}
	result := log.Runs[0].Results[0]
	if result.RuleID != "high" || result.Level != "error" {
		t.Fatalf("unexpected SARIF result: %+v", result)
	}
}
