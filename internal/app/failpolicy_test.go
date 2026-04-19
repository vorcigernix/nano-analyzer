package app

import (
	"testing"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

func TestEvaluateFailPolicyValidated(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FailMode = "validated"
	cfg.FailOn = domain.SeverityHigh
	cfg.FailConfidence = 0.7
	summary := domain.Summary{
		Triage: []domain.TriageResult{{
			Verdict:    domain.VerdictValid,
			Confidence: 0.8,
			Finding: domain.Finding{
				Severity: domain.SeverityHigh,
				Title:    "validated high",
			},
		}},
	}
	EvaluateFailPolicy(cfg, &summary)
	if !summary.ShouldFail {
		t.Fatal("expected validated high finding to fail")
	}
}

func TestEvaluateFailPolicyValidatedIgnoresLowConfidence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FailMode = "validated"
	cfg.FailOn = domain.SeverityHigh
	cfg.FailConfidence = 0.9
	summary := domain.Summary{
		Triage: []domain.TriageResult{{
			Verdict:    domain.VerdictValid,
			Confidence: 0.8,
			Finding:    domain.Finding{Severity: domain.SeverityHigh},
		}},
	}
	EvaluateFailPolicy(cfg, &summary)
	if summary.ShouldFail {
		t.Fatal("low confidence finding should not fail")
	}
}

func TestEvaluateFailPolicyRaw(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FailMode = "raw"
	cfg.FailOn = domain.SeverityMedium
	summary := domain.Summary{
		Results: []domain.ScanResult{{
			DisplayName: "vuln.c",
			Findings: []domain.Finding{{
				Severity: domain.SeverityMedium,
				Title:    "raw medium",
			}},
		}},
	}
	EvaluateFailPolicy(cfg, &summary)
	if !summary.ShouldFail {
		t.Fatal("expected raw medium finding to fail")
	}
}
