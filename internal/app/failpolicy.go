package app

import "github.com/weareaisle/nano-analyzer/internal/domain"

func EvaluateFailPolicy(cfg Config, summary *domain.Summary) {
	summary.ShouldFail = false
	summary.FailureFindings = nil

	switch cfg.FailMode {
	case "never", "":
		return
	case "raw":
		for _, result := range summary.Results {
			for _, finding := range result.Findings {
				if domain.SeverityAtOrAbove(finding.Severity, cfg.FailOn) {
					summary.ShouldFail = true
					summary.FailureFindings = append(summary.FailureFindings, domain.TriageResult{
						FindingTitle: finding.Title,
						File:         result.DisplayName,
						Verdict:      domain.VerdictValid,
						Confidence:   1,
						Finding:      finding,
					})
				}
			}
		}
	case "validated":
		for _, triage := range summary.Triage {
			if triage.Verdict != domain.VerdictValid {
				continue
			}
			if triage.Confidence < cfg.FailConfidence {
				continue
			}
			if !domain.SeverityAtOrAbove(triage.Finding.Severity, cfg.FailOn) {
				continue
			}
			summary.ShouldFail = true
			summary.FailureFindings = append(summary.FailureFindings, triage)
		}
	}
}
