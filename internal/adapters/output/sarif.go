package output

import "github.com/weareaisle/nano-analyzer/internal/domain"

type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type SARIFResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    SARIFMessage    `json:"message"`
	Locations  []SARIFLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

func BuildSARIF(summary domain.Summary) SARIFLog {
	rules := []SARIFRule{
		rule(domain.SeverityCritical),
		rule(domain.SeverityHigh),
		rule(domain.SeverityMedium),
		rule(domain.SeverityLow),
		rule(domain.SeverityInformational),
	}
	results := make([]SARIFResult, 0)
	for _, scan := range summary.Results {
		for _, finding := range scan.Findings {
			results = append(results, sarifResult(scan.DisplayName, finding, "raw", 0))
		}
	}
	for _, triage := range summary.Triage {
		if triage.Verdict != domain.VerdictValid {
			continue
		}
		results = append(results, sarifResult(triage.File, triage.Finding, "validated", triage.Confidence))
	}
	return SARIFLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           "nano-analyzer",
				InformationURI: "https://github.com/weareaisle/nano-analyzer",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

func rule(sev domain.Severity) SARIFRule {
	return SARIFRule{
		ID:   string(sev),
		Name: string(sev),
		ShortDescription: SARIFMessage{
			Text: "nano-analyzer " + string(sev) + " finding",
		},
	}
}

func sarifResult(path string, finding domain.Finding, source string, confidence float64) SARIFResult {
	message := finding.Title
	if finding.Description != "" {
		message += ": " + finding.Description
	} else if finding.Body != "" {
		message += ": " + finding.Body
	}
	properties := map[string]any{"source": source}
	if confidence > 0 {
		properties["confidence"] = confidence
	}
	return SARIFResult{
		RuleID:  string(finding.Severity),
		Level:   sarifLevel(finding.Severity),
		Message: SARIFMessage{Text: message},
		Locations: []SARIFLocation{{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: path},
				Region:           SARIFRegion{StartLine: 1},
			},
		}},
		Properties: properties,
	}
}

func sarifLevel(sev domain.Severity) string {
	switch sev {
	case domain.SeverityCritical, domain.SeverityHigh:
		return "error"
	case domain.SeverityMedium:
		return "warning"
	case domain.SeverityLow, domain.SeverityInformational:
		return "note"
	default:
		return "none"
	}
}
