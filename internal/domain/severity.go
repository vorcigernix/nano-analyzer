package domain

import "strings"

type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
	SeverityClean         Severity = "clean"
)

var SeverityOrder = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInformational,
}

func NormalizeSeverity(value string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(value))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	case SeverityInformational:
		return SeverityInformational
	case SeverityClean:
		return SeverityClean
	default:
		return SeverityMedium
	}
}

func SeverityRank(sev Severity) int {
	for idx, candidate := range SeverityOrder {
		if candidate == sev {
			return idx
		}
	}
	return len(SeverityOrder)
}

func SeverityAtOrAbove(sev, threshold Severity) bool {
	return SeverityRank(sev) <= SeverityRank(threshold)
}

func NewSeverityCounts() map[Severity]int {
	counts := make(map[Severity]int, len(SeverityOrder))
	for _, sev := range SeverityOrder {
		counts[sev] = 0
	}
	return counts
}

func TopSeverity(counts map[Severity]int) Severity {
	for _, sev := range SeverityOrder {
		if counts[sev] > 0 {
			return sev
		}
	}
	return SeverityClean
}
