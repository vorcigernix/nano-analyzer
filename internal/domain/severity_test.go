package domain

import "testing"

func TestSeverityAtOrAbove(t *testing.T) {
	if !SeverityAtOrAbove(SeverityCritical, SeverityHigh) {
		t.Fatal("critical should be above high")
	}
	if !SeverityAtOrAbove(SeverityHigh, SeverityHigh) {
		t.Fatal("high should meet high threshold")
	}
	if SeverityAtOrAbove(SeverityMedium, SeverityHigh) {
		t.Fatal("medium should not meet high threshold")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	if got := NormalizeSeverity("HIGH"); got != SeverityHigh {
		t.Fatalf("NormalizeSeverity(HIGH) = %s", got)
	}
	if got := NormalizeSeverity("unknown"); got != SeverityMedium {
		t.Fatalf("unknown severity should default to medium, got %s", got)
	}
}
