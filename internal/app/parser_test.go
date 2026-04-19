package app

import (
	"testing"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

func TestParseFindingsFromJSONArray(t *testing.T) {
	text := "reasoning first\n```json\n[{\"severity\":\"high\",\"title\":\"Overflow\",\"function\":\"parse()\",\"description\":\"bad copy\"}]\n```"
	findings := ParseFindings(text)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != domain.SeverityHigh || findings[0].Title != "Overflow" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestParseFindingsRepairsNumberedObjects(t *testing.T) {
	text := `[
  1: {"severity":"critical","title":"Bad memcpy","description":"overflow"},
  2: {"severity":"low","title":"Minor leak","description":"info"}
]`
	findings := ParseFindings(text)
	if len(findings) != 2 {
		t.Fatalf("expected 2 repaired findings, got %d", len(findings))
	}
	if findings[0].Severity != domain.SeverityCritical {
		t.Fatalf("unexpected severity: %s", findings[0].Severity)
	}
}

func TestParseFindingsFromMarker(t *testing.T) {
	findings := ParseFindings(">>> HIGH: Stack overflow | memcpy without bound")
	if len(findings) != 1 {
		t.Fatalf("expected marker finding, got %d", len(findings))
	}
	if findings[0].Title != "Stack overflow" {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}
