package main

import (
	"strings"
	"testing"
)

func TestProgressMode(t *testing.T) {
	tests := []struct {
		line string
		want progressMessageMode
	}{
		{line: "target: ./src", want: progressMessageLine},
		{line: "scan: starting 12 file(s) with 4 worker(s)", want: progressMessageStatus},
		{line: "scan 3/12 crypto/x.c high findings=2 totals issues=4 c=0 h=2 m=2 l=0 i=0 err=0", want: progressMessageStatus},
		{line: "scan: complete 12/12 totals issues=4 c=0 h=2 m=2 l=0 i=0 err=0", want: progressMessageDone},
		{line: "triage: evaluating 4 finding(s) at or above medium with 2 worker(s)", want: progressMessageStatus},
		{line: "triage 1/4 crypto/x.c overflow: VALID 100% totals valid=1 invalid=0 uncertain=0 error=0", want: progressMessageStatus},
		{line: "llm: rate limited (api 429); retrying at 21:07:00 (59s)", want: progressMessageStatus},
		{line: "triage: no findings at or above medium", want: progressMessageDone},
		{line: "triage: complete 4/4 totals valid=1 invalid=2 uncertain=1 error=0", want: progressMessageDone},
	}

	for _, test := range tests {
		if got := progressMode(test.line); got != test.want {
			t.Fatalf("progressMode(%q) = %v, want %v", test.line, got, test.want)
		}
	}
}

func TestFormatProgressLineTruncatesToTerminalWidth(t *testing.T) {
	line := formatProgressLine(
		progressFrames[0],
		"triage 21/2710 src/server/modules/ingestion/service/event-persistence.ts SQL casting failures on invalid UUIDs cause transaction abort (DoS): VALID 33% totals valid=9 invalid=12 uncertain=0 error=0",
		64,
	)

	if got := displayWidth(line); got > 63 {
		t.Fatalf("displayWidth(line) = %d, want <= 63 (%q)", got, line)
	}
	if !strings.HasPrefix(line, "| \\(^_^ ) ") {
		t.Fatalf("expected spinner prefix to be preserved, got %q", line)
	}
	if !strings.Contains(line, "...") {
		t.Fatalf("expected truncated line to contain ellipsis, got %q", line)
	}
	if !strings.Contains(line, "error=0") {
		t.Fatalf("expected line tail to be preserved, got %q", line)
	}
}
