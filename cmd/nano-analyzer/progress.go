package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type progressMessageMode int

const (
	progressMessageLine progressMessageMode = iota
	progressMessageStatus
	progressMessageDone
)

var progressFrames = []string{
	"| \\(^_^ )",
	"/ ( ^_^)/",
	"- /( ^_^)",
	"\\ ( ^_^)\\",
}

const (
	progressFrameWidth     = 10
	defaultTerminalColumns = 80
)

type terminalProgress struct {
	out         io.Writer
	term        *os.File
	interactive bool

	mu        sync.Mutex
	status    string
	frame     int
	lineWidth int
	done      chan struct{}
	stopped   chan struct{}
}

func newTerminalProgress(stderr *os.File) *terminalProgress {
	progress := &terminalProgress{
		out:         stderr,
		term:        stderr,
		interactive: isInteractiveTerminal(stderr),
		done:        make(chan struct{}),
		stopped:     make(chan struct{}),
	}
	if progress.interactive {
		go progress.loop()
	} else {
		close(progress.stopped)
	}
	return progress
}

func (p *terminalProgress) Logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if !p.interactive {
		fmt.Fprintln(p.out, line)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	switch progressMode(line) {
	case progressMessageStatus:
		p.status = line
		p.renderLocked()
	case progressMessageDone:
		p.status = ""
		p.clearLocked()
		fmt.Fprintln(p.out, line)
	case progressMessageLine:
		p.clearLocked()
		fmt.Fprintln(p.out, line)
		if p.status != "" {
			p.renderLocked()
		}
	}
}

func (p *terminalProgress) Close() {
	if !p.interactive {
		return
	}
	close(p.done)
	<-p.stopped
}

func (p *terminalProgress) loop() {
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	defer close(p.stopped)

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			p.renderLocked()
			p.mu.Unlock()
		case <-p.done:
			p.mu.Lock()
			p.status = ""
			p.clearLocked()
			p.mu.Unlock()
			return
		}
	}
}

func (p *terminalProgress) renderLocked() {
	if p.status == "" {
		return
	}
	frame := progressFrames[p.frame%len(progressFrames)]
	p.frame++
	line := formatProgressLine(frame, p.status, terminalColumns(p.term))
	width := max(p.lineWidth, displayWidth(line))
	fmt.Fprintf(p.out, "\r%-*s", width, line)
	p.lineWidth = width
}

func (p *terminalProgress) clearLocked() {
	if p.lineWidth == 0 {
		return
	}
	fmt.Fprintf(p.out, "\r%-*s\r", p.lineWidth, "")
	p.lineWidth = 0
}

func progressMode(line string) progressMessageMode {
	switch {
	case strings.HasPrefix(line, "scan: complete"),
		strings.HasPrefix(line, "triage: complete"),
		strings.HasPrefix(line, "triage: no findings"):
		return progressMessageDone
	case strings.HasPrefix(line, "scan "),
		strings.HasPrefix(line, "triage "),
		strings.HasPrefix(line, "scan: starting"),
		strings.HasPrefix(line, "triage: evaluating"),
		strings.HasPrefix(line, "llm: rate limit"):
		return progressMessageStatus
	default:
		return progressMessageLine
	}
}

func formatProgressLine(frame, status string, columns int) string {
	prefix := fmt.Sprintf("%-*s ", progressFrameWidth, frame)
	if columns <= 0 {
		return prefix + status
	}

	width := columns - 1
	if width <= 0 {
		return ""
	}
	prefixWidth := displayWidth(prefix)
	if prefixWidth >= width {
		return truncateMiddle(prefix, width)
	}
	return prefix + truncateMiddle(status, width-prefixWidth)
}

func truncateMiddle(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if displayWidth(value) <= width {
		return value
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}

	remaining := width - 3
	leftWidth := (remaining * 2) / 3
	if leftWidth == 0 {
		leftWidth = 1
	}
	rightWidth := remaining - leftWidth
	if rightWidth == 0 {
		rightWidth = 1
		leftWidth = remaining - rightWidth
	}

	return firstRunes(value, leftWidth) + "..." + lastRunes(value, rightWidth)
}

func firstRunes(value string, count int) string {
	if count <= 0 {
		return ""
	}
	var b strings.Builder
	written := 0
	for _, r := range value {
		if written >= count {
			break
		}
		b.WriteRune(r)
		written++
	}
	return b.String()
}

func lastRunes(value string, count int) string {
	if count <= 0 {
		return ""
	}
	runes := []rune(value)
	if count >= len(runes) {
		return value
	}
	return string(runes[len(runes)-count:])
}

func displayWidth(value string) int {
	return utf8.RuneCountInString(value)
}

func terminalColumns(file *os.File) int {
	if file == nil {
		return defaultTerminalColumns
	}
	if columns, err := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS"))); err == nil && columns > 0 {
		return columns
	}
	return defaultTerminalColumns
}

func isInteractiveTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	term := strings.TrimSpace(strings.ToLower(os.Getenv("TERM")))
	if term == "" || term == "dumb" {
		return false
	}
	return true
}
