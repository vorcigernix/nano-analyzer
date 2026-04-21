package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
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

type terminalProgress struct {
	out         io.Writer
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
	line := fmt.Sprintf("%-10s %s", frame, p.status)
	width := max(p.lineWidth, len(line))
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
		strings.HasPrefix(line, "triage: evaluating"):
		return progressMessageStatus
	default:
		return progressMessageLine
	}
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
