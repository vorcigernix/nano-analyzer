package app

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/weareaisle/nano-analyzer/internal/ports"
)

const (
	maxGrepRequests = 3
	maxGrepLines    = 30
	maxGrepLineLen  = 2000
)

var (
	grepLineRE       = regexp.MustCompile(`(?i)GREP:\s*(.+)`)
	grepQuotedRE     = regexp.MustCompile(`(?i)grep\s+(?:for\s+)?[` + "`" + `"]([^` + "`" + `"]+)[` + "`" + `"]`)
	grepIdentifierRE = regexp.MustCompile(`(?i)grep\s+(?:for\s+)?(\w[\w_:.*]+\(?)`)
	grepJunk         = map[string]bool{
		"results": true, "call": true, "code": true, "function": true,
		"value": true, "NULL": true, "null": true, "type": true,
		"data": true, "return": true, "void": true, "true": true,
		"false": true, "the": true, "this": true, "that": true,
		"from": true, "verification": true, "verifications": true,
		"verified": true, "verify": true, "evidence": true, "confirm": true,
		"confirmed": true, "confirms": true, "output": true, "outputs": true,
		"search": true, "searches": true, "pattern": true, "patterns": true,
		"required": true, "provided": true, "shown": true, "needed": true,
		"following": true, "whether": true, "checked": true, "checking": true,
		"matched": true, "matches": true, "returned": true, "returns": true,
		"failed": true, "missing": true,
	}
)

func ExecuteGrepRequests(ctx context.Context, responseText string, searcher ports.Searcher) string {
	if searcher == nil {
		return ""
	}
	requests := grepRequests(responseText)
	if len(requests) == 0 {
		return ""
	}
	results := make([]string, 0, len(requests))
	for _, pattern := range requests {
		matches, err := searcher.Search(ctx, pattern)
		output := "(no matches in repo)"
		if err != nil {
			output = "(search failed: " + err.Error() + ")"
		} else if len(matches) > 0 {
			sort.SliceStable(matches, func(i, j int) bool {
				left, right := matches[i], matches[j]
				if strings.Contains(left.Text, "#define") != strings.Contains(right.Text, "#define") {
					return strings.Contains(left.Text, "#define")
				}
				if strings.HasSuffix(left.Path, ".h") != strings.HasSuffix(right.Path, ".h") {
					return strings.HasSuffix(left.Path, ".h")
				}
				if left.Path != right.Path {
					return left.Path < right.Path
				}
				return left.Line < right.Line
			})
			lines := make([]string, 0, min(len(matches), maxGrepLines))
			for _, match := range matches[:min(len(matches), maxGrepLines)] {
				text := strings.ReplaceAll(match.Text, "\x00", "")
				if len(text) > maxGrepLineLen {
					text = text[:maxGrepLineLen] + "..."
				}
				lines = append(lines, fmt.Sprintf("%s:%d:%s", match.Path, match.Line, text))
			}
			output = strings.Join(lines, "\n")
		}
		results = append(results, fmt.Sprintf("GREP `%s`:\n```\n%s\n```", pattern, output))
	}
	return strings.Join(results, "\n\n")
}

func grepRequests(responseText string) []string {
	seen := map[string]bool{}
	raw := make([]string, 0)
	add := func(value string) {
		value = strings.Trim(strings.TrimSpace(value), "`\"'")
		if value != "" && !seen[value] {
			seen[value] = true
			raw = append(raw, value)
		}
	}
	for _, match := range grepLineRE.FindAllStringSubmatch(responseText, -1) {
		add(match[1])
	}
	for _, match := range grepQuotedRE.FindAllStringSubmatch(responseText, -1) {
		add(match[1])
	}
	for _, match := range grepIdentifierRE.FindAllStringSubmatch(responseText, -1) {
		if len(match[1]) > 6 {
			add(match[1])
		}
	}

	expanded := make([]string, 0)
	seenExpanded := map[string]bool{}
	for _, request := range raw[:min(len(raw), maxGrepRequests)] {
		parts := []string{request}
		if strings.Contains(request, "|") {
			parts = strings.Split(request, "|")
		}
		for _, part := range parts {
			cleaned := cleanGrepPattern(part)
			if cleaned == "" || seenExpanded[cleaned] {
				continue
			}
			seenExpanded[cleaned] = true
			expanded = append(expanded, cleaned)
		}
	}
	if len(expanded) > maxGrepRequests*2 {
		expanded = expanded[:maxGrepRequests*2]
	}
	return expanded
}

func cleanGrepPattern(pattern string) string {
	pattern = strings.Trim(strings.TrimSpace(pattern), "`\"'")
	pattern = regexp.MustCompile(`\\[bBdDwWsS]`).ReplaceAllString(pattern, "")
	pattern = regexp.MustCompile(`\\(.)`).ReplaceAllString(pattern, "$1")
	if pattern == "" || len(pattern) < 3 || grepJunk[pattern] {
		return ""
	}
	if match := regexp.MustCompile(`^[\w/\\]+\.\w+[:\s]+(.+)`).FindStringSubmatch(pattern); len(match) == 2 {
		pattern = strings.TrimSpace(match[1])
	}
	if regexp.MustCompile(`^\d+[:\s]*$`).MatchString(pattern) {
		return ""
	}
	if strings.Contains(pattern, ", ") || len(pattern) > 60 {
		if simplified := simplifyPattern(pattern); simplified != "" {
			pattern = simplified
		}
	}
	if pattern == "" || len(pattern) < 3 || grepJunk[pattern] {
		return ""
	}
	return pattern
}

func simplifyPattern(pattern string) string {
	identifiers := regexp.MustCompile(`[a-zA-Z_]\w*(?:->[\w]+)*`).FindAllString(pattern, -1)
	sort.Slice(identifiers, func(i, j int) bool { return len(identifiers[i]) > len(identifiers[j]) })
	for _, identifier := range identifiers {
		if len(identifier) > 5 && !grepJunk[identifier] {
			return identifier
		}
	}
	return ""
}
