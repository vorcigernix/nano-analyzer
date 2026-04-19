package app

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

var (
	fenceRE       = regexp.MustCompile("(?s)```(?:json)?\\s*\\n?(.*?)```")
	numberedObjRE = regexp.MustCompile(`,?\s*\d+\s*:\s*\{`)
	badSlashRE    = regexp.MustCompile(`\\([^"\\/bfnrtu])`)
	markerRE      = regexp.MustCompile(`(?im)^>>>\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*(.+)`)
	headingRE     = regexp.MustCompile(`(?im)^#{1,4}\s+(.+)`)
	sevWordRE     = regexp.MustCompile(`(?i)\b(critical|high|medium|low|informational)\b`)
	bugKeywordRE  = regexp.MustCompile(`(?i)(overflow|underflow|use.after.free|double.free|null.pointer|null.deref|out.of.bounds|oob|buffer|race|deadlock|injection|bypass|escalat|uncheck|missing.check|missing.bound|missing.valid|unbounded|unchecked|integer.overflow|uaf|memcpy|sprintf|strcpy|strcat|format.string|denial.of.service|dos\b|crash|panic|corrupt|leak|disclosure|uninitiali|dangling|stale|sequence|replay|shift|xdr|length|size)`)
	junkTitleRE   = regexp.MustCompile(`(?i)(^summary|^overview|^what (this|to|i) |^threat model|^overall|^conclusion|^next step|^recommend|^note|^checklist|^audit |^action|^practical |^.?level\b|^/info|^.?impact\b|^.?risk\b|^.?confidence\b|exploitation path|candidates|^concurrency consider|^other |^ssues|^oncrete )`)
	funcSigRE     = regexp.MustCompile(`(?i)^[` + "`" + `\s]*\w+[\w_]*\s*[\(/]`)
)

func ExtractJSON(text string) any {
	candidate := strings.TrimSpace(text)
	if match := fenceRE.FindStringSubmatch(candidate); len(match) == 2 {
		candidate = strings.TrimSpace(match[1])
	}
	if parsed, ok := decodeJSON(candidate); ok {
		return parsed
	}

	if strings.Contains(candidate, `"severity"`) {
		repaired := numberedObjRE.ReplaceAllString(candidate, ", {")
		repaired = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(repaired), "[,"))
		if !strings.HasPrefix(repaired, "[") && strings.Contains(repaired, "{") {
			repaired = "[" + repaired
		}
		repaired = badSlashRE.ReplaceAllString(repaired, `\\$1`)
		if parsed, ok := decodeJSON(repaired); ok {
			return parsed
		}
		if objects := extractFindingObjects(candidate); len(objects) > 0 {
			return objects
		}
	}

	for _, pair := range [][2]byte{{'[', ']'}, {'{', '}'}} {
		if chunk, ok := balancedJSONChunk(candidate, pair[0], pair[1]); ok {
			if parsed, ok := decodeJSON(chunk); ok {
				return parsed
			}
		}
	}
	return nil
}

func ParseFindings(text string) []domain.Finding {
	if matches := markerRE.FindAllStringSubmatch(text, -1); len(matches) > 0 {
		findings := make([]domain.Finding, 0, len(matches))
		for _, match := range matches {
			title := strings.TrimSpace(strings.SplitN(match[2], "|", 2)[0])
			findings = append(findings, domain.Finding{
				Severity: domain.NormalizeSeverity(match[1]),
				Title:    title,
				Body:     strings.TrimSpace(match[2]),
			})
		}
		return findings
	}

	switch parsed := ExtractJSON(text).(type) {
	case map[string]any:
		if _, ok := parsed["severity"]; ok {
			return findingsFromItems([]any{parsed})
		}
		if items, ok := parsed["findings"].([]any); ok {
			return findingsFromItems(items)
		}
	case []any:
		return findingsFromItems(parsed)
	}

	findings := parseHeadingFindings(text)
	if len(findings) > 0 {
		return findings
	}

	if match := sevWordRE.FindStringSubmatch(text); len(match) == 2 {
		return []domain.Finding{{
			Severity: domain.NormalizeSeverity(match[1]),
			Title:    "Unstructured finding",
			Body:     strings.TrimSpace(text),
		}}
	}
	return nil
}

func CountSeverities(text string) map[domain.Severity]int {
	counts := domain.NewSeverityCounts()
	for _, finding := range ParseFindings(text) {
		if _, ok := counts[finding.Severity]; ok {
			counts[finding.Severity]++
		}
	}
	return counts
}

func findingsFromItems(items []any) []domain.Finding {
	findings := make([]domain.Finding, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		sev := domain.NormalizeSeverity(stringField(obj, "severity", "medium"))
		if sev == domain.SeverityClean {
			continue
		}
		description := stringField(obj, "description", "")
		if fix := stringField(obj, "fix", ""); fix != "" {
			description += "\n\nFix: " + fix
		}
		title := stringField(obj, "title", "Untitled finding")
		findings = append(findings, domain.Finding{
			Severity:    sev,
			Title:       title,
			Function:    stringField(obj, "function", ""),
			Description: description,
			Body:        description,
		})
	}
	return findings
}

func parseHeadingFindings(text string) []domain.Finding {
	matches := headingRE.FindAllStringSubmatchIndex(text, -1)
	findings := make([]domain.Finding, 0)
	for idx, match := range matches {
		title := strings.TrimSpace(text[match[2]:match[3]])
		title = strings.Trim(title, "* ")
		title = regexp.MustCompile(`(?i)^severity\s*[:/]\s*`).ReplaceAllString(title, "")
		title = regexp.MustCompile(`(?i)^[\(\[]?\s*(critical|high|medium|low|informational)\s*[\)\]]?\s*[:/]?\s*`).ReplaceAllString(title, "")
		title = strings.TrimSpace(title)
		start := match[0]
		end := len(text)
		if idx+1 < len(matches) {
			end = matches[idx+1][0]
		}
		section := strings.TrimSpace(text[start:end])
		if title == "" || junkTitleRE.MatchString(title) || funcSigRE.MatchString(title) {
			continue
		}
		if !bugKeywordRE.MatchString(title) && !bugKeywordRE.MatchString(prefix(section, 300)) {
			continue
		}
		sev := domain.SeverityMedium
		if sevMatch := sevWordRE.FindStringSubmatch(section); len(sevMatch) == 2 {
			sev = domain.NormalizeSeverity(sevMatch[1])
		}
		findings = append(findings, domain.Finding{Severity: sev, Title: title, Body: section})
	}
	return findings
}

func decodeJSON(text string) (any, bool) {
	var parsed any
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

func extractFindingObjects(text string) []any {
	var objects []any
	for _, loc := range regexp.MustCompile(`\{\s*"severity"`).FindAllStringIndex(text, -1) {
		depth := 0
		for idx := loc[0]; idx < len(text); idx++ {
			switch text[idx] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					chunk := badSlashRE.ReplaceAllString(text[loc[0]:idx+1], `\\$1`)
					if parsed, ok := decodeJSON(chunk); ok {
						objects = append(objects, parsed)
					}
					idx = len(text)
				}
			}
		}
	}
	return objects
}

func balancedJSONChunk(text string, startChar, endChar byte) (string, bool) {
	start := strings.IndexByte(text, startChar)
	if start < 0 {
		return "", false
	}
	depth := 0
	inString := false
	escaped := false
	var buf bytes.Buffer
	for idx := start; idx < len(text); idx++ {
		ch := text[idx]
		buf.WriteByte(ch)
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			escaped = true
			continue
		}
		if ch == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if ch == startChar {
			depth++
		}
		if ch == endChar {
			depth--
			if depth == 0 {
				return buf.String(), true
			}
		}
	}
	return "", false
}

func stringField(obj map[string]any, key string, fallback string) string {
	value, ok := obj[key]
	if !ok || value == nil {
		return fallback
	}
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return fallback
		}
		return typed
	default:
		return fallback
	}
}

func prefix(text string, max int) string {
	if len(text) <= max {
		return text
	}
	return text[:max]
}
