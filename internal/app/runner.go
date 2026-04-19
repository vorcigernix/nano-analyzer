package app

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/weareaisle/nano-analyzer/internal/domain"
	"github.com/weareaisle/nano-analyzer/internal/ports"
)

type Runner struct {
	LLM             ports.LLMClient
	Searcher        ports.Searcher
	ChangedDetector ports.ChangedFileDetector
	Writer          ports.OutputWriter
	Logf            func(format string, args ...any)
}

func (r Runner) Run(ctx context.Context, cfg Config) (domain.Summary, error) {
	if err := cfg.Normalize(); err != nil {
		return domain.Summary{}, err
	}
	timestamp := time.Now().Format("2006-01-02_150405")
	if cfg.OutputDir == "" {
		root, err := DefaultOutputRoot()
		if err != nil {
			return domain.Summary{}, err
		}
		cfg.OutputDir = filepath.Join(root, timestamp)
	}
	if r.LLM == nil {
		return domain.Summary{}, fmt.Errorf("llm client is required")
	}

	start := time.Now()
	files, skipped, err := DiscoverSourceFiles(ctx, cfg, r.ChangedDetector)
	if err != nil {
		return domain.Summary{}, err
	}
	totalLines := 0
	for _, file := range files {
		totalLines += file.Lines
	}
	r.logf("target: %s", strings.Join(cfg.Paths, ", "))
	r.logf("repo: %s", cfg.RepoDir)
	r.logf("files: %d scannable, %d skipped", len(files), len(skipped))
	if len(files) == 0 {
		summary := domain.Summary{
			Timestamp:       timestamp,
			Target:          cfg.Paths,
			Model:           cfg.Model,
			FilesSkipped:    len(skipped),
			TotalLines:      totalLines,
			OutputDir:       cfg.OutputDir,
			WallTime:        time.Since(start).Seconds(),
			Results:         nil,
			Triage:          nil,
			ShouldFail:      false,
			FilesScanned:    0,
			FailureFindings: nil,
			MinConfidence:   cfg.MinConfidence,
		}
		if r.Writer != nil {
			if err := r.Writer.WriteRun(ctx, summary); err != nil {
				return summary, err
			}
		}
		return summary, nil
	}

	results := r.scanFiles(ctx, cfg, timestamp, files)
	triage := r.triageResults(ctx, cfg, results)
	summary := buildSummary(cfg, timestamp, start, len(skipped), totalLines, results, triage)
	EvaluateFailPolicy(cfg, &summary)
	if r.Writer != nil {
		if err := r.Writer.WriteRun(ctx, summary); err != nil {
			return summary, err
		}
	}
	return summary, nil
}

func (r Runner) scanFiles(ctx context.Context, cfg Config, timestamp string, files []domain.SourceFile) []domain.ScanResult {
	workers := min(cfg.Parallel, len(files))
	jobs := make(chan domain.SourceFile)
	results := make(chan domain.ScanResult, len(files))
	var wg sync.WaitGroup
	for idx := 0; idx < workers; idx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range jobs {
				results <- r.scanFile(ctx, cfg, timestamp, file)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, file := range files {
			select {
			case <-ctx.Done():
				return
			case jobs <- file:
			}
		}
	}()
	wg.Wait()
	close(results)

	scanResults := make([]domain.ScanResult, 0, len(files))
	for result := range results {
		scanResults = append(scanResults, result)
		if result.Status == "ok" {
			r.logf("scanned %s: %s", result.DisplayName, domain.TopSeverity(result.Severities))
		} else {
			r.logf("scan error %s: %s", result.DisplayName, result.Error)
		}
	}
	sort.Slice(scanResults, func(i, j int) bool {
		a, b := scanResults[i], scanResults[j]
		for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
			if a.Severities[sev] != b.Severities[sev] {
				return a.Severities[sev] > b.Severities[sev]
			}
		}
		return a.DisplayName < b.DisplayName
	})
	return scanResults
}

func (r Runner) scanFile(ctx context.Context, cfg Config, timestamp string, file domain.SourceFile) domain.ScanResult {
	result := domain.ScanResult{
		File:        file.Path,
		DisplayName: file.DisplayName,
		Model:       cfg.Model,
		Code:        file.Content,
		Severities:  domain.NewSeverityCounts(),
		Status:      "ok",
		Lines:       file.Lines,
		Chars:       file.Chars,
		Timestamp:   timestamp,
	}
	ctxMessages := []domain.Message{
		{Role: "system", Content: ContextGenPrompt},
		{Role: "user", Content: fmt.Sprintf("File: %s\n\n```\n%s\n```", file.DisplayName, file.Content)},
	}
	contextResp, err := r.LLM.Chat(ctx, ports.ChatRequest{Model: cfg.Model, Messages: ctxMessages})
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result
	}
	contextText := contextResp.Content
	if grepResults := ExecuteGrepRequests(ctx, contextText, r.Searcher); grepResults != "" {
		contextText += "\n\n[GREP RESULTS from codebase]:\n" + grepResults
	}
	result.Context = contextText
	result.ContextTokens = contextResp.TotalTokens
	result.ContextElapsed = round1(contextResp.ElapsedSeconds)

	scanMessages := []domain.Message{
		{Role: "system", Content: DefaultSystemPrompt + "\n\nSecurity context for the file being analyzed:\n" + contextText},
		{Role: "user", Content: FewshotExampleUser},
		{Role: "assistant", Content: FewshotExampleAssistant},
		{Role: "user", Content: fmt.Sprintf(UserPromptTemplate, file.DisplayName, file.Content)},
	}
	scanResp, err := r.LLM.Chat(ctx, ports.ChatRequest{Model: cfg.Model, Messages: scanMessages})
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
		return result
	}
	result.Report = scanResp.Content
	result.PromptTokens = scanResp.PromptTokens
	result.CompletionTokens = scanResp.CompletionTokens
	result.TotalTokens = scanResp.TotalTokens
	result.ScanElapsed = round1(scanResp.ElapsedSeconds)
	result.TotalElapsed = round1(contextResp.ElapsedSeconds + scanResp.ElapsedSeconds)
	result.Findings = ParseFindings(scanResp.Content)
	for idx := range result.Findings {
		result.Findings[idx].File = file.DisplayName
	}
	result.Severities = CountSeverities(scanResp.Content)
	return result
}

func (r Runner) triageResults(ctx context.Context, cfg Config, results []domain.ScanResult) []domain.TriageResult {
	if cfg.TriageMode == "disabled" {
		return nil
	}
	type job struct {
		Result  domain.ScanResult
		Finding domain.Finding
	}
	var jobsList []job
	for _, result := range results {
		if result.Status != "ok" {
			continue
		}
		for _, finding := range result.Findings {
			if domain.SeverityAtOrAbove(finding.Severity, cfg.TriageThreshold) {
				jobsList = append(jobsList, job{Result: result, Finding: finding})
			}
		}
	}
	if len(jobsList) == 0 {
		return nil
	}
	workers := min(cfg.TriageParallel, len(jobsList))
	jobsCh := make(chan job)
	resultsCh := make(chan domain.TriageResult, len(jobsList))
	var wg sync.WaitGroup
	for idx := 0; idx < workers; idx++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobsCh {
				resultsCh <- r.triageFinding(ctx, cfg, item.Result, item.Finding)
			}
		}()
	}
	go func() {
		defer close(jobsCh)
		for _, item := range jobsList {
			select {
			case <-ctx.Done():
				return
			case jobsCh <- item:
			}
		}
	}()
	wg.Wait()
	close(resultsCh)

	triages := make([]domain.TriageResult, 0, len(jobsList))
	for triage := range resultsCh {
		triages = append(triages, triage)
		r.logf("triage %s %s: %s %.0f%%", triage.File, triage.FindingTitle, triage.Verdict, triage.Confidence*100)
	}
	sort.Slice(triages, func(i, j int) bool {
		if triages[i].Verdict != triages[j].Verdict {
			return triages[i].Verdict == domain.VerdictValid
		}
		if triages[i].Confidence != triages[j].Confidence {
			return triages[i].Confidence > triages[j].Confidence
		}
		return triages[i].File < triages[j].File
	})
	return triages
}

func (r Runner) triageFinding(ctx context.Context, cfg Config, scan domain.ScanResult, finding domain.Finding) domain.TriageResult {
	findingText := fmt.Sprintf("[%s] %s\n\n%s", strings.ToUpper(string(finding.Severity)), finding.Title, findingBody(finding))
	prior := make([]domain.TriageRound, 0, cfg.TriageRounds)
	rounds := make([]domain.TriageRound, 0, cfg.TriageRounds+1)
	for roundNum := 1; roundNum <= cfg.TriageRounds; roundNum++ {
		prompt := fmt.Sprintf(TriagePromptTemplate, cfg.Project, findingText, scan.DisplayName, sourceCodeFromScan(scan))
		if scan.Context != "" {
			prompt += "\n\n**Security context for this file:**\n" + prefix(scan.Context, 2000)
		}
		if len(prior) > 0 {
			prompt += "\n\n---\n\nPrior reviewers have weighed in below. Their reasoning is speculative and may contain errors.\n\n"
			for idx, previous := range prior {
				reasoning := previous.Reasoning
				if previous.GrepResults != "" {
					reasoning += "\n\n[GREP RESULTS]:\n" + previous.GrepResults
				}
				if idx < len(prior)-1 {
					reasoning = condensePriorGreps(reasoning)
				}
				prompt += fmt.Sprintf("**Reviewer %d**:\n%s\n\n", idx+1, reasoning)
			}
		}
		messages := []domain.Message{
			{Role: "system", Content: "You are a security engineer triaging vulnerability reports. Decide whether the bug is real, attacker-reachable, and security-relevant. Use GREP to verify concrete defenses. Do not guess."},
			{Role: "user", Content: prompt},
		}
		response, err := r.LLM.Chat(ctx, ports.ChatRequest{Model: cfg.Model, Messages: messages, JSONMode: true})
		round := parseTriageRound(finding.Title, scan.DisplayName, roundNum, response, err)
		if round.Reasoning != "" {
			if grepResults := ExecuteGrepRequests(ctx, round.Reasoning, r.Searcher); grepResults != "" {
				round.GrepUsed = true
				round.GrepResults = grepResults
			}
		}
		rounds = append(rounds, round)
		prior = append(prior, round)
	}

	confidence := validConfidence(rounds)
	verdicts := verdictString(rounds)
	if cfg.TriageRounds > 1 {
		if arbiter := r.arbitrate(ctx, cfg, scan, finding, findingText, rounds); arbiter.Verdict == domain.VerdictValid || arbiter.Verdict == domain.VerdictInvalid {
			rounds = append(rounds, arbiter)
			verdicts += "->" + string(string(arbiter.Verdict)[0])
			confidence = validConfidence(rounds)
		}
	}
	final := rounds[len(rounds)-1]
	return domain.TriageResult{
		FindingTitle: finding.Title,
		File:         scan.DisplayName,
		Verdict:      final.Verdict,
		Reasoning:    final.Reasoning,
		Confidence:   round2(confidence),
		Verdicts:     verdicts,
		Finding:      finding,
		AllRounds:    rounds,
	}
}

func (r Runner) arbitrate(ctx context.Context, cfg Config, scan domain.ScanResult, finding domain.Finding, findingText string, rounds []domain.TriageRound) domain.TriageRound {
	evidence := make([]string, 0, len(rounds))
	valid, invalid := 0, 0
	for _, round := range rounds {
		if round.Verdict == domain.VerdictValid {
			valid++
		}
		if round.Verdict == domain.VerdictInvalid {
			invalid++
		}
		summary := prefix(round.Reasoning, 500)
		evidence = append(evidence, fmt.Sprintf("Round %d (%s): %s", round.Round, round.Verdict, summary))
		if round.GrepResults != "" {
			evidence = append(evidence, round.GrepResults)
		}
	}
	prompt := fmt.Sprintf("A vulnerability was reported in %s:\n%s\n\nReported finding:\n%s\n\nKey evidence:\n%s\n\nVerdicts so far: %s (%d valid, %d invalid)\n\nSource code from %s:\n```c\n%s\n```\n\nBased on the code and evidence, is this a real security vulnerability? Respond with JSON: {\"verdict\":\"VALID/INVALID\",\"reasoning\":\"concise explanation\"}",
		cfg.Project, finding.Title, findingText, strings.Join(evidence, "\n"), verdictString(rounds), valid, invalid, scan.DisplayName, sourceCodeFromScan(scan))
	response, err := r.LLM.Chat(ctx, ports.ChatRequest{
		Model:    cfg.Model,
		JSONMode: true,
		Messages: []domain.Message{
			{Role: "system", Content: "You are an impartial judge. Decide based on evidence, not arguments."},
			{Role: "user", Content: prompt},
		},
	})
	return parseTriageRound(finding.Title, scan.DisplayName, len(rounds)+1, response, err)
}

func parseTriageRound(title, file string, roundNum int, response ports.ChatResponse, err error) domain.TriageRound {
	round := domain.TriageRound{
		FindingTitle: title,
		File:         file,
		Round:        roundNum,
		Verdict:      domain.VerdictUncertain,
		Reasoning:    response.Content,
		Elapsed:      round1(response.ElapsedSeconds),
		Tokens:       response.TotalTokens,
	}
	if err != nil {
		round.Verdict = domain.VerdictError
		round.Reasoning = err.Error()
		return round
	}
	if parsed, ok := ExtractJSON(response.Content).(map[string]any); ok {
		if verdict := strings.ToUpper(stringField(parsed, "verdict", "")); verdict == string(domain.VerdictValid) || verdict == string(domain.VerdictInvalid) || verdict == string(domain.VerdictUncertain) {
			round.Verdict = domain.Verdict(verdict)
		}
		if reasoning := stringField(parsed, "reasoning", ""); reasoning != "" {
			round.Reasoning = reasoning
		}
		if crux := stringField(parsed, "crux", ""); crux != "" {
			round.Reasoning += "\n\nCRUX: " + crux
		}
		if grep := stringField(parsed, "grep", ""); grep != "" {
			grep = strings.Trim(strings.TrimPrefix(grep, "GREP:"), "`\"' ")
			if grep != "" {
				round.Reasoning += "\nGREP: " + grep
			}
		}
		return round
	}
	clean := strings.ToUpper(strings.TrimSpace(response.Content))
	if strings.HasPrefix(clean, "INVALID") {
		round.Verdict = domain.VerdictInvalid
	} else if strings.HasPrefix(clean, "VALID") {
		round.Verdict = domain.VerdictValid
	} else if strings.HasPrefix(clean, "UNCERTAIN") {
		round.Verdict = domain.VerdictUncertain
	}
	return round
}

func buildSummary(cfg Config, timestamp string, start time.Time, skipped int, totalLines int, results []domain.ScanResult, triage []domain.TriageResult) domain.Summary {
	summary := domain.Summary{
		Timestamp:     timestamp,
		Target:        cfg.Paths,
		Model:         cfg.Model,
		FilesScanned:  len(results),
		FilesSkipped:  skipped,
		TotalLines:    totalLines,
		WallTime:      round1(time.Since(start).Seconds()),
		OutputDir:     cfg.OutputDir,
		Results:       results,
		Triage:        triage,
		MinConfidence: cfg.MinConfidence,
	}
	for _, result := range results {
		if result.Status == "error" {
			summary.ErrorFiles++
			continue
		}
		if result.Severities[domain.SeverityCritical] > 0 {
			summary.CriticalFiles++
		}
		if result.Severities[domain.SeverityHigh] > 0 {
			summary.HighFiles++
		}
		if domain.TopSeverity(result.Severities) == domain.SeverityClean {
			summary.CleanFiles++
		}
	}
	return summary
}

func validConfidence(rounds []domain.TriageRound) float64 {
	if len(rounds) == 0 {
		return 0
	}
	valid := 0
	for _, round := range rounds {
		if round.Verdict == domain.VerdictValid {
			valid++
		}
	}
	return float64(valid) / float64(len(rounds))
}

func verdictString(rounds []domain.TriageRound) string {
	var builder strings.Builder
	for _, round := range rounds {
		if round.Verdict == "" {
			builder.WriteByte('?')
			continue
		}
		builder.WriteByte(string(round.Verdict)[0])
	}
	return builder.String()
}

func condensePriorGreps(reasoning string) string {
	const marker = "\n\n[GREP RESULTS"
	idx := strings.Index(reasoning, marker)
	if idx < 0 {
		return reasoning
	}
	before := reasoning[:idx]
	grepSection := reasoning[idx:]
	lines := strings.Split(grepSection, "\n")
	condensed := make([]string, 0, 8)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "```") || strings.HasPrefix(line, "GREP `") {
			continue
		}
		if strings.Contains(line, "(no matches") {
			condensed = append(condensed, "- "+line)
			continue
		}
		if strings.Contains(line, ":") {
			condensed = append(condensed, "- "+line)
		}
		if len(condensed) >= 6 {
			break
		}
	}
	if len(condensed) == 0 {
		return before
	}
	return before + "\n\n[Prior grep evidence]:\n" + strings.Join(condensed, "\n")
}

func findingBody(finding domain.Finding) string {
	if finding.Body != "" {
		return finding.Body
	}
	if finding.Description != "" {
		return finding.Description
	}
	payload, _ := json.Marshal(finding)
	return string(payload)
}

func sourceCodeFromScan(scan domain.ScanResult) string {
	return scan.Code
}

func round1(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}

func round2(value float64) float64 {
	return float64(int(value*100+0.5)) / 100
}

func (r Runner) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}
