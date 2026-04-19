package domain

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type SourceFile struct {
	Path        string `json:"path"`
	DisplayName string `json:"display_name"`
	Content     string `json:"-"`
	Lines       int    `json:"lines"`
	Chars       int    `json:"chars"`
}

type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Function    string   `json:"function,omitempty"`
	Description string   `json:"description,omitempty"`
	Body        string   `json:"body,omitempty"`
	File        string   `json:"file,omitempty"`
}

type ScanResult struct {
	File             string           `json:"file"`
	DisplayName      string           `json:"display_name"`
	Model            string           `json:"model"`
	Context          string           `json:"context,omitempty"`
	Report           string           `json:"report,omitempty"`
	Code             string           `json:"-"`
	Findings         []Finding        `json:"findings,omitempty"`
	Severities       map[Severity]int `json:"severities"`
	Status           string           `json:"status"`
	Error            string           `json:"error,omitempty"`
	ContextTokens    int              `json:"context_tokens,omitempty"`
	PromptTokens     int              `json:"prompt_tokens,omitempty"`
	CompletionTokens int              `json:"completion_tokens,omitempty"`
	TotalTokens      int              `json:"total_tokens,omitempty"`
	ContextElapsed   float64          `json:"context_elapsed,omitempty"`
	ScanElapsed      float64          `json:"scan_elapsed,omitempty"`
	TotalElapsed     float64          `json:"total_elapsed,omitempty"`
	Lines            int              `json:"lines"`
	Chars            int              `json:"chars"`
	Timestamp        string           `json:"timestamp"`
}

type Verdict string

const (
	VerdictValid     Verdict = "VALID"
	VerdictInvalid   Verdict = "INVALID"
	VerdictUncertain Verdict = "UNCERTAIN"
	VerdictError     Verdict = "ERROR"
)

type TriageRound struct {
	FindingTitle string  `json:"finding_title"`
	File         string  `json:"file"`
	Round        int     `json:"round"`
	Verdict      Verdict `json:"verdict"`
	Reasoning    string  `json:"reasoning"`
	GrepUsed     bool    `json:"grep_used,omitempty"`
	GrepResults  string  `json:"grep_results,omitempty"`
	Elapsed      float64 `json:"elapsed,omitempty"`
	Tokens       int     `json:"tokens,omitempty"`
}

type TriageResult struct {
	FindingTitle string        `json:"finding_title"`
	File         string        `json:"file"`
	Verdict      Verdict       `json:"verdict"`
	Reasoning    string        `json:"reasoning"`
	Confidence   float64       `json:"confidence"`
	Verdicts     string        `json:"verdicts_str"`
	TriagePath   string        `json:"triage_md,omitempty"`
	Finding      Finding       `json:"finding"`
	AllRounds    []TriageRound `json:"all_rounds"`
}

type Summary struct {
	Timestamp       string         `json:"timestamp"`
	Target          []string       `json:"target"`
	Model           string         `json:"model"`
	FilesScanned    int            `json:"files_scanned"`
	FilesSkipped    int            `json:"files_skipped"`
	TotalLines      int            `json:"total_lines"`
	WallTime        float64        `json:"wall_time_seconds"`
	CriticalFiles   int            `json:"critical_files"`
	HighFiles       int            `json:"high_files"`
	CleanFiles      int            `json:"clean_files"`
	ErrorFiles      int            `json:"error_files"`
	OutputDir       string         `json:"output_dir"`
	Results         []ScanResult   `json:"per_file"`
	Triage          []TriageResult `json:"triage,omitempty"`
	ShouldFail      bool           `json:"should_fail"`
	FailureFindings []TriageResult `json:"failure_findings,omitempty"`
	MinConfidence   float64        `json:"min_confidence,omitempty"`
}
