package ports

import (
	"context"

	"github.com/weareaisle/nano-analyzer/internal/domain"
)

type ChatRequest struct {
	Model           string
	Messages        []domain.Message
	JSONMode        bool
	ReasoningEffort string
}

type ChatResponse struct {
	Content          string
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	ElapsedSeconds   float64
}

type LLMClient interface {
	Chat(ctx context.Context, request ChatRequest) (ChatResponse, error)
}

type SearchMatch struct {
	Path string
	Line int
	Text string
}

type Searcher interface {
	Search(ctx context.Context, pattern string) ([]SearchMatch, error)
}

type ChangedFileDetector interface {
	ChangedFiles(ctx context.Context, repoDir string) ([]string, error)
}

type OutputWriter interface {
	WriteRun(ctx context.Context, summary domain.Summary) error
}
