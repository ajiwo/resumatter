package ai

import (
	"context"

	"resumatter/internal/types"
)

// AIProvider interface for different AI implementations
// All methods now return token usage information - callers can ignore it if not needed
type AIProvider interface {
	TailorResume(ctx context.Context, input types.TailorResumeInput) (types.TailorResumeOutput, *TokenUsage, error)
	EvaluateResume(ctx context.Context, input types.EvaluateResumeInput) (types.EvaluateResumeOutput, *TokenUsage, error)
	AnalyzeJob(ctx context.Context, input types.AnalyzeJobInput) (types.AnalyzeJobOutput, *TokenUsage, error)
	GetModelInfo(ctx context.Context) *ModelInfo
	Close() error
}

// SchemaBuilder interface for building AI request schemas
type SchemaBuilder interface {
	BuildTailorSchema() any
	BuildEvaluateSchema() any
}

// PromptBuilder interface for building AI prompts
type PromptBuilder interface {
	BuildTailorPrompt(baseResume, jobDescription string) string
	BuildEvaluatePrompt(baseResume, tailoredResume string) string
}
