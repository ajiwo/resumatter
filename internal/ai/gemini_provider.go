package ai

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"time"

	"resumatter/internal/config"
	resumatterErrors "resumatter/internal/errors"
	"resumatter/internal/types"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/api/googleapi"
	"google.golang.org/genai"
)

// GeminiProvider implements AIProvider for Google Gemini
type GeminiProvider struct {
	client         *genai.Client
	httpClient     *http.Client
	config         *config.OperationAIConfig
	circuitBreaker *AICircuitBreaker
	modelBreaker   *ModelCircuitBreaker
	logger         *resumatterErrors.Logger
}

// Ensure GeminiProvider implements AIProvider
var _ AIProvider = (*GeminiProvider)(nil)

// NewGeminiProvider creates a new Gemini provider instance for a specific operation
func NewGeminiProvider(cfg *config.OperationAIConfig, operationType string, logger *resumatterErrors.Logger) (*GeminiProvider, error) {
	ctx := context.Background()
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: cfg.APIKey,
	})
	if err != nil {
		return nil, resumatterErrors.NewAIError(resumatterErrors.ErrCodeAIServiceFailed,
			"Failed to create Gemini client", err)
	}

	// Initialize circuit breaker with operation-specific configuration
	circuitBreaker := NewAICircuitBreaker(operationType, cfg, logger)
	modelBreaker := NewModelCircuitBreaker(operationType, cfg, logger)

	return &GeminiProvider{
		client: client,
		httpClient: &http.Client{
			Timeout: *cfg.Timeout,
		},
		config:         cfg,
		circuitBreaker: circuitBreaker,
		modelBreaker:   modelBreaker,
		logger:         logger,
	}, nil
}

// ModelInfo represents information about the AI model
type ModelInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Version     string `json:"version,omitempty"`
	Available   bool   `json:"available"`
	Error       string `json:"error,omitempty"`
}

// GetModelInfo checks the readiness and availability of the configured model
func (g *GeminiProvider) GetModelInfo(ctx context.Context) *ModelInfo {
	modelInfo := &ModelInfo{
		Name:      g.config.Model,
		Available: false,
	}

	// Create a timeout context for the model check
	timeout := getAIModelCheckTimeout()
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get model information from Gemini API with circuit breaker
	model, err := g.modelBreaker.ExecuteModel(func() (*genai.Model, error) {
		return g.client.Models.Get(checkCtx, g.config.Model, &genai.GetModelConfig{})
	})
	if err != nil {
		modelInfo.Error = fmt.Sprintf("Failed to get model info: %v", err)

		// Log the error for debugging
		g.logger.Warn("Model availability check failed",
			"model", g.config.Model,
			"provider", g.config.Provider,
			"error", err.Error())
		return modelInfo
	}

	// Model is available, populate info
	modelInfo.Available = true
	if model.DisplayName != "" {
		modelInfo.DisplayName = model.DisplayName
	}
	if model.Version != "" {
		modelInfo.Version = model.Version
	}

	// Log successful check
	g.logger.Debug("Model availability check successful",
		"model", g.config.Model,
		"provider", g.config.Provider,
		"display_name", modelInfo.DisplayName,
		"version", modelInfo.Version)

	return modelInfo
}

// executeWithRetry executes an AI operation with retry logic and exponential backoff
func (g *GeminiProvider) executeWithRetry(ctx context.Context, operation string, fn func() (*genai.GenerateContentResponse, error)) (*genai.GenerateContentResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= *g.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Log retry attempt
			g.logger.Warn("Retrying AI operation",
				"operation", operation,
				"attempt", attempt,
				"max_retries", *g.config.MaxRetries,
				"error", lastErr.Error())

			// Exponential backoff with jitter to prevent thundering herd
			baseDelay := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			// Use crypto/rand for secure random jitter
			jitterMax := big.NewInt(int64(float64(baseDelay) * 0.1))
			jitterBig, _ := rand.Int(rand.Reader, jitterMax)
			jitter := time.Duration(jitterBig.Int64())
			// Cap maximum backoff at 30 seconds
			backoff := min(baseDelay+jitter, 30*time.Second)

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		result, err := fn()
		if err == nil {
			if attempt > 0 {
				g.logger.Info("AI operation succeeded after retry",
					"operation", operation,
					"successful_attempt", attempt+1,
					"total_attempts", attempt+1)
			}
			return result, nil
		}

		lastErr = err

		// Don't retry on certain errors (auth, invalid input, etc.)
		if !g.isRetryableError(err) {
			g.logger.Debug("Error is not retryable, stopping retry attempts",
				"operation", operation,
				"error", err.Error())
			break
		}
	}

	// Log final failure
	g.logger.LogError(lastErr, "AI operation failed after all retry attempts",
		"operation", operation,
		"total_attempts", *g.config.MaxRetries+1)

	return nil, fmt.Errorf("operation '%s' failed after %d retries: %w", operation, *g.config.MaxRetries, lastErr)
}

// isRetryableError determines if an error should trigger a retry
func (g *GeminiProvider) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors (timeouts, connection issues)
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true // Retry on timeouts
		}
		// Consider other network errors retryable (e.g., connection refused)
		return true
	}

	// Check for Google API errors (HTTP status codes)
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case http.StatusTooManyRequests,
			http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		}
	}

	return false
}

// executeAIOperation is a generic helper to run AI operations with common tracing, circuit breaker, and parsing logic.
func executeAIOperation[Out any](
	g *GeminiProvider,
	ctx context.Context,
	operationName string,
	userPrompt string,
	systemPrompt string,
	genaiConfig *genai.GenerateContentConfig,
	spanAttributes ...attribute.KeyValue,
) (Out, *TokenUsage, error) {
	var output Out
	tracer := otel.Tracer("resumatter.ai.gemini")
	ctx, span := tracer.Start(ctx, "gemini."+operationName)
	defer span.End()

	// Set base attributes
	span.SetAttributes(
		attribute.String("ai.provider", "gemini"),
		attribute.String("ai.model", g.config.Model),
		attribute.Float64("ai.temperature", float64(*g.config.Temperature)),
	)
	span.SetAttributes(spanAttributes...)

	if *g.config.UseSystemPrompts && systemPrompt != "" {
		genaiConfig.SystemInstruction = genai.NewContentFromText(systemPrompt, genai.RoleUser)
	}

	result, err := g.circuitBreaker.Execute(func() (*genai.GenerateContentResponse, error) {
		return g.executeWithRetry(ctx, operationName, func() (*genai.GenerateContentResponse, error) {
			return g.client.Models.GenerateContent(ctx, g.config.Model, genai.Text(userPrompt), genaiConfig)
		})
	})

	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("success", false))
		return output, nil, resumatterErrors.NewAIError(resumatterErrors.ErrCodeAIServiceFailed, "Failed to generate content for "+operationName, err)
	}

	if err := json.Unmarshal([]byte(result.Text()), &output); err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("success", false))
		return output, nil, resumatterErrors.NewAIError("AI_RESPONSE_PARSE_FAILED", "Failed to parse AI response for "+operationName, err)
	}

	tokenUsage := extractTokenUsage(result)
	if tokenUsage != nil {
		span.SetAttributes(
			attribute.Int64("ai.tokens.input", tokenUsage.InputTokens),
			attribute.Int64("ai.tokens.output", tokenUsage.OutputTokens),
			attribute.Int64("ai.tokens.total", tokenUsage.TotalTokens),
		)
	}

	span.SetAttributes(attribute.Bool("success", true))
	return output, tokenUsage, nil
}

// TailorResume implements AIProvider interface for resume tailoring
func (g *GeminiProvider) TailorResume(ctx context.Context, input types.TailorResumeInput) (types.TailorResumeOutput, *TokenUsage, error) {
	systemPrompt, userPrompt := g.getPromptsForTailor(input.BaseResume, input.JobDescription)
	config := g.buildTailorSchema()

	output, tokenUsage, err := executeAIOperation[types.TailorResumeOutput](
		g,
		ctx,
		"tailor_resume",
		userPrompt,
		systemPrompt,
		config,
		attribute.Int("input.resume_length", len(input.BaseResume)),
		attribute.Int("input.job_length", len(input.JobDescription)),
	)

	if err != nil {
		return types.TailorResumeOutput{}, nil, err
	}

	// Add operation-specific success metrics to the span created by the helper
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			attribute.Int("output.tailored_length", len(output.TailoredResume)),
			attribute.Int("ats.score", output.ATSAnalysis.Score),
		)
	}

	return output, tokenUsage, nil
}

// EvaluateResume implements AIProvider interface for resume evaluation
func (g *GeminiProvider) EvaluateResume(ctx context.Context, input types.EvaluateResumeInput) (types.EvaluateResumeOutput, *TokenUsage, error) {
	systemPrompt, userPrompt := g.getPromptsForEvaluate(input.BaseResume, input.TailoredResume)
	config := g.buildEvaluateSchema()

	output, tokenUsage, err := executeAIOperation[types.EvaluateResumeOutput](
		g,
		ctx,
		"evaluate_resume",
		userPrompt,
		systemPrompt,
		config,
		attribute.Int("input.base_resume_length", len(input.BaseResume)),
		attribute.Int("input.tailored_resume_length", len(input.TailoredResume)),
	)

	if err != nil {
		return types.EvaluateResumeOutput{}, nil, err
	}

	// Add operation-specific success metrics to the span created by the helper
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			attribute.Int("findings_count", len(output.Findings)),
		)
	}

	return output, tokenUsage, nil
}

// AnalyzeJob implements AIProvider interface for job description analysis
func (g *GeminiProvider) AnalyzeJob(ctx context.Context, input types.AnalyzeJobInput) (types.AnalyzeJobOutput, *TokenUsage, error) {
	systemPrompt, userPrompt := g.getPromptsForAnalyze(input.JobDescription)
	config := g.buildAnalyzeSchema()

	output, tokenUsage, err := executeAIOperation[types.AnalyzeJobOutput](
		g,
		ctx,
		"analyze_job",
		userPrompt,
		systemPrompt,
		config,
		attribute.Int("input.job_length", len(input.JobDescription)),
	)

	if err != nil {
		return types.AnalyzeJobOutput{}, nil, err
	}

	// Add operation-specific success metrics to the span created by the helper
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			attribute.Int("quality_score", output.JobQualityScore),
			attribute.Int("clarity_score", output.Clarity.Score),
			attribute.Int("inclusivity_score", output.Inclusivity.Score),
		)
	}

	return output, tokenUsage, nil
}

// GetCircuitBreakerStats returns circuit breaker statistics
func (g *GeminiProvider) GetCircuitBreakerStats() map[string]any {
	stats := map[string]any{
		"ai_operations":    g.circuitBreaker.GetStats(),
		"model_operations": g.modelBreaker.GetModelStats(),
	}

	// Overall health - both breakers must be healthy
	aiHealthy := g.circuitBreaker.IsHealthy()
	modelHealthy := g.modelBreaker.IsModelHealthy()
	stats["overall_healthy"] = aiHealthy && modelHealthy

	return stats
}

// Close implements AIProvider interface
func (g *GeminiProvider) Close() error {
	// Gemini client doesn't have a Close method in current single-shot usage
	// Probably needed in streaming mode
	return nil
}

// buildTailorSchema creates the schema for tailor requests
func (g *GeminiProvider) buildTailorSchema() *genai.GenerateContentConfig {
	config := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseSchema: &genai.Schema{
			Type: genai.TypeObject,
			Properties: map[string]*genai.Schema{
				"tailoredResume": {Type: genai.TypeString},
				"atsAnalysis": {
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"score":      {Type: genai.TypeInteger},
						"strengths":  {Type: genai.TypeString},
						"weaknesses": {Type: genai.TypeString},
					},
					Required: []string{"score", "strengths", "weaknesses"},
				},
				"jobPostingAnalysis": {
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"clarity":     {Type: genai.TypeString},
						"inclusivity": {Type: genai.TypeString},
						"quality":     {Type: genai.TypeString},
					},
					Required: []string{"clarity", "inclusivity", "quality"},
				},
			},
			Required: []string{"tailoredResume", "atsAnalysis", "jobPostingAnalysis"},
		},
	}

	// Apply temperature configuration if set
	if *g.config.Temperature > 0 {
		config.Temperature = g.config.Temperature
	}

	return config
}

// getPromptsForTailor returns system and user prompts for tailoring
func (g *GeminiProvider) getPromptsForTailor(baseResume, jobDescription string) (string, string) {
	// Get prompts from config or use defaults
	systemPrompt := g.getSystemPrompt("tailor")
	userPrompt := g.getUserPrompt("tailor")

	// Format user prompt with dynamic content
	formattedUserPrompt := fmt.Sprintf(userPrompt, baseResume, jobDescription)

	return systemPrompt, formattedUserPrompt
}

// getPromptsForEvaluate returns system and user prompts for evaluation
func (g *GeminiProvider) getPromptsForEvaluate(baseResume, tailoredResume string) (string, string) {
	// Get prompts from config or use defaults
	systemPrompt := g.getSystemPrompt("evaluate")
	userPrompt := g.getUserPrompt("evaluate")

	// Format user prompt with dynamic content
	formattedUserPrompt := fmt.Sprintf(userPrompt, baseResume, tailoredResume)

	return systemPrompt, formattedUserPrompt
}

// getSystemPrompt returns the appropriate system prompt
func (g *GeminiProvider) getSystemPrompt(promptType string) string {
	loadedPrompts, configPrompts := g.getPrompts(promptType)
	var configSystemPrompts *config.SystemPrompts
	if configPrompts != nil {
		configSystemPrompts = &configPrompts.SystemPrompts
	} else {
		// Create an empty struct to avoid nil pointer panics
		configSystemPrompts = &config.SystemPrompts{}
	}

	switch promptType {
	case "tailor":
		return resolvePrompt(
			loadedPrompts.SystemPrompts.TailorResume,
			configSystemPrompts.TailorResume,
			DefaultSystemPrompts.TailorResume,
		)
	case "evaluate":
		return resolvePrompt(
			loadedPrompts.SystemPrompts.EvaluateResume,
			configSystemPrompts.EvaluateResume,
			DefaultSystemPrompts.EvaluateResume,
		)
	case "analyze":
		return resolvePrompt(
			loadedPrompts.SystemPrompts.AnalyzeJob,
			configSystemPrompts.AnalyzeJob,
			DefaultSystemPrompts.AnalyzeJob,
		)
	default:
		// Fallback for any unknown prompt type, perhaps returning an empty string or a default
		return ""
	}
}

// getUserPrompt returns the appropriate user prompt template
func (g *GeminiProvider) getUserPrompt(promptType string) string {
	loadedPrompts, configPrompts := g.getPrompts(promptType)
	var configUserPrompts *config.UserPrompts
	if configPrompts != nil {
		configUserPrompts = &configPrompts.UserPrompts
	} else {
		// Create an empty struct to avoid nil pointer panics
		configUserPrompts = &config.UserPrompts{}
	}

	switch promptType {
	case "tailor":
		return resolvePrompt(
			loadedPrompts.UserPrompts.TailorResume,
			configUserPrompts.TailorResume,
			DefaultUserPrompts.TailorResume,
		)
	case "evaluate":
		return resolvePrompt(
			loadedPrompts.UserPrompts.EvaluateResume,
			configUserPrompts.EvaluateResume,
			DefaultUserPrompts.EvaluateResume,
		)
	case "analyze":
		return resolvePrompt(
			loadedPrompts.UserPrompts.AnalyzeJob,
			configUserPrompts.AnalyzeJob,
			DefaultUserPrompts.AnalyzeJob,
		)
	default:
		return ""
	}
}

// getPromptsForAnalyze returns system and user prompts for job analysis
func (g *GeminiProvider) getPromptsForAnalyze(jobDescription string) (string, string) {
	// Get prompts from config or use defaults
	systemPrompt := g.getSystemPrompt("analyze")
	userPrompt := g.getUserPrompt("analyze")

	// Format user prompt with dynamic content
	formattedUserPrompt := fmt.Sprintf(userPrompt, jobDescription)

	return systemPrompt, formattedUserPrompt
}

// buildEvaluateSchema creates the schema for evaluate requests
func (g *GeminiProvider) buildEvaluateSchema() *genai.GenerateContentConfig {
	config := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseSchema: &genai.Schema{
			Type: genai.TypeObject,
			Properties: map[string]*genai.Schema{
				"summary": {Type: genai.TypeString},
				"findings": {
					Type: genai.TypeArray,
					Items: &genai.Schema{
						Type: genai.TypeObject,
						Properties: map[string]*genai.Schema{
							"type":        {Type: genai.TypeString},
							"description": {Type: genai.TypeString},
							"evidence":    {Type: genai.TypeString},
						},
						Required: []string{"type", "description", "evidence"},
					},
				},
			},
			Required: []string{"summary", "findings"},
		},
	}

	// Apply temperature configuration if set
	if *g.config.Temperature > 0 {
		config.Temperature = g.config.Temperature
	}

	return config
}

// buildAnalyzeSchema creates the schema for job analysis requests
func (g *GeminiProvider) buildAnalyzeSchema() *genai.GenerateContentConfig {
	config := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
		ResponseSchema: &genai.Schema{
			Type: genai.TypeObject,
			Properties: map[string]*genai.Schema{
				"jobQualityScore": {Type: genai.TypeInteger},
				"clarity": {
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"score":    {Type: genai.TypeInteger},
						"analysis": {Type: genai.TypeString},
						"improvements": {
							Type:  genai.TypeArray,
							Items: &genai.Schema{Type: genai.TypeString},
						},
					},
					Required: []string{"score", "analysis", "improvements"},
				},
				"inclusivity": {
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"score":    {Type: genai.TypeInteger},
						"analysis": {Type: genai.TypeString},
						"flaggedTerms": {
							Type:  genai.TypeArray,
							Items: &genai.Schema{Type: genai.TypeString},
						},
						"suggestions": {
							Type:  genai.TypeArray,
							Items: &genai.Schema{Type: genai.TypeString},
						},
					},
					Required: []string{"score", "analysis", "flaggedTerms", "suggestions"},
				},
				"candidateAttraction": {
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"score": {Type: genai.TypeInteger},
						"strengths": {
							Type:  genai.TypeArray,
							Items: &genai.Schema{Type: genai.TypeString},
						},
						"weaknesses": {
							Type:  genai.TypeArray,
							Items: &genai.Schema{Type: genai.TypeString},
						},
					},
					Required: []string{"score", "strengths", "weaknesses"},
				},
				"marketCompetitiveness": {
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"salaryTransparency":  {Type: genai.TypeString},
						"requirementsRealism": {Type: genai.TypeString},
						"industryAlignment":   {Type: genai.TypeString},
					},
					Required: []string{"salaryTransparency", "requirementsRealism", "industryAlignment"},
				},
				"recommendations": {
					Type:  genai.TypeArray,
					Items: &genai.Schema{Type: genai.TypeString},
				},
			},
			Required: []string{"jobQualityScore", "clarity", "inclusivity", "candidateAttraction", "marketCompetitiveness", "recommendations"},
		},
	}

	// Apply temperature configuration if set
	if *g.config.Temperature > 0 {
		config.Temperature = g.config.Temperature
	}

	return config
}

// TokenUsage represents token usage information from AI responses
type TokenUsage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

// AIOperationResult holds the result of an AI operation including token usage
type AIOperationResult struct {
	Error      error
	TokenUsage *TokenUsage
}

// extractTokenUsage extracts token usage information from Gemini API response
func extractTokenUsage(result *genai.GenerateContentResponse) *TokenUsage {
	if result == nil || result.UsageMetadata == nil {
		return nil
	}

	usage := result.UsageMetadata
	return &TokenUsage{
		InputTokens:  int64(usage.PromptTokenCount),
		OutputTokens: int64(usage.CandidatesTokenCount),
		TotalTokens:  int64(usage.TotalTokenCount),
	}
}

// getAIModelCheckTimeout returns the configured AI model check timeout
func getAIModelCheckTimeout() time.Duration {
	// Use default timeout since we don't have access to config here
	// This function should be refactored to accept timeout as parameter
	// Fallback to default
	return 10 * time.Second
}

// getPrompts returns the appropriate prompts for the operation, prioritizing loaded content over config
func (g *GeminiProvider) getPrompts(operationType string) (config.OperationLoadedPrompts, *config.PromptConfig) {
	// Get loaded prompts (returns a copy)
	loadedPrompts := config.GetPromptsForOperation(operationType)
	configPrompts := &g.config.CustomPrompts
	return loadedPrompts, configPrompts
}

// resolvePrompt selects the correct prompt string based on a clear priority order:
// 1. A prompt loaded from a file.
// 2. A prompt defined directly in the configuration.
// 3. A hardcoded default prompt.
// This helper function centralizes the decision logic, making it DRY and easy to maintain.
func resolvePrompt(loadedFromFile, fromConfig, fromDefault string) string {
	if loadedFromFile != "" {
		return loadedFromFile
	}
	if fromConfig != "" {
		return fromConfig
	}
	return fromDefault
}
