package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"resumatter/internal/ai"
	"resumatter/internal/observability"
	"resumatter/internal/types"

	"go.opentelemetry.io/otel/attribute"
)

// createTailorHandler wraps the tailor handler with observability
func (s *Server) createTailorHandler(om *observability.ObservabilityManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tracer := om.Tracer("resumatter.api")
		ctx, span := tracer.Start(ctx, "api.tailor")
		defer span.End()

		// Parse request
		var req TailorRequest
		if err := parseJSONRequest(r, &req); err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "validation"))
			writeErrorResponse(w, "Invalid request body", err.Error(), http.StatusBadRequest)
			return
		}

		// Validation
		if strings.TrimSpace(req.BaseResume) == "" {
			err := fmt.Errorf("missing base resume")
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "validation"))
			writeErrorResponse(w, "Missing base resume", "baseResume field is required", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.JobDescription) == "" {
			err := fmt.Errorf("missing job description")
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "validation"))
			writeErrorResponse(w, "Missing job description", "jobDescription field is required", http.StatusBadRequest)
			return
		}

		// Size validation
		if len(req.BaseResume) > int(s.MaxRequestSize/2) {
			err := fmt.Errorf("base resume too large: %d chars", len(req.BaseResume))
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "validation"))
			writeErrorResponse(w, "Base resume too large", fmt.Sprintf("baseResume exceeds recommended size limit of %d characters", s.MaxRequestSize/2), http.StatusBadRequest)
			return
		}
		if len(req.JobDescription) > int(s.MaxRequestSize/2) {
			err := fmt.Errorf("job description too large: %d chars", len(req.JobDescription))
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "validation"))
			writeErrorResponse(w, "Job description too large", fmt.Sprintf("jobDescription exceeds recommended size limit of %d characters", s.MaxRequestSize/2), http.StatusBadRequest)
			return
		}

		// Add request attributes to span
		span.SetAttributes(
			attribute.Int("request.resume_length", len(req.BaseResume)),
			attribute.Int("request.job_length", len(req.JobDescription)),
			attribute.String("operation", "tailor"),
		)

		input := types.TailorResumeInput{
			BaseResume:     req.BaseResume,
			JobDescription: req.JobDescription,
		}

		// Create AI service for tailor operation
		tailorConfig := s.AppConfig.GetTailorConfig()
		aiService, err := ai.NewService(&tailorConfig, "tailor", s.Logger)
		if err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "service_creation"))
			writeErrorResponse(w, "Failed to create AI service", err.Error(), http.StatusInternalServerError)
			return
		}

		// Track AI operation with observability and token usage
		metrics := om.GetMetrics()
		var result types.TailorResumeOutput
		err = metrics.TrackAIOperationWithTokens(ctx, "tailor", func(ctx context.Context) *observability.AIOperationResult {
			output, tokenUsage, aiErr := aiService.Provider.TailorResume(ctx, input)
			result = output
			return &observability.AIOperationResult{
				Error:      aiErr,
				TokenUsage: (*observability.TokenUsage)(tokenUsage),
			}
		}, om)

		if err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "ai_processing"))
			metrics.RecordBusinessMetric(ctx, "resume_tailored", false, om,
				attribute.String("error", err.Error()))
			writeErrorResponse(w, "Failed to tailor resume", err.Error(), http.StatusInternalServerError)
			return
		}

		// Record success metrics
		metrics.RecordBusinessMetric(ctx, "resume_tailored", true, om,
			attribute.Int("output.tailored_length", len(result.TailoredResume)),
			attribute.Int("ats.score", result.ATSAnalysis.Score))

		span.SetAttributes(
			attribute.Bool("success", true),
			attribute.Int("response.tailored_length", len(result.TailoredResume)),
			attribute.Int("ats.score", result.ATSAnalysis.Score),
		)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			span.RecordError(err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// createEvaluateHandler wraps the evaluate handler with observability
func (s *Server) createEvaluateHandler(om *observability.ObservabilityManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tracer := om.Tracer("resumatter.api")
		ctx, span := tracer.Start(ctx, "api.evaluate")
		defer span.End()

		var req EvaluateRequest
		if err := parseJSONRequest(r, &req); err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "validation"))
			writeErrorResponse(w, "Invalid request body", err.Error(), http.StatusBadRequest)
			return
		}

		// Validation (similar to tailor)
		if strings.TrimSpace(req.BaseResume) == "" {
			err := fmt.Errorf("missing base resume")
			span.RecordError(err)
			writeErrorResponse(w, "Missing base resume", "baseResume field is required", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.TailoredResume) == "" {
			err := fmt.Errorf("missing tailored resume")
			span.RecordError(err)
			writeErrorResponse(w, "Missing tailored resume", "tailoredResume field is required", http.StatusBadRequest)
			return
		}

		span.SetAttributes(
			attribute.Int("request.base_resume_length", len(req.BaseResume)),
			attribute.Int("request.tailored_resume_length", len(req.TailoredResume)),
			attribute.String("operation", "evaluate"),
		)

		input := types.EvaluateResumeInput{
			BaseResume:     req.BaseResume,
			TailoredResume: req.TailoredResume,
		}

		// Create AI service for evaluate operation
		evaluateConfig := s.AppConfig.GetEvaluateConfig()
		aiService, err := ai.NewService(&evaluateConfig, "evaluate", s.Logger)
		if err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "service_creation"))
			writeErrorResponse(w, "Failed to create AI service", err.Error(), http.StatusInternalServerError)
			return
		}

		metrics := om.GetMetrics()
		var result types.EvaluateResumeOutput
		err = metrics.TrackAIOperationWithTokens(ctx, "evaluate", func(ctx context.Context) *observability.AIOperationResult {
			output, tokenUsage, aiErr := aiService.Provider.EvaluateResume(ctx, input)
			result = output
			return &observability.AIOperationResult{
				Error:      aiErr,
				TokenUsage: (*observability.TokenUsage)(tokenUsage),
			}
		}, om)

		if err != nil {
			span.RecordError(err)
			metrics.RecordBusinessMetric(ctx, "resume_evaluated", false, om)
			writeErrorResponse(w, "Failed to evaluate resume", err.Error(), http.StatusInternalServerError)
			return
		}

		metrics.RecordBusinessMetric(ctx, "resume_evaluated", true, om,
			attribute.Int("findings_count", len(result.Findings)))

		span.SetAttributes(
			attribute.Bool("success", true),
			attribute.Int("findings_count", len(result.Findings)),
		)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			span.RecordError(err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// createAnalyzeHandler wraps the analyze handler with observability
func (s *Server) createAnalyzeHandler(om *observability.ObservabilityManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tracer := om.Tracer("resumatter.api")
		ctx, span := tracer.Start(ctx, "api.analyze")
		defer span.End()

		var req AnalyzeRequest
		if err := parseJSONRequest(r, &req); err != nil {
			span.RecordError(err)
			writeErrorResponse(w, "Invalid request body", err.Error(), http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(req.JobDescription) == "" {
			err := fmt.Errorf("missing job description")
			span.RecordError(err)
			writeErrorResponse(w, "Missing job description", "jobDescription field is required", http.StatusBadRequest)
			return
		}

		span.SetAttributes(
			attribute.Int("request.job_length", len(req.JobDescription)),
			attribute.String("operation", "analyze"),
		)

		input := types.AnalyzeJobInput{
			JobDescription: req.JobDescription,
		}

		// Create AI service for analyze operation
		analyzeConfig := s.AppConfig.GetAnalyzeConfig()
		aiService, err := ai.NewService(&analyzeConfig, "analyze", s.Logger)
		if err != nil {
			span.RecordError(err)
			span.SetAttributes(attribute.String("error.type", "service_creation"))
			writeErrorResponse(w, "Failed to create AI service", err.Error(), http.StatusInternalServerError)
			return
		}

		metrics := om.GetMetrics()
		var result types.AnalyzeJobOutput
		err = metrics.TrackAIOperationWithTokens(ctx, "analyze", func(ctx context.Context) *observability.AIOperationResult {
			output, tokenUsage, aiErr := aiService.Provider.AnalyzeJob(ctx, input)
			result = output
			return &observability.AIOperationResult{
				Error:      aiErr,
				TokenUsage: (*observability.TokenUsage)(tokenUsage),
			}
		}, om)

		if err != nil {
			span.RecordError(err)
			metrics.RecordBusinessMetric(ctx, "job_analyzed", false, om)
			writeErrorResponse(w, "Failed to analyze job description", err.Error(), http.StatusInternalServerError)
			return
		}

		metrics.RecordBusinessMetric(ctx, "job_analyzed", true, om,
			attribute.Int("quality_score", result.JobQualityScore),
			attribute.Int("clarity_score", result.Clarity.Score),
			attribute.Int("inclusivity_score", result.Inclusivity.Score))

		span.SetAttributes(
			attribute.Bool("success", true),
			attribute.Int("quality_score", result.JobQualityScore),
			attribute.Int("clarity_score", result.Clarity.Score),
			attribute.Int("inclusivity_score", result.Inclusivity.Score),
		)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			span.RecordError(err)
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	}
}

// createRateLimitMiddleware adds observability to rate limiting
func (s *Server) createRateLimitMiddleware(om *observability.ObservabilityManager) func(http.HandlerFunc) http.HandlerFunc {
	originalMiddleware := s.rateLimitMiddleware()

	return func(next http.HandlerFunc) http.HandlerFunc {
		return originalMiddleware(func(w http.ResponseWriter, r *http.Request) {
			// Check if this request was rate limited by examining the response
			// We'll wrap the ResponseWriter to detect rate limit responses
			wrapper := &responseWrapper{ResponseWriter: w, statusCode: 200}

			next(wrapper, r)

			// If rate limited, record metric
			if wrapper.statusCode == http.StatusTooManyRequests {
				metrics := om.GetMetrics()
				metrics.RecordBusinessMetric(r.Context(), "rate_limit_hit", true, om,
					attribute.String("endpoint", r.URL.Path),
					attribute.String("method", r.Method))
			}
		})
	}
}

// responseWrapper wraps http.ResponseWriter to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
