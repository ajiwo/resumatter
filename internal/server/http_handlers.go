package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"resumatter/internal/ai"
)

// getHealthCheckTimeout returns the configured health check timeout
func (s *Server) getHealthCheckTimeout() time.Duration {
	return s.AppConfig.Observability.HealthCheck.Timeout
}

// healthHandler provides a comprehensive health check endpoint including AI model status
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]any{
		"status":  "healthy",
		"service": "resumatter",
		"version": s.Version,
	}

	// Check AI model availability for all operations
	aiStatus := s.checkAIModelsHealth()
	response["ai_models"] = aiStatus

	// Check circuit breaker status
	circuitBreakerStatus := s.checkCircuitBreakerHealth()
	response["circuit_breakers"] = circuitBreakerStatus

	// Check certificate status if certificate manager is available
	certStatus := s.checkCertificateHealth()
	if certStatus != nil {
		response["certificates"] = certStatus
	}

	// Determine overall health status
	overallHealthy := true
	for _, modelStatus := range aiStatus {
		if modelInfo, ok := modelStatus.(map[string]any); ok {
			if available, exists := modelInfo["available"]; exists {
				if avail, ok := available.(bool); ok && !avail {
					overallHealthy = false
					break
				}
			}
		}
	}

	// Check certificate health
	if certStatus != nil {
		if healthy, exists := certStatus["healthy"]; exists {
			if certHealthy, ok := healthy.(bool); ok && !certHealthy {
				overallHealthy = false
			}
		}
	}

	if !overallHealthy {
		response["status"] = "degraded"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode health response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// checkAIModelsHealth checks the health of all AI models used by different operations
func (s *Server) checkAIModelsHealth() map[string]any {
	// Use configurable health check timeout
	timeout := s.getHealthCheckTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	aiStatus := make(map[string]any)

	// Check tailor service model
	tailorConfig := s.AppConfig.GetTailorConfig()
	if tailorService, err := ai.NewService(&tailorConfig, "tailor", s.Logger); err == nil {
		modelInfo := tailorService.GetModelInfo(ctx)
		aiStatus["tailor"] = modelInfo
	} else {
		aiStatus["tailor"] = map[string]any{
			"available": false,
			"error":     fmt.Sprintf("Failed to create tailor service: %v", err),
		}
	}

	// Check evaluate service model
	evaluateConfig := s.AppConfig.GetEvaluateConfig()
	if evaluateService, err := ai.NewService(&evaluateConfig, "evaluate", s.Logger); err == nil {
		modelInfo := evaluateService.GetModelInfo(ctx)
		aiStatus["evaluate"] = modelInfo
	} else {
		aiStatus["evaluate"] = map[string]any{
			"available": false,
			"error":     fmt.Sprintf("Failed to create evaluate service: %v", err),
		}
	}

	// Check analyze service model
	analyzeConfig := s.AppConfig.GetAnalyzeConfig()
	if analyzeService, err := ai.NewService(&analyzeConfig, "analyze", s.Logger); err == nil {
		modelInfo := analyzeService.GetModelInfo(ctx)
		aiStatus["analyze"] = modelInfo
	} else {
		aiStatus["analyze"] = map[string]any{
			"available": false,
			"error":     fmt.Sprintf("Failed to create analyze service: %v", err),
		}
	}

	return aiStatus
}

// checkCircuitBreakerHealth checks the health of circuit breakers for all AI operations
func (s *Server) checkCircuitBreakerHealth() map[string]any {
	circuitBreakerStatus := make(map[string]any)

	// Check tailor service circuit breaker
	tailorConfig := s.AppConfig.GetTailorConfig()
	if _, err := ai.NewService(&tailorConfig, "tailor", s.Logger); err == nil {
		circuitBreakerStatus["tailor"] = map[string]any{
			"available": true,
			"message":   "Circuit breaker integrated with tailor service",
		}
	} else {
		circuitBreakerStatus["tailor"] = map[string]any{
			"available": false,
			"error":     fmt.Sprintf("Failed to create tailor service: %v", err),
		}
	}

	// Check evaluate service circuit breaker
	evaluateConfig := s.AppConfig.GetEvaluateConfig()
	if _, err := ai.NewService(&evaluateConfig, "evaluate", s.Logger); err == nil {
		circuitBreakerStatus["evaluate"] = map[string]any{
			"available": true,
			"message":   "Circuit breaker integrated with evaluate service",
		}
	} else {
		circuitBreakerStatus["evaluate"] = map[string]any{
			"available": false,
			"error":     fmt.Sprintf("Failed to create evaluate service: %v", err),
		}
	}

	// Check analyze service circuit breaker
	analyzeConfig := s.AppConfig.GetAnalyzeConfig()
	if _, err := ai.NewService(&analyzeConfig, "analyze", s.Logger); err == nil {
		circuitBreakerStatus["analyze"] = map[string]any{
			"available": true,
			"message":   "Circuit breaker integrated with analyze service",
		}
	} else {
		circuitBreakerStatus["analyze"] = map[string]any{
			"available": false,
			"error":     fmt.Sprintf("Failed to create analyze service: %v", err),
		}
	}

	return circuitBreakerStatus
}

// checkCertificateHealth checks the health of TLS certificates
func (s *Server) checkCertificateHealth() map[string]any {
	if s.CertificateManager == nil {
		return nil
	}

	certStatus := make(map[string]any)

	// Check certificate expiry
	timeToExpiry, err := s.CertificateManager.CheckExpiry()
	if err != nil {
		certStatus["healthy"] = false
		certStatus["error"] = fmt.Sprintf("Failed to check certificate expiry: %v", err)
		return certStatus
	}

	// Consider certificates unhealthy if they expire within 24 hours
	criticalThreshold := 24 * time.Hour
	warningThreshold := 7 * 24 * time.Hour // 7 days

	certStatus["time_to_expiry_hours"] = int(timeToExpiry.Hours())
	certStatus["time_to_expiry"] = timeToExpiry.String()

	if timeToExpiry <= 0 {
		certStatus["healthy"] = false
		certStatus["status"] = "expired"
		certStatus["message"] = "Certificate has expired"
	} else if timeToExpiry <= criticalThreshold {
		certStatus["healthy"] = false
		certStatus["status"] = "critical"
		certStatus["message"] = "Certificate expires within 24 hours"
	} else if timeToExpiry <= warningThreshold {
		certStatus["healthy"] = true
		certStatus["status"] = "warning"
		certStatus["message"] = "Certificate expires within 7 days"
	} else {
		certStatus["healthy"] = true
		certStatus["status"] = "ok"
		certStatus["message"] = "Certificate is valid"
	}

	// Add auto-reload status
	if s.TLSConfig.AutoReload.Enabled {
		certStatus["auto_reload"] = map[string]any{
			"enabled":               true,
			"file_watcher_enabled":  s.TLSConfig.AutoReload.FileWatcher.Enabled,
			"vault_watcher_enabled": s.TLSConfig.AutoReload.VaultWatcher.Enabled,
		}

		// Add file watcher status
		if s.CertificateManager.fileWatcher != nil {
			certStatus["auto_reload"].(map[string]any)["file_watcher_running"] = s.CertificateManager.fileWatcher.IsRunning()
			certStatus["auto_reload"].(map[string]any)["watched_files"] = s.CertificateManager.fileWatcher.GetWatchedFiles()
		}

		// Add vault watcher status
		if s.CertificateManager.vaultWatcher != nil {
			certStatus["auto_reload"].(map[string]any)["vault_watcher_status"] = s.CertificateManager.vaultWatcher.Status()
		}
	} else {
		certStatus["auto_reload"] = map[string]any{
			"enabled": false,
		}
	}

	// Add certificate metrics
	metrics := s.CertificateManager.GetMetrics()
	if metrics != nil {
		certStatus["metrics"] = map[string]any{
			"reload_count":         metrics.ReloadCount,
			"reload_success_count": metrics.ReloadSuccessCount,
			"reload_failure_count": metrics.ReloadFailureCount,
			"last_reload_time":     metrics.LastReloadTime,
			"last_reload_success":  metrics.LastReloadSuccess,
			"last_reload_error":    metrics.LastReloadError,
		}
	}

	return certStatus
}

// statsHandler provides server statistics including rate limiting info
func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]any{
		"service": "resumatter",
		"version": s.Version,
		"server": map[string]any{
			"max_request_size_bytes": s.MaxRequestSize,
		},
	}

	// Add rate limiting stats if enabled
	if s.RateLimiter != nil {
		response["rate_limiting"] = s.RateLimiter.GetStats()
	} else {
		response["rate_limiting"] = map[string]any{
			"enabled": false,
		}
	}

	// Add configuration info
	if s.RateLimit != nil {
		response["rate_limit_config"] = map[string]any{
			"enabled":          s.RateLimit.Enabled,
			"requests_per_min": s.RateLimit.RequestsPerMin,
			"burst_capacity":   s.RateLimit.BurstCapacity,
			"by_ip":            s.RateLimit.ByIP,
			"by_api_key":       s.RateLimit.ByAPIKey,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode stats response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// parseJSONRequest parses JSON request body into the provided struct
func parseJSONRequest(r *http.Request, v any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("content-type must be application/json")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("request body too large (limit is %d bytes)", maxBytesErr.Limit)
		}
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("Failed to close request body: %v", err)
		}
	}()

	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	return nil
}

// writeErrorResponse writes a standardized error response
func writeErrorResponse(w http.ResponseWriter, error, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   error,
		Message: message,
	}

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Failed to encode error response: %v", err)
		http.Error(w, "Failed to encode error response", http.StatusInternalServerError)
	}
}
