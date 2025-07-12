package server

import (
	"net/http"
	"strings"

	"resumatter/internal/observability"
)

// setupRoutes configures all HTTP routes and middleware
func (s *Server) setupRoutes(om *observability.ObservabilityManager) *http.ServeMux {
	mux := http.NewServeMux()

	// Add middleware layers with observability
	rateLimitHandler := s.createRateLimitMiddleware(om)
	requestLimitHandler := s.requestSizeLimitMiddleware()

	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/stats", s.statsHandler)
	mux.HandleFunc("/tailor",
		rateLimitHandler(
			s.authMiddleware(requestLimitHandler(s.createTailorHandler(om))),
		),
	)
	mux.HandleFunc("/evaluate",
		rateLimitHandler(
			s.authMiddleware(requestLimitHandler(s.createEvaluateHandler(om))),
		),
	)
	mux.HandleFunc("/analyze",
		rateLimitHandler(
			s.authMiddleware(requestLimitHandler(s.createAnalyzeHandler(om))),
		),
	)

	return mux
}

// authMiddleware provides API key authentication
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication if no API keys are configured
		if len(s.APIKeys) == 0 {
			next(w, r)
			return
		}

		// Check for API key in X-API-Key header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Check for Bearer token in Authorization header as fallback
			authHeader := r.Header.Get("Authorization")
			if after, ok := strings.CutPrefix(authHeader, "Bearer "); ok {
				apiKey = after
			}
		}

		if apiKey == "" {
			s.Logger.Info("Authentication failed: missing API key",
				"endpoint", r.URL.Path,
				"client_ip", r.RemoteAddr)
			writeErrorResponse(w, "Missing API key", "X-API-Key header or Authorization Bearer token required", http.StatusUnauthorized)
			return
		}

		// Validate API key
		if !s.APIKeys[apiKey] {
			s.Logger.Info("Authentication failed: invalid API key",
				"endpoint", r.URL.Path,
				"client_ip", r.RemoteAddr,
				"api_key_prefix", maskAPIKey(apiKey))
			writeErrorResponse(w, "Invalid API key", "Unauthorized access", http.StatusUnauthorized)
			return
		}

		// Log successful authentication
		s.Logger.Debug("API authentication successful",
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
			"api_key_prefix", maskAPIKey(apiKey))

		next(w, r)
	}
}

// requestSizeLimitMiddleware limits the size of incoming requests
func (s *Server) requestSizeLimitMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.MaxRequestSize > 0 {
				// Limit the request body size
				r.Body = http.MaxBytesReader(w, r.Body, s.MaxRequestSize)
			}

			next(w, r)
		}
	}
}

// maskAPIKey masks an API key for logging (shows only first 8 characters)
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "****"
	}
	return apiKey[:8] + "****"
}
