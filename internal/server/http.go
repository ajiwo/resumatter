package server

import (
	"time"

	"resumatter/internal/config"
	resumatterErrors "resumatter/internal/errors"
)

// TailorRequest represents the request body for the tailor endpoint
// EvaluateRequest represents the request body for the evaluate endpoint
// ErrorResponse represents an error response
type TailorRequest struct {
	BaseResume     string `json:"baseResume"`
	JobDescription string `json:"jobDescription"`
}

type EvaluateRequest struct {
	BaseResume     string `json:"baseResume"`
	TailoredResume string `json:"tailoredResume"`
}

type AnalyzeRequest struct {
	JobDescription string `json:"jobDescription"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Server holds configuration for the HTTP server
type Server struct {
	Host    string
	Port    string
	Version string

	// Full application configuration
	AppConfig *config.Config

	// TLS Configuration
	TLSConfig config.TLSConfig

	// Certificate management
	CertificateManager *CertificateManager

	// API Authentication
	APIKeys map[string]bool

	// Timeout configurations
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Request size limit
	MaxRequestSize int64

	// Rate limiting
	RateLimit   *config.RateLimitConfig
	RateLimiter *RateLimiter

	// Logger
	Logger *resumatterErrors.Logger
}

// ServerConfig holds configuration for creating a Server instance
// (Refactored to reduce long parameter list in NewServer)
type ServerConfig struct {
	Host           string
	Port           string
	Version        string
	TLSConfig      config.TLSConfig
	APIKeys        []string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxRequestSize int64
	RateLimit      *config.RateLimitConfig
}

// NewServer creates a new Server instance from a ServerConfig struct
func NewServer(appCfg *config.Config, cfg ServerConfig, logger *resumatterErrors.Logger) *Server {
	// Convert API keys slice to map for O(1) lookup
	apiKeyMap := make(map[string]bool)
	for _, key := range cfg.APIKeys {
		if key != "" {
			apiKeyMap[key] = true
		}
	}

	var rateLimiter *RateLimiter
	if cfg.RateLimit != nil && cfg.RateLimit.Enabled {
		rateLimiter = NewRateLimiter(
			cfg.RateLimit.RequestsPerMin,
			cfg.RateLimit.Window,
			cfg.RateLimit.BurstCapacity,
			logger,
		)
	}

	return &Server{
		Host:           cfg.Host,
		Port:           cfg.Port,
		Version:        cfg.Version,
		AppConfig:      appCfg,
		TLSConfig:      cfg.TLSConfig,
		APIKeys:        apiKeyMap,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxRequestSize: cfg.MaxRequestSize,
		RateLimit:      cfg.RateLimit,
		RateLimiter:    rateLimiter,
		Logger:         logger,
	}
}
