package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"resumatter/internal/ai"
	"resumatter/internal/config"
	resumatterErrors "resumatter/internal/errors"
	"resumatter/internal/observability"
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

func (s *Server) Start() error {
	om, err := s.initializeObservability()
	if err != nil {
		return err
	}
	defer s.shutdownObservability(om)

	httpServer, err := s.setupHTTPServer(om)
	if err != nil {
		return err
	}

	vaultClient, err := s.initializeVaultClient()
	if err != nil {
		return err
	}

	if err := s.configureTLS(httpServer, vaultClient, om); err != nil {
		return err
	}

	s.displayServerInfo()

	return s.startWithGracefulShutdown(httpServer)
}

// initializeObservability sets up observability components
func (s *Server) initializeObservability() (*observability.ObservabilityManager, error) {
	obsConfig := observability.ObservabilityConfig{
		ServiceName:    s.AppConfig.Observability.ServiceName,
		ServiceVersion: s.Version,
		Enabled:        s.AppConfig.Observability.Enabled,
		ConsoleOutput:  s.AppConfig.Observability.ConsoleOutput,
		PrettyPrint:    s.AppConfig.Observability.Console.PrettyPrint,
		SampleRate:     s.AppConfig.Observability.SampleRate,
		Prometheus: observability.PrometheusConfig{
			Enabled:  s.AppConfig.Observability.Prometheus.Enabled,
			Endpoint: s.AppConfig.Observability.Prometheus.Endpoint,
			Port:     s.AppConfig.Observability.Prometheus.Port,
		},
	}

	om, err := observability.NewObservabilityManager(obsConfig, s.AppConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize observability: %w", err)
	}

	return om, nil
}

// shutdownObservability handles observability cleanup
func (s *Server) shutdownObservability(om *observability.ObservabilityManager) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := om.Shutdown(ctx); err != nil {
		s.Logger.LogError(err, "Failed to shutdown observability")
	}
}

// setupHTTPServer creates and configures the HTTP server
func (s *Server) setupHTTPServer(om *observability.ObservabilityManager) (*http.Server, error) {
	mux := s.setupRoutes(om)
	handler := om.HTTPMiddleware()(mux)
	addr := fmt.Sprintf("%s:%s", s.Host, s.Port)

	return &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  s.ReadTimeout,
		WriteTimeout: s.WriteTimeout,
		IdleTimeout:  s.IdleTimeout,
	}, nil
}

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

// initializeVaultClient creates a Vault client if needed
func (s *Server) initializeVaultClient() (VaultClientInterface, error) {
	if !s.TLSConfig.AutoReload.VaultWatcher.Enabled {
		return nil, nil
	}

	vc, err := config.NewVaultClient(s.AppConfig.Vault, s.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Vault client: %w", err)
	}

	return vc, nil
}

// configureTLS sets up TLS configuration based on the mode
func (s *Server) configureTLS(httpServer *http.Server, vaultClient VaultClientInterface, om *observability.ObservabilityManager) error {
	addr := httpServer.Addr

	switch s.TLSConfig.Mode {
	case "server":
		return s.configureServerTLS(httpServer, addr, vaultClient, om)
	case "mutual":
		return s.configureMutualTLS(httpServer, addr, vaultClient, om)
	case "disabled":
		fmt.Printf("Starting server on http://%s\n", addr)
		fmt.Println("TLS mode: Disabled (HTTP only)")
		return nil
	default:
		return fmt.Errorf("invalid TLS mode: %s (must be 'disabled', 'server', or 'mutual')", s.TLSConfig.Mode)
	}
}

// configureServerTLS sets up server-only TLS
func (s *Server) configureServerTLS(httpServer *http.Server, addr string, vaultClient VaultClientInterface, om *observability.ObservabilityManager) error {
	fmt.Printf("Starting server with HTTPS (server-only TLS) on https://%s\n", addr)
	fmt.Println("TLS mode: Server-only (no client certificates required)")

	if err := s.setupCertificateManager(vaultClient, om); err != nil {
		return err
	}

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to set up TLS: %w", err)
	}
	httpServer.TLSConfig = tlsConfig

	return nil
}

// configureMutualTLS sets up mutual TLS
func (s *Server) configureMutualTLS(httpServer *http.Server, addr string, vaultClient VaultClientInterface, om *observability.ObservabilityManager) error {
	fmt.Printf("Starting server with mTLS (mutual TLS) on https://%s\n", addr)
	fmt.Println("TLS mode: Mutual (client certificates required)")

	if err := s.setupCertificateManager(vaultClient, om); err != nil {
		return err
	}

	tlsConfig, err := s.buildTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to set up mTLS: %w", err)
	}
	httpServer.TLSConfig = tlsConfig

	return nil
}

// setupCertificateManager initializes certificate manager if auto-reload is enabled
func (s *Server) setupCertificateManager(vaultClient VaultClientInterface, om *observability.ObservabilityManager) error {
	if !s.TLSConfig.AutoReload.Enabled {
		return nil
	}

	certManager := NewCertificateManager(&s.TLSConfig, &s.TLSConfig.AutoReload, vaultClient, om, s.Logger)
	if err := certManager.Start(); err != nil {
		return fmt.Errorf("failed to start certificate manager: %w", err)
	}
	s.CertificateManager = certManager

	// Add reload callback to log certificate reloads
	certManager.AddReloadCallback(func(success bool, err error) {
		if success {
			s.Logger.Info("TLS certificates reloaded successfully")
		} else {
			s.Logger.LogError(err, "Failed to reload TLS certificates")
		}
	})

	s.displayAutoReloadInfo()

	return nil
}

// displayAutoReloadInfo shows auto-reload configuration
func (s *Server) displayAutoReloadInfo() {
	fmt.Println("TLS auto-reload: ENABLED")
	if s.TLSConfig.AutoReload.FileWatcher.Enabled {
		fmt.Println("  - File watching enabled")
	}
	if s.TLSConfig.AutoReload.VaultWatcher.Enabled {
		fmt.Println("  - Vault watching enabled")
	}
}

// displayServerInfo shows server configuration information
func (s *Server) displayServerInfo() {
	s.displayEndpoints()
	s.displayAuthInfo()
	s.displayRequestLimitInfo()
	s.displayRateLimitInfo()
}

// displayEndpoints shows available API endpoints
func (s *Server) displayEndpoints() {
	fmt.Println("Available endpoints:")
	fmt.Println("  GET  /health    - Health check")
	fmt.Println("  GET  /stats     - Server statistics")
	fmt.Println("  POST /tailor    - Tailor resume (requires API key)")
	fmt.Println("  POST /evaluate  - Evaluate resume (requires API key)")
	fmt.Println("  POST /analyze   - Analyze job description (requires API key)")
}

// displayAuthInfo shows authentication configuration
func (s *Server) displayAuthInfo() {
	if len(s.APIKeys) > 0 {
		fmt.Printf("API authentication: ENABLED (%d keys configured)\n", len(s.APIKeys))
		fmt.Println("Include 'X-API-Key: <your-key>' header in requests to /tailor and /evaluate")
	} else {
		fmt.Println("API authentication: DISABLED (no API keys configured)")
		fmt.Println("WARNING: API endpoints are publicly accessible!")
	}
}

// displayRequestLimitInfo shows request size limit configuration
func (s *Server) displayRequestLimitInfo() {
	if s.MaxRequestSize > 0 {
		fmt.Printf("Request size limit: %d bytes (%.1f MB)\n", s.MaxRequestSize, float64(s.MaxRequestSize)/(1024*1024))
	} else {
		fmt.Println("Request size limit: DISABLED")
		fmt.Println("WARNING: No request size limits configured!")
	}
}

// displayRateLimitInfo shows rate limiting configuration
func (s *Server) displayRateLimitInfo() {
	if s.RateLimit != nil && s.RateLimit.Enabled {
		fmt.Printf("Rate limiting: ENABLED (%d requests/min, burst: %d)\n",
			s.RateLimit.RequestsPerMin, s.RateLimit.BurstCapacity)
		if s.RateLimit.ByAPIKey {
			fmt.Println("  - Per API key rate limiting enabled")
		}
		if s.RateLimit.ByIP {
			fmt.Println("  - Per IP address rate limiting enabled")
		}
	} else {
		fmt.Println("Rate limiting: DISABLED")
		fmt.Println("WARNING: No rate limiting configured!")
	}
}

// startWithGracefulShutdown starts the HTTP server and handles graceful shutdown
func (s *Server) startWithGracefulShutdown(server *http.Server) error {
	// Channel to receive OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Channel to receive server errors
	serverErrors := make(chan error, 1)

	// Start the server in a goroutine
	go func() {
		s.Logger.Info("Starting HTTP server",
			"address", server.Addr,
			"tls_enabled", server.TLSConfig != nil)

		var err error
		if server.TLSConfig != nil {
			// When using TLS with certificate content, we need to use ListenAndServeTLS with empty strings
			// because the certificates are already loaded in the TLS config
			if s.TLSConfig.CertContent != "" || s.TLSConfig.KeyContent != "" {
				err = server.ListenAndServeTLS("", "")
			} else {
				err = server.ListenAndServeTLS(s.TLSConfig.CertFile, s.TLSConfig.KeyFile)
			}
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	// Wait for either a signal or server error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server failed to start: %w", err)
	case sig := <-quit:
		s.Logger.Info("Received shutdown signal, starting graceful shutdown",
			"signal", sig.String())

		// Create a context with timeout for graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Stop certificate manager if running
		if s.CertificateManager != nil {
			if err := s.CertificateManager.Stop(); err != nil {
				s.Logger.LogError(err, "Failed to stop certificate manager")
			}
		}

		// Clean up rate limiter if enabled
		if s.RateLimiter != nil {
			s.RateLimiter.Close()
			s.Logger.Info("Rate limiter cleanup completed")
		}

		// Attempt graceful shutdown
		if err := server.Shutdown(shutdownCtx); err != nil {
			s.Logger.LogError(err, "Failed to shutdown server gracefully")
			return fmt.Errorf("server shutdown failed: %w", err)
		}

		s.Logger.Info("Server shutdown completed successfully")
		return nil
	}
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
		s.Logger.Info("API request authenticated",
			"endpoint", r.URL.Path,
			"client_ip", r.RemoteAddr,
			"api_key_prefix", maskAPIKey(apiKey))

		next(w, r)
	}
}

// maskAPIKey masks an API key for logging (shows only first 8 characters)
func maskAPIKey(apiKey string) string {
	if len(apiKey) <= 8 {
		return "****"
	}
	return apiKey[:8] + "****"
}

// requestSizeLimitMiddleware limits the size of incoming request bodies
func (s *Server) requestSizeLimitMiddleware() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Skip size limiting if not configured
			if s.MaxRequestSize <= 0 {
				next(w, r)
				return
			}

			// Limit the request body size
			r.Body = http.MaxBytesReader(w, r.Body, s.MaxRequestSize)

			next(w, r)
		}
	}
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Set minimum TLS version
	}

	if err := s.configureTLSCertificates(tlsConfig); err != nil {
		return nil, err
	}

	s.configureTLSVersion(tlsConfig)
	s.configureCipherSuites(tlsConfig)

	if err := s.configureClientAuthentication(tlsConfig); err != nil {
		return nil, err
	}

	s.configureDevelopmentOptions(tlsConfig)

	return tlsConfig, nil
}

// configureTLSCertificates sets up certificate loading (dynamic or static)
func (s *Server) configureTLSCertificates(tlsConfig *tls.Config) error {
	if s.CertificateManager != nil {
		return s.configureDynamicCertificates(tlsConfig)
	}
	return s.configureStaticCertificates(tlsConfig)
}

// configureDynamicCertificates sets up dynamic certificate loading via certificate manager
func (s *Server) configureDynamicCertificates(tlsConfig *tls.Config) error {
	tlsConfig.GetCertificate = s.CertificateManager.GetServerCertificate

	// Set up client certificate verification for mutual TLS
	if s.TLSConfig.Mode == "mutual" {
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return s.CertificateManager.GetClientCertificate()
		}
		tlsConfig.VerifyPeerCertificate = s.CertificateManager.VerifyPeerCertificate
	}

	return nil
}

// configureStaticCertificates sets up static certificate loading for backward compatibility
func (s *Server) configureStaticCertificates(tlsConfig *tls.Config) error {
	cert, err := s.loadServerCertificate()
	if err != nil {
		return err
	}

	tlsConfig.Certificates = []tls.Certificate{cert}
	return nil
}

// loadServerCertificate loads the server certificate from content or files
func (s *Server) loadServerCertificate() (tls.Certificate, error) {
	if s.TLSConfig.CertContent != "" && s.TLSConfig.KeyContent != "" {
		// Load from certificate content (preferred for Vault)
		cert, err := tls.X509KeyPair([]byte(s.TLSConfig.CertContent), []byte(s.TLSConfig.KeyContent))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load server cert/key from content: %w", err)
		}
		return cert, nil
	}

	if s.TLSConfig.CertFile != "" && s.TLSConfig.KeyFile != "" {
		// Load from files (traditional approach)
		cert, err := tls.LoadX509KeyPair(s.TLSConfig.CertFile, s.TLSConfig.KeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load server cert/key from files: %w", err)
		}
		return cert, nil
	}

	return tls.Certificate{}, fmt.Errorf("TLS certificate and key are required (provide either files or content)")
}

// configureTLSVersion sets the minimum TLS version
func (s *Server) configureTLSVersion(tlsConfig *tls.Config) {
	switch s.TLSConfig.MinVersion {
	case "1.2":
		tlsConfig.MinVersion = tls.VersionTLS12
	case "1.3":
		tlsConfig.MinVersion = tls.VersionTLS13
	default:
		tlsConfig.MinVersion = tls.VersionTLS12 // Default to TLS 1.2
	}
}

// configureCipherSuites configures the cipher suites if specified
func (s *Server) configureCipherSuites(tlsConfig *tls.Config) {
	if len(s.TLSConfig.CipherSuites) == 0 {
		return
	}

	cipherSuites := make([]uint16, 0, len(s.TLSConfig.CipherSuites))
	for _, suite := range s.TLSConfig.CipherSuites {
		if cipherID := getCipherSuiteID(suite); cipherID != 0 {
			cipherSuites = append(cipherSuites, cipherID)
		}
	}
	tlsConfig.CipherSuites = cipherSuites
}

// configureClientAuthentication sets up client authentication for mutual TLS
func (s *Server) configureClientAuthentication(tlsConfig *tls.Config) error {
	if s.TLSConfig.Mode != "mutual" {
		// For server-only TLS, no client authentication
		tlsConfig.ClientAuth = tls.NoClientCert
		return nil
	}

	caCertPool, err := s.loadCACertificatePool()
	if err != nil {
		return err
	}

	tlsConfig.ClientCAs = caCertPool
	tlsConfig.ClientAuth = s.getClientAuthPolicy()

	return nil
}

// loadCACertificatePool loads the CA certificate pool for client verification
func (s *Server) loadCACertificatePool() (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	caCert, err := s.loadCACertificate()
	if err != nil {
		return nil, err
	}

	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	return caCertPool, nil
}

// loadCACertificate loads the CA certificate from content or file
func (s *Server) loadCACertificate() ([]byte, error) {
	if s.TLSConfig.CAContent != "" {
		// Load CA from content (preferred for Vault)
		return []byte(s.TLSConfig.CAContent), nil
	}

	if s.TLSConfig.CAFile != "" {
		// Load CA from file (traditional approach)
		caCert, err := os.ReadFile(s.TLSConfig.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		return caCert, nil
	}

	return nil, fmt.Errorf("CA certificate is required for mutual TLS mode (provide either caFile or caContent)")
}

// getClientAuthPolicy returns the appropriate client authentication policy
func (s *Server) getClientAuthPolicy() tls.ClientAuthType {
	switch s.TLSConfig.ClientAuthPolicy {
	case "require":
		return tls.RequireAndVerifyClientCert
	case "request":
		return tls.RequestClientCert
	case "verify":
		return tls.VerifyClientCertIfGiven
	default:
		return tls.RequireAndVerifyClientCert // Default for mutual TLS
	}
}

// configureDevelopmentOptions sets development/testing options
func (s *Server) configureDevelopmentOptions(tlsConfig *tls.Config) {
	if s.TLSConfig.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		fmt.Println("WARNING: TLS certificate verification is disabled (insecureSkipVerify=true)")
	}

	if s.TLSConfig.ServerName != "" {
		tlsConfig.ServerName = s.TLSConfig.ServerName
	}
}

// getCipherSuiteID returns the cipher suite ID for a given name
func getCipherSuiteID(name string) uint16 {
	cipherSuites := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
		"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
		"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
	return cipherSuites[name]
}

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
