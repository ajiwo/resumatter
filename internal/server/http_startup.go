package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"resumatter/internal/observability"
)

// Start starts the HTTP server with all configured components
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

		return s.performGracefulShutdown(server)
	}
}

// performGracefulShutdown handles the graceful shutdown process
func (s *Server) performGracefulShutdown(server *http.Server) error {
	// Create a context with timeout for graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop certificate manager if running
	if err := s.stopCertificateManager(); err != nil {
		s.Logger.LogError(err, "Failed to stop certificate manager")
	}

	// Clean up rate limiter if enabled
	s.cleanupRateLimiter()

	// Attempt graceful shutdown of HTTP server
	s.Logger.Info("Shutting down HTTP server...")
	if err := server.Shutdown(shutdownCtx); err != nil {
		s.Logger.LogError(err, "Failed to shutdown server gracefully, forcing close")
		return server.Close()
	}

	s.Logger.Info("Server shutdown completed successfully")
	return nil
}

// stopCertificateManager stops the certificate manager if it's running
func (s *Server) stopCertificateManager() error {
	if s.CertificateManager != nil {
		return s.CertificateManager.Stop()
	}
	return nil
}

// cleanupRateLimiter cleans up the rate limiter resources
func (s *Server) cleanupRateLimiter() {
	if s.RateLimiter != nil {
		s.RateLimiter.Close()
		s.Logger.Info("Rate limiter cleaned up")
	}
}
