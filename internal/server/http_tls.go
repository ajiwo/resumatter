package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"resumatter/internal/config"
	"resumatter/internal/observability"
)

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

// buildTLSConfig creates the TLS configuration
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
