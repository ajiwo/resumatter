package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"

	"resumatter/internal/config"
	"resumatter/internal/errors"
	"resumatter/internal/observability"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// CertificateManager manages TLS certificates with auto-reload capability
type CertificateManager struct {
	mu sync.RWMutex

	// Current certificates
	serverCert *tls.Certificate
	clientCert *tls.Certificate
	caCertPool *x509.CertPool

	// Certificate metadata
	serverCertExpiry time.Time
	clientCertExpiry time.Time
	lastReloadTime   time.Time

	// Watchers
	fileWatcher  *CertWatcher
	vaultWatcher *VaultWatcher

	// Configuration
	config           *config.TLSConfig
	autoReloadConfig *config.AutoReloadConfig
	vaultClient      VaultClientInterface

	// Callbacks and metrics
	reloadCallbacks []ReloadCallback
	logger          *errors.Logger

	// Observability
	observabilityManager *observability.ObservabilityManager

	// Internal metrics tracking
	reloadCount        int64
	reloadSuccessCount int64
	reloadFailureCount int64
	lastReloadSuccess  bool
	lastReloadError    string
}

// ReloadCallback is called when certificates are reloaded
type ReloadCallback func(success bool, err error)

// CertificateMetrics holds metrics about certificate operations
type CertificateMetrics struct {
	ReloadCount        int64
	ReloadSuccessCount int64
	ReloadFailureCount int64
	LastReloadTime     time.Time
	LastReloadSuccess  bool
	LastReloadError    string
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(tlsConfig *config.TLSConfig, autoReloadConfig *config.AutoReloadConfig, vaultClient VaultClientInterface, om *observability.ObservabilityManager, logger *errors.Logger) *CertificateManager {
	return &CertificateManager{
		config:               tlsConfig,
		autoReloadConfig:     autoReloadConfig,
		vaultClient:          vaultClient,
		logger:               logger,
		reloadCallbacks:      make([]ReloadCallback, 0),
		observabilityManager: om,
	}
}

// Start initializes and starts the certificate manager
func (cm *CertificateManager) Start() error {
	// Load initial certificates
	if err := cm.loadCertificates(); err != nil {
		return fmt.Errorf("failed to load initial certificates: %w", err)
	}

	// Start certificate expiry monitoring
	cm.StartExpiryMonitoring()

	// Start file watcher if enabled
	if err := cm.startFileWatcher(); err != nil {
		return err
	}

	// Start Vault watcher if enabled
	if err := cm.startVaultWatcher(); err != nil {
		return err
	}

	return nil
}

// startFileWatcher starts the file watcher if enabled and using file-based certificates
func (cm *CertificateManager) startFileWatcher() error {
	if cm.autoReloadConfig == nil || !cm.autoReloadConfig.FileWatcher.Enabled {
		return nil
	}

	if cm.config.CertFile == "" && cm.config.KeyFile == "" && cm.config.CAFile == "" {
		return nil
	}

	watcher, err := NewCertWatcher(
		cm.config.CertFile,
		cm.config.KeyFile,
		cm.config.CAFile,
		cm.autoReloadConfig.FileWatcher.DebounceDelay,
		cm.triggerReload,
		cm.logger,
	)
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	cm.fileWatcher = watcher
	if err := cm.fileWatcher.Start(); err != nil {
		return fmt.Errorf("failed to start file watcher: %w", err)
	}

	if cm.logger != nil {
		cm.logger.Info("Certificate file watcher started",
			"cert_file", cm.config.CertFile,
			"key_file", cm.config.KeyFile,
			"ca_file", cm.config.CAFile)
	}

	return nil
}

// startVaultWatcher starts the Vault watcher if enabled and using Vault-based certificates
func (cm *CertificateManager) startVaultWatcher() error {
	if !cm.shouldStartVaultWatcher() {
		return nil
	}

	if !cm.isVaultClientAvailable() {
		return nil
	}

	vw, err := cm.createVaultWatcher()
	if err != nil {
		return err
	}

	return cm.startVaultWatcherInstance(vw)
}

// shouldStartVaultWatcher checks if Vault watcher should be started
func (cm *CertificateManager) shouldStartVaultWatcher() bool {
	return cm.autoReloadConfig != nil && cm.autoReloadConfig.VaultWatcher.Enabled &&
		(cm.config.CertContent != "" || cm.config.KeyContent != "" || cm.config.CAContent != "")
}

// isVaultClientAvailable checks if Vault client is available
func (cm *CertificateManager) isVaultClientAvailable() bool {
	if cm.vaultClient == nil {
		if cm.logger != nil {
			cm.logger.Warn("Vault watcher enabled but Vault client is nil")
		}
		return false
	}
	return true
}

// createVaultWatcher creates a new Vault watcher instance
func (cm *CertificateManager) createVaultWatcher() (*VaultWatcher, error) {
	vaultReloadCb := cm.createVaultReloadCallback()
	vw := NewVaultWatcher(
		cm.vaultClient,
		cm.autoReloadConfig.VaultWatcher.SecretPath,
		cm.autoReloadConfig.VaultWatcher.PollInterval,
		vaultReloadCb,
		cm.logger,
	)
	return vw, nil
}

// startVaultWatcherInstance starts the Vault watcher instance
func (cm *CertificateManager) startVaultWatcherInstance(vw *VaultWatcher) error {
	cm.vaultWatcher = vw
	if err := cm.vaultWatcher.Start(); err != nil {
		return fmt.Errorf("failed to start Vault watcher: %w", err)
	}

	if cm.logger != nil {
		cm.logger.Info("Vault watcher started",
			"secret_path", cm.autoReloadConfig.VaultWatcher.SecretPath,
			"poll_interval", cm.autoReloadConfig.VaultWatcher.PollInterval)
	}

	return nil
}

// createVaultReloadCallback creates a callback that handles new certificate data from Vault
func (cm *CertificateManager) createVaultReloadCallback() func(*CertificateData, error) {
	return func(data *CertificateData, err error) {
		if err != nil {
			if cm.logger != nil {
				cm.logger.LogError(err, "Failed to fetch new certificate data from Vault")
			}
			return
		}

		// Update the certificate manager's configuration with new data
		cm.mu.Lock()
		if data.CertContent != "" {
			cm.config.CertContent = data.CertContent
		}
		if data.KeyContent != "" {
			cm.config.KeyContent = data.KeyContent
		}
		if data.CAContent != "" {
			cm.config.CAContent = data.CAContent
		}
		cm.mu.Unlock()

		// Now trigger the internal reload logic
		cm.triggerReload()
	}
}

// Stop stops the certificate manager and all watchers
func (cm *CertificateManager) Stop() error {
	if cm.fileWatcher != nil {
		if err := cm.fileWatcher.Stop(); err != nil {
			if cm.logger != nil {
				cm.logger.LogError(err, "Failed to stop file watcher")
			}
			return err
		}
	}
	if cm.vaultWatcher != nil {
		if err := cm.vaultWatcher.Stop(); err != nil {
			if cm.logger != nil {
				cm.logger.LogError(err, "Failed to stop Vault watcher")
			}
			return err
		}
	}
	if cm.logger != nil {
		cm.logger.Info("Certificate manager stopped")
	}
	return nil
}

// GetServerCertificate returns the current server certificate for TLS handshakes
func (cm *CertificateManager) GetServerCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.serverCert == nil {
		return nil, fmt.Errorf("no server certificate available")
	}

	// Check certificate expiry
	if time.Now().After(cm.serverCertExpiry) {
		if cm.logger != nil {
			cm.logger.LogError(fmt.Errorf("server certificate expired"), "Server certificate expired",
				"expiry", cm.serverCertExpiry,
				"server_name", hello.ServerName)
		}
		return nil, fmt.Errorf("server certificate expired")
	}

	// Check if preemptive renewal is needed
	if cm.autoReloadConfig != nil && cm.autoReloadConfig.PreemptiveRenewal > 0 {
		renewalTime := cm.serverCertExpiry.Add(-cm.autoReloadConfig.PreemptiveRenewal)
		if time.Now().After(renewalTime) {
			go cm.triggerPreemptiveRenewal()
		}
	}

	return cm.serverCert, nil
}

// GetClientCertificate returns the current client certificate
func (cm *CertificateManager) GetClientCertificate() (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.clientCert == nil {
		return nil, fmt.Errorf("no client certificate available")
	}

	// Check certificate expiry
	if time.Now().After(cm.clientCertExpiry) {
		if cm.logger != nil {
			cm.logger.LogError(fmt.Errorf("client certificate expired"), "Client certificate expired", "expiry", cm.clientCertExpiry)
		}
		return nil, fmt.Errorf("client certificate expired")
	}

	return cm.clientCert, nil
}

// GetCACertPool returns the current CA certificate pool
func (cm *CertificateManager) GetCACertPool() *x509.CertPool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.caCertPool
}

// VerifyPeerCertificate verifies peer certificates using the current CA pool
func (cm *CertificateManager) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no peer certificates provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse peer certificate: %w", err)
	}

	caCertPool := cm.GetCACertPool()
	if caCertPool == nil {
		return fmt.Errorf("no CA certificate pool available")
	}

	opts := x509.VerifyOptions{
		Roots: caCertPool,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("peer certificate verification failed: %w", err)
	}

	return nil
}

// ReloadCertificates manually triggers a certificate reload
func (cm *CertificateManager) ReloadCertificates() error {
	return cm.loadCertificates()
}

// AddReloadCallback adds a callback to be called when certificates are reloaded
func (cm *CertificateManager) AddReloadCallback(callback ReloadCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.reloadCallbacks = append(cm.reloadCallbacks, callback)
}

// CheckExpiry returns the time until the earliest certificate expires
func (cm *CertificateManager) CheckExpiry() (time.Duration, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	now := time.Now()
	var earliestExpiry time.Time

	if !cm.serverCertExpiry.IsZero() {
		earliestExpiry = cm.serverCertExpiry
	}

	if !cm.clientCertExpiry.IsZero() && (earliestExpiry.IsZero() || cm.clientCertExpiry.Before(earliestExpiry)) {
		earliestExpiry = cm.clientCertExpiry
	}

	if earliestExpiry.IsZero() {
		return 0, fmt.Errorf("no certificates loaded")
	}

	return earliestExpiry.Sub(now), nil
}

// GetMetrics returns certificate management metrics
func (cm *CertificateManager) GetMetrics() *CertificateMetrics {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return &CertificateMetrics{
		ReloadCount:        cm.reloadCount,
		ReloadSuccessCount: cm.reloadSuccessCount,
		ReloadFailureCount: cm.reloadFailureCount,
		LastReloadTime:     cm.lastReloadTime,
		LastReloadSuccess:  cm.lastReloadSuccess,
		LastReloadError:    cm.lastReloadError,
	}
}

// loadCertificates loads certificates from files or content
func (cm *CertificateManager) loadCertificates() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var newServerCert *tls.Certificate
	var newClientCert *tls.Certificate
	var newCACertPool *x509.CertPool

	// Load server certificate and key
	if err := cm.loadServerCertificate(&newServerCert); err != nil {
		return err
	}

	// Load CA certificate for mutual TLS
	if err := cm.loadCACertificate(&newCACertPool); err != nil {
		return err
	}

	// Update certificates atomically
	cm.serverCert = newServerCert
	cm.clientCert = newClientCert
	cm.caCertPool = newCACertPool
	cm.lastReloadTime = time.Now()

	// Update metrics and callbacks
	cm.updateReloadMetrics(true, nil)
	cm.callReloadCallbacks(true, nil)

	if cm.logger != nil {
		cm.logger.Info("Certificates reloaded successfully",
			"server_cert_expiry", cm.serverCertExpiry,
			"reload_time", cm.lastReloadTime)
	}

	return nil
}

// loadServerCertificate loads the server certificate and key
func (cm *CertificateManager) loadServerCertificate(newServerCert **tls.Certificate) error {
	if !cm.shouldLoadServerCertificate() {
		return nil
	}

	cert, err := cm.loadCertificatePair()
	if err != nil {
		return err
	}

	if err := cm.parseCertificateExpiry(&cert); err != nil {
		return err
	}

	*newServerCert = &cert
	return nil
}

// shouldLoadServerCertificate checks if server certificate should be loaded
func (cm *CertificateManager) shouldLoadServerCertificate() bool {
	return (cm.config.CertFile != "" && cm.config.KeyFile != "") ||
		(cm.config.CertContent != "" && cm.config.KeyContent != "")
}

// loadCertificatePair loads the certificate and key pair
func (cm *CertificateManager) loadCertificatePair() (tls.Certificate, error) {
	if cm.config.CertContent != "" && cm.config.KeyContent != "" {
		// Load from content (Vault)
		return tls.X509KeyPair([]byte(cm.config.CertContent), []byte(cm.config.KeyContent))
	}
	// Load from files
	return tls.LoadX509KeyPair(cm.config.CertFile, cm.config.KeyFile)
}

// parseCertificateExpiry parses the certificate to extract expiry time
func (cm *CertificateManager) parseCertificateExpiry(cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return nil
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse server certificate: %w", err)
	}
	cm.serverCertExpiry = x509Cert.NotAfter
	return nil
}

// loadCACertificate loads the CA certificate for mutual TLS
func (cm *CertificateManager) loadCACertificate(newCACertPool **x509.CertPool) error {
	if cm.config.Mode != "mutual" {
		return nil
	}

	caCertPool := x509.NewCertPool()
	var caCert []byte
	var err error

	if cm.config.CAContent != "" {
		// Load from content (Vault)
		caCert = []byte(cm.config.CAContent)
	} else if cm.config.CAFile != "" {
		// Load from file
		caCert, err = os.ReadFile(cm.config.CAFile)
		if err != nil {
			return fmt.Errorf("failed to read CA file: %w", err)
		}
	}

	if len(caCert) > 0 {
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return fmt.Errorf("failed to parse CA certificate")
		}
		*newCACertPool = caCertPool
	}

	return nil
}

// updateReloadMetrics updates the internal metrics for certificate reloads
func (cm *CertificateManager) updateReloadMetrics(success bool, err error) {
	cm.reloadCount++
	if success {
		cm.reloadSuccessCount++
		cm.lastReloadSuccess = true
		cm.lastReloadError = ""
	} else {
		cm.reloadFailureCount++
		cm.lastReloadSuccess = false
		if err != nil {
			cm.lastReloadError = err.Error()
		}
	}

	// Record OpenTelemetry metrics
	cm.recordMetrics(success, err)
}

// callReloadCallbacks calls all registered reload callbacks
func (cm *CertificateManager) callReloadCallbacks(success bool, err error) {
	for _, callback := range cm.reloadCallbacks {
		go callback(success, err)
	}
}

// triggerReload is called by watchers to trigger a certificate reload
func (cm *CertificateManager) triggerReload() {
	if cm.logger != nil {
		cm.logger.Info("Certificate reload triggered by file watcher")
	}

	if err := cm.loadCertificates(); err != nil {
		cm.handleReloadError(err)
	}
}

// handleReloadError handles errors that occur during certificate reload
func (cm *CertificateManager) handleReloadError(err error) {
	// Update internal metrics for failure
	cm.mu.Lock()
	cm.reloadCount++
	cm.reloadFailureCount++
	cm.lastReloadSuccess = false
	cm.lastReloadError = err.Error()
	cm.mu.Unlock()

	// Record OpenTelemetry metrics
	cm.recordMetrics(false, err)

	if cm.logger != nil {
		cm.logger.LogError(err, "Failed to reload certificates")
	}

	// Call reload callbacks with error
	cm.mu.RLock()
	callbacks := make([]ReloadCallback, len(cm.reloadCallbacks))
	copy(callbacks, cm.reloadCallbacks)
	cm.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(false, err)
	}
}

// triggerPreemptiveRenewal triggers preemptive certificate renewal
func (cm *CertificateManager) triggerPreemptiveRenewal() {
	if cm.logger != nil {
		cm.logger.Info("Triggering preemptive certificate renewal")
	}

	// For file-based certificates, we just reload from files
	// In a production environment, this might trigger certificate renewal from a CA
	cm.triggerReload()
}

// recordMetrics records certificate metrics to OpenTelemetry
func (cm *CertificateManager) recordMetrics(success bool, err error) {
	if cm.observabilityManager == nil {
		return
	}

	metrics := cm.observabilityManager.GetMetrics()
	if metrics == nil {
		return
	}

	ctx := context.Background()

	// Record reload count
	if success {
		attrs := []attribute.KeyValue{
			attribute.String("status", "success"),
			attribute.String("cert_type", "server"),
		}
		metrics.CertReloadCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	} else {
		errorMsg := ""
		if err != nil {
			errorMsg = err.Error()
		}
		attrs := []attribute.KeyValue{
			attribute.String("status", "failure"),
			attribute.String("cert_type", "server"),
			attribute.String("error", errorMsg),
		}
		metrics.CertReloadCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}

	// Update certificate expiry time gauge
	cm.updateExpiryMetrics()
}

// updateExpiryMetrics updates the certificate expiry time metrics
func (cm *CertificateManager) updateExpiryMetrics() {
	if cm.observabilityManager == nil {
		return
	}

	metrics := cm.observabilityManager.GetMetrics()
	if metrics == nil {
		return
	}

	ctx := context.Background()
	now := time.Now()

	// Update server certificate expiry
	if !cm.serverCertExpiry.IsZero() {
		secondsToExpiry := cm.serverCertExpiry.Sub(now).Seconds()
		attrs := []attribute.KeyValue{
			attribute.String("cert_type", "server"),
		}
		metrics.CertExpiryTime.Record(ctx, secondsToExpiry, metric.WithAttributes(attrs...))
	}

	// Update client certificate expiry if available
	if !cm.clientCertExpiry.IsZero() {
		secondsToExpiry := cm.clientCertExpiry.Sub(now).Seconds()
		attrs := []attribute.KeyValue{
			attribute.String("cert_type", "client"),
		}
		metrics.CertExpiryTime.Record(ctx, secondsToExpiry, metric.WithAttributes(attrs...))
	}
}

// StartExpiryMonitoring starts a goroutine to periodically update certificate expiry metrics
func (cm *CertificateManager) StartExpiryMonitoring() {
	if cm.observabilityManager == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute) // Update every minute
		defer ticker.Stop()

		for range ticker.C {
			cm.mu.RLock()
			cm.updateExpiryMetrics()
			cm.mu.RUnlock()
		}
	}()

	if cm.logger != nil {
		cm.logger.Info("Certificate expiry monitoring started")
	}
}
