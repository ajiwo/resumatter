package server

import (
	"fmt"
	"sync"
	"time"

	"resumatter/internal/config"
	"resumatter/internal/errors"
)

// VaultClientInterface defines the interface for Vault operations
type VaultClientInterface interface {
	GetSecretV2(path string) (*config.VaultSecret, error)
	GetStringSecret(path, key string) (string, error)
	GetStringSliceSecret(path, key string) ([]string, error)
}

// CertificateData holds certificate data fetched from Vault
type CertificateData struct {
	CertContent string
	KeyContent  string
	CAContent   string
}

// VaultReloadCallback is called when new certificate data is available from Vault
type VaultReloadCallback func(data *CertificateData, err error)

// VaultWatcher watches Vault for TLS secret changes and triggers reloads
// It polls the Vault secret at a configured interval and triggers reload if the version changes
// (No lease renewal for now, but can be added)
type VaultWatcher struct {
	mu sync.RWMutex

	client         VaultClientInterface
	secretPath     string
	pollInterval   time.Duration
	reloadCallback VaultReloadCallback
	logger         *errors.Logger

	stopChan    chan struct{}
	reloadChan  chan struct{}
	running     bool
	lastVersion int64
}

// NewVaultWatcher creates a new VaultWatcher
func NewVaultWatcher(client VaultClientInterface, secretPath string, pollInterval time.Duration, reloadCallback VaultReloadCallback, logger *errors.Logger) *VaultWatcher {
	return &VaultWatcher{
		client:         client,
		secretPath:     secretPath,
		pollInterval:   pollInterval,
		reloadCallback: reloadCallback,
		logger:         logger,
		stopChan:       make(chan struct{}),
		reloadChan:     make(chan struct{}, 1),
	}
}

// Start begins polling Vault for secret changes
func (vw *VaultWatcher) Start() error {
	vw.mu.Lock()
	defer vw.mu.Unlock()
	if vw.running {
		return fmt.Errorf("vault watcher is already running")
	}
	vw.running = true
	go vw.pollLoop()
	if vw.logger != nil {
		vw.logger.Info("Vault watcher started", "secret_path", vw.secretPath, "poll_interval", vw.pollInterval)
	}
	return nil
}

// Stop stops the Vault watcher
func (vw *VaultWatcher) Stop() error {
	vw.mu.Lock()
	defer vw.mu.Unlock()
	if !vw.running {
		return nil
	}
	close(vw.stopChan)
	vw.running = false
	if vw.logger != nil {
		vw.logger.Info("Vault watcher stopped")
	}
	return nil
}

// pollLoop polls Vault for secret changes
func (vw *VaultWatcher) pollLoop() {
	ticker := time.NewTicker(vw.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			changed, err := vw.checkForUpdates()
			if err != nil {
				if vw.logger != nil {
					vw.logger.LogError(err, "Failed to check Vault for updates")
				}
				continue
			}
			if changed {
				if vw.logger != nil {
					vw.logger.Info("Vault secret changed, fetching new certificate data...")
				}
				// Fetch new data and pass it to the callback
				newData, err := vw.fetchNewCertsFromVault()
				if err != nil {
					if vw.logger != nil {
						vw.logger.LogError(err, "Failed to fetch new certificate data from Vault")
					}
					vw.reloadCallback(nil, err)
				} else {
					if vw.logger != nil {
						vw.logger.Info("New certificate data fetched from Vault, triggering reload")
					}
					vw.reloadCallback(newData, nil)
				}
			}
		case <-vw.stopChan:
			return
		}
	}
}

// checkForUpdates checks if the Vault secret version has changed
func (vw *VaultWatcher) checkForUpdates() (bool, error) {
	secret, err := vw.client.GetSecretV2(vw.secretPath)
	if err != nil {
		return false, fmt.Errorf("failed to read secret: %w", err)
	}
	if secret.Version > vw.lastVersion {
		vw.lastVersion = secret.Version
		return true, nil
	}
	return false, nil
}

// fetchNewCertsFromVault fetches new certificate data from Vault
func (vw *VaultWatcher) fetchNewCertsFromVault() (*CertificateData, error) {
	secret, err := vw.client.GetSecretV2(vw.secretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch new TLS data from vault: %w", err)
	}

	data := &CertificateData{}
	if certContent, ok := secret.Data["cert"].(string); ok {
		data.CertContent = certContent
	}
	if keyContent, ok := secret.Data["key"].(string); ok {
		data.KeyContent = keyContent
	}
	if caContent, ok := secret.Data["ca"].(string); ok {
		data.CAContent = caContent
	}
	return data, nil
}

// Status returns the current status of the VaultWatcher for health reporting
func (vw *VaultWatcher) Status() map[string]any {
	vw.mu.RLock()
	defer vw.mu.RUnlock()
	status := map[string]any{
		"running":       vw.running,
		"poll_interval": vw.pollInterval.String(),
		"secret_path":   vw.secretPath,
		"last_version":  vw.lastVersion,
	}
	return status
}
