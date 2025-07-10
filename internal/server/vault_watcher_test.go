package server

import (
	"testing"
	"time"

	"resumatter/internal/config"
)

// MockVaultClient is a mock implementation for testing
type MockVaultClient struct {
	secrets map[string]*config.VaultSecret
}

func (m *MockVaultClient) GetSecretV2(path string) (*config.VaultSecret, error) {
	if secret, exists := m.secrets[path]; exists {
		return secret, nil
	}
	return nil, nil
}

func (m *MockVaultClient) GetStringSecret(path, key string) (string, error) {
	if secret, exists := m.secrets[path]; exists {
		if value, ok := secret.Data[key].(string); ok {
			return value, nil
		}
	}
	return "", nil
}

func (m *MockVaultClient) GetStringSliceSecret(path, key string) ([]string, error) {
	if secret, exists := m.secrets[path]; exists {
		if value, ok := secret.Data[key].([]string); ok {
			return value, nil
		}
	}
	return nil, nil
}

func TestVaultWatcherFetchNewCertsFromVault(t *testing.T) {
	// Create mock Vault client with test data
	mockClient := &MockVaultClient{
		secrets: map[string]*config.VaultSecret{
			"secret/data/test": {
				Data: map[string]any{
					"cert": "new-cert-content",
					"key":  "new-key-content",
					"ca":   "new-ca-content",
				},
				Version: 1,
			},
		},
	}

	// Create VaultWatcher with interface type
	vw := &VaultWatcher{
		client:         mockClient,
		secretPath:     "secret/data/test",
		pollInterval:   1 * time.Minute,
		reloadCallback: func(data *CertificateData, err error) {}, // Empty callback for testing
		logger:         nil,
		stopChan:       make(chan struct{}),
		reloadChan:     make(chan struct{}, 1),
	}

	// Test fetchNewCertsFromVault
	data, err := vw.fetchNewCertsFromVault()
	if err != nil {
		t.Fatalf("fetchNewCertsFromVault failed: %v", err)
	}

	// Verify that the certificate data was fetched correctly
	if data.CertContent != "new-cert-content" {
		t.Errorf("CertContent not fetched correctly, got: %s, want: %s",
			data.CertContent, "new-cert-content")
	}
	if data.KeyContent != "new-key-content" {
		t.Errorf("KeyContent not fetched correctly, got: %s, want: %s",
			data.KeyContent, "new-key-content")
	}
	if data.CAContent != "new-ca-content" {
		t.Errorf("CAContent not fetched correctly, got: %s, want: %s",
			data.CAContent, "new-ca-content")
	}
}

func TestVaultWatcherCheckForUpdates(t *testing.T) {
	// Create mock Vault client with version metadata
	mockClient := &MockVaultClient{
		secrets: map[string]*config.VaultSecret{
			"secret/data/test": {
				Data: map[string]any{
					// no certs needed for this test
				},
				Version: 2,
			},
		},
	}

	// Create VaultWatcher with interface type
	vw := &VaultWatcher{
		client:         mockClient,
		secretPath:     "secret/data/test",
		pollInterval:   1 * time.Minute,
		reloadCallback: func(data *CertificateData, err error) {}, // Empty callback for testing
		logger:         nil,
		stopChan:       make(chan struct{}),
		reloadChan:     make(chan struct{}, 1),
	}

	// Test initial check (should detect change from version 0 to 2)
	changed, err := vw.checkForUpdates()
	if err != nil {
		t.Fatalf("checkForUpdates failed: %v", err)
	}
	if !changed {
		t.Error("Expected change to be detected")
	}

	// Test subsequent check (should not detect change since version is still 2)
	changed, err = vw.checkForUpdates()
	if err != nil {
		t.Fatalf("checkForUpdates failed: %v", err)
	}
	if changed {
		t.Error("Expected no change to be detected")
	}
}
