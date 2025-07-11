package config

import (
	"os"
	"path/filepath"
	"testing"

	"resumatter/internal/errors"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockLogger() *errors.Logger {
	// Return a real logger for testing since the interface is complex
	logger, _ := errors.New("debug")
	return logger
}

// Test parseVersionValue function
func TestParseVersionValue(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		path        string
		expected    int64
		expectError bool
	}{
		{
			name:     "int64 value",
			input:    int64(42),
			path:     "test/path",
			expected: 42,
		},
		{
			name:     "float64 value",
			input:    float64(42.0),
			path:     "test/path",
			expected: 42,
		},
		{
			name:     "string value",
			input:    "42",
			path:     "test/path",
			expected: 42,
		},
		{
			name:        "invalid string value",
			input:       "not-a-number",
			path:        "test/path",
			expectError: true,
		},
		{
			name:        "unsupported type",
			input:       []string{"42"},
			path:        "test/path",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseVersionValue(tt.input, tt.path)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// Test applyGeminiKeyToConfig function
func TestApplyGeminiKeyToConfig(t *testing.T) {
	config := &Config{
		AI: AIConfig{
			Tailor:   OperationAIConfig{},
			Evaluate: OperationAIConfig{},
			Analyze:  OperationAIConfig{},
		},
	}

	geminiKey := "test-gemini-key"
	applyGeminiKeyToConfig(config, geminiKey)

	assert.Equal(t, geminiKey, config.AI.APIKey)
	assert.Equal(t, geminiKey, config.AI.Tailor.APIKey)
	assert.Equal(t, geminiKey, config.AI.Evaluate.APIKey)
	assert.Equal(t, geminiKey, config.AI.Analyze.APIKey)
}

func TestApplyGeminiKeyToConfigWithExistingKeys(t *testing.T) {
	existingTailorKey := "existing-tailor-key"
	config := &Config{
		AI: AIConfig{
			Tailor:   OperationAIConfig{APIKey: existingTailorKey},
			Evaluate: OperationAIConfig{},
			Analyze:  OperationAIConfig{},
		},
	}

	geminiKey := "test-gemini-key"
	applyGeminiKeyToConfig(config, geminiKey)

	assert.Equal(t, geminiKey, config.AI.APIKey)
	assert.Equal(t, existingTailorKey, config.AI.Tailor.APIKey) // Should not overwrite existing
	assert.Equal(t, geminiKey, config.AI.Evaluate.APIKey)
	assert.Equal(t, geminiKey, config.AI.Analyze.APIKey)
}

// Test loadSingleCertificate function
func TestLoadSingleCertificate(t *testing.T) {
	logger := newMockLogger()

	tests := []struct {
		name        string
		tlsData     *VaultSecret
		key         string
		description string
		expected    int
		expectValue string
	}{
		{
			name: "valid certificate content",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"cert": "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
				},
			},
			key:         "cert",
			description: "TLS certificate content",
			expected:    1,
			expectValue: "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
		},
		{
			name: "empty certificate content",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"cert": "",
				},
			},
			key:         "cert",
			description: "TLS certificate content",
			expected:    0,
			expectValue: "",
		},
		{
			name: "missing certificate key",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"other": "value",
				},
			},
			key:         "cert",
			description: "TLS certificate content",
			expected:    0,
			expectValue: "",
		},
		{
			name: "non-string certificate value",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"cert": 123,
				},
			},
			key:         "cert",
			description: "TLS certificate content",
			expected:    0,
			expectValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target string
			result := loadSingleCertificate(tt.tlsData, tt.key, &target, tt.description, logger)

			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.expectValue, target)
		})
	}
}

// Test resolveVaultToken function
func TestResolveVaultToken(t *testing.T) {
	logger := newMockLogger()

	t.Run("token from config", func(t *testing.T) {
		config := VaultConfig{
			Token: "direct-token",
		}

		token, err := resolveVaultToken(config, logger)
		assert.NoError(t, err)
		assert.Equal(t, "direct-token", token)
	})

	t.Run("token from file", func(t *testing.T) {
		// Create temporary token file
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "vault-token")
		err := os.WriteFile(tokenFile, []byte("  file-token  \n"), 0600)
		require.NoError(t, err)

		config := VaultConfig{
			TokenFile: tokenFile,
		}

		token, err := resolveVaultToken(config, logger)
		assert.NoError(t, err)
		assert.Equal(t, "file-token", token) // Should be trimmed
	})

	t.Run("missing token file", func(t *testing.T) {
		config := VaultConfig{
			TokenFile: "/nonexistent/token/file",
		}

		_, err := resolveVaultToken(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read vault token file")
	})

	t.Run("no token provided", func(t *testing.T) {
		config := VaultConfig{}

		_, err := resolveVaultToken(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vault token is required")
	})

	t.Run("empty token from file", func(t *testing.T) {
		// Create temporary empty token file
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "empty-token")
		err := os.WriteFile(tokenFile, []byte("   \n  \n"), 0600)
		require.NoError(t, err)

		config := VaultConfig{
			TokenFile: tokenFile,
		}

		_, err = resolveVaultToken(config, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vault token is required")
	})
}

// Test validateTLSDeprecatedFields function
func TestValidateTLSDeprecatedFields(t *testing.T) {
	logger := newMockLogger()

	tests := []struct {
		name        string
		tlsData     *VaultSecret
		expectError bool
		errorField  string
	}{
		{
			name: "no deprecated fields",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"cert": "cert-content",
					"key":  "key-content",
					"ca":   "ca-content",
				},
			},
			expectError: false,
		},
		{
			name: "deprecated cert_file field",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"cert_file": "/path/to/cert",
				},
			},
			expectError: true,
			errorField:  "cert_file",
		},
		{
			name: "deprecated key_file field",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"key_file": "/path/to/key",
				},
			},
			expectError: true,
			errorField:  "key_file",
		},
		{
			name: "deprecated ca_file field",
			tlsData: &VaultSecret{
				Data: map[string]any{
					"ca_file": "/path/to/ca",
				},
			},
			expectError: true,
			errorField:  "ca_file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTLSDeprecatedFields(tt.tlsData, logger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorField)
				assert.Contains(t, err.Error(), "no longer supported")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test loadTLSCertificateContent function
func TestLoadTLSCertificateContent(t *testing.T) {
	logger := newMockLogger()

	config := &Config{
		Server: ServerConfig{
			TLS: TLSConfig{},
		},
	}

	tlsData := &VaultSecret{
		Data: map[string]any{
			"cert": "cert-content",
			"key":  "key-content",
			"ca":   "ca-content",
		},
	}

	certCount := loadTLSCertificateContent(config, tlsData, logger)

	assert.Equal(t, 3, certCount)
	assert.Equal(t, "cert-content", config.Server.TLS.CertContent)
	assert.Equal(t, "key-content", config.Server.TLS.KeyContent)
	assert.Equal(t, "ca-content", config.Server.TLS.CAContent)
}

func TestLoadTLSCertificateContentPartial(t *testing.T) {
	logger := newMockLogger()

	config := &Config{
		Server: ServerConfig{
			TLS: TLSConfig{},
		},
	}

	tlsData := &VaultSecret{
		Data: map[string]any{
			"cert": "cert-content",
			// Missing key and ca
		},
	}

	certCount := loadTLSCertificateContent(config, tlsData, logger)

	assert.Equal(t, 1, certCount)
	assert.Equal(t, "cert-content", config.Server.TLS.CertContent)
	assert.Equal(t, "", config.Server.TLS.KeyContent)
	assert.Equal(t, "", config.Server.TLS.CAContent)
}

// Test ApplyVaultSecrets function with disabled vault
func TestApplyVaultSecretsDisabled(t *testing.T) {
	logger := newMockLogger()

	config := &Config{
		Vault: VaultConfig{
			Enabled: false,
		},
	}

	err := ApplyVaultSecrets(config, logger)
	assert.NoError(t, err)
	// Note: We can't easily test logger calls with the real logger,
	// but we can verify the function returns without error
}

// Test parseInt64 function
func TestParseInt64(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int64
		expectError bool
	}{
		{
			name:     "valid positive number",
			input:    "42",
			expected: 42,
		},
		{
			name:     "valid negative number",
			input:    "-42",
			expected: -42,
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
		},
		{
			name:        "invalid string",
			input:       "not-a-number",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "float string",
			input:       "42.5",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseInt64(tt.input)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// Integration test for VaultClient methods (requires mock setup)
func TestVaultClientExtractSecretData(t *testing.T) {
	logger := newMockLogger()
	vc := &VaultClient{
		logger: logger,
	}

	tests := []struct {
		name        string
		secret      *api.Secret
		path        string
		expectError bool
		expected    map[string]any
	}{
		{
			name: "valid KVv2 secret",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{
						"key1": "value1",
						"key2": "value2",
					},
				},
			},
			path:     "secret/test",
			expected: map[string]any{"key1": "value1", "key2": "value2"},
		},
		{
			name: "missing data field",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{},
				},
			},
			path:        "secret/test",
			expectError: true,
		},
		{
			name: "data field wrong type",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": "not-a-map",
				},
			},
			path:        "secret/test",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.extractSecretData(tt.secret, tt.path)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestVaultClientExtractSecretVersion(t *testing.T) {
	logger := newMockLogger()
	vc := &VaultClient{
		logger: logger,
	}

	tests := []struct {
		name        string
		secret      *api.Secret
		path        string
		expectError bool
		expected    int64
	}{
		{
			name: "valid version as int64",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"version": int64(42),
					},
				},
			},
			path:     "secret/test",
			expected: 42,
		},
		{
			name: "valid version as float64",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"version": float64(42),
					},
				},
			},
			path:     "secret/test",
			expected: 42,
		},
		{
			name: "missing metadata field",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"data": map[string]interface{}{},
				},
			},
			path:        "secret/test",
			expectError: true,
		},
		{
			name: "missing version field",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"metadata": map[string]interface{}{
						"other": "value",
					},
				},
			},
			path:        "secret/test",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := vc.extractSecretVersion(tt.secret, tt.path)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
