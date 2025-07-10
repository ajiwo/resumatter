package config

import (
	"fmt"
	"os"
	"strings"

	"resumatter/internal/errors"

	"strconv"

	"github.com/hashicorp/vault/api"
)

// VaultConfig holds Vault connection configuration
type VaultConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Address   string `mapstructure:"address"`
	Token     string `mapstructure:"token"`
	TokenFile string `mapstructure:"tokenFile"`
	Namespace string `mapstructure:"namespace"`

	// Secret paths
	Secrets VaultSecrets `mapstructure:"secrets"`
}

// VaultSecrets defines where to find secrets in Vault
type VaultSecrets struct {
	// APIKeys expects a single string with comma-separated values in Vault
	// Example format: "key1,key2,key3"
	// The first key will be used as the primary key, others as fallbacks
	APIKeys   string `mapstructure:"apiKeys"`   // Path to API keys secret
	GeminiKey string `mapstructure:"geminiKey"` // Path to Gemini API key
	TLSCerts  string `mapstructure:"tlsCerts"`  // Path to TLS certificates
}

// VaultClient wraps the Vault API client
type VaultClient struct {
	client *api.Client
	config VaultConfig
	logger *errors.Logger // Add logger field
}

// NewVaultClient creates a new Vault client from configuration
func NewVaultClient(config VaultConfig, logger *errors.Logger) (*VaultClient, error) {
	if !config.Enabled {
		if logger != nil {
			logger.Debug("Vault integration disabled")
		}
		return nil, nil
	}

	if logger != nil {
		logger.Debug("Initializing Vault client",
			"address", config.Address,
			"namespace", config.Namespace,
			"token_file", config.TokenFile,
			"has_token", config.Token != "")
	}

	// Create Vault client configuration
	vaultConfig := api.DefaultConfig()
	if config.Address != "" {
		vaultConfig.Address = config.Address
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		if logger != nil {
			logger.LogError(err, "Failed to create Vault client")
		}
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Set namespace if provided
	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
		if logger != nil {
			logger.Debug("Set Vault namespace", "namespace", config.Namespace)
		}
	}

	// Set token
	token := config.Token
	if token == "" && config.TokenFile != "" {
		if logger != nil {
			logger.Debug("Reading Vault token from file", "file", config.TokenFile)
		}
		tokenBytes, err := os.ReadFile(config.TokenFile)
		if err != nil {
			if logger != nil {
				logger.LogError(err, "Failed to read Vault token file", "file", config.TokenFile)
			}
			return nil, fmt.Errorf("failed to read vault token file: %w", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}

	if token == "" {
		if logger != nil {
			logger.LogError(fmt.Errorf("vault token is required"), "Vault token is required when Vault is enabled")
		}
		return nil, fmt.Errorf("vault token is required when vault is enabled")
	}

	client.SetToken(token)
	if logger != nil {
		logger.Debug("Vault token configured", "token_prefix", token[:min(len(token), 8)]+"...")
	}

	// Test connection
	if logger != nil {
		logger.Debug("Testing Vault connection", "address", vaultConfig.Address)
	}
	health, err := client.Sys().Health()
	if err != nil {
		if logger != nil {
			logger.LogError(err, "Failed to connect to Vault", "address", vaultConfig.Address)
		}
		return nil, fmt.Errorf("failed to connect to vault: %w", err)
	}

	if logger != nil {
		logger.Info("Successfully connected to Vault",
			"address", vaultConfig.Address,
			"version", health.Version,
			"sealed", health.Sealed,
			"cluster_name", health.ClusterName)
	}

	return &VaultClient{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// VaultSecret represents a secret read from Vault's KVv2 engine.
type VaultSecret struct {
	Data    map[string]any
	Version int64
}

// GetSecretV2 retrieves a secret from a Vault KVv2 store.
func (vc *VaultClient) GetSecretV2(path string) (*VaultSecret, error) {
	if vc == nil {
		return nil, fmt.Errorf("vault client not initialized")
	}

	if vc.logger != nil {
		vc.logger.Debug("Reading secret from Vault", "path", path)
	}

	secret, err := vc.client.Logical().Read(path)
	if err != nil {
		if vc.logger != nil {
			vc.logger.LogError(err, "Failed to read secret from Vault", "path", path)
		}
		return nil, fmt.Errorf("failed to read secret from %s: %w", path, err)
	}

	if secret == nil || secret.Data == nil {
		if vc.logger != nil {
			vc.logger.Warn("Secret not found at path", "path", path)
		}
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	data, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("secret at %s is not in KVv2 format (missing 'data' field)", path)
	}

	metadata, ok := secret.Data["metadata"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("secret at %s is not in KVv2 format (missing 'metadata' field)", path)
	}

	versionRaw, ok := metadata["version"]
	if !ok {
		return nil, fmt.Errorf("secret metadata at %s is missing 'version' field", path)
	}

	var version int64
	switch v := versionRaw.(type) {
	case int64:
		version = v
	case float64:
		version = int64(v)
	case string:
		var err error
		version, err = parseInt64(v)
		if err != nil {
			return nil, fmt.Errorf("could not parse secret version at %s: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("unexpected type for version at %s: %T", path, versionRaw)
	}

	return &VaultSecret{
		Data:    data,
		Version: version,
	}, nil
}

func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// GetStringSecret retrieves a string value from a Vault secret
func (vc *VaultClient) GetStringSecret(path, key string) (string, error) {
	secret, err := vc.GetSecretV2(path)
	if err != nil {
		return "", err
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key '%s' not found in secret %s", key, path)
	}
	strValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("value for key '%s' is not a string in secret %s", key, path)
	}

	if vc.logger != nil {
		maskedValue := strValue
		if len(strValue) > 8 {
			// A common practice for API keys
			maskedValue = strValue[:4] + "****" + strValue[len(strValue)-4:]
		} else if len(strValue) > 0 {
			maskedValue = "****"
		}
		vc.logger.Debug("String secret retrieved from Vault",
			"path", path,
			"key", key,
			"masked_value", maskedValue)
	}

	return strValue, nil
}

// GetStringSliceSecret retrieves a comma-separated string as a slice from Vault
func (vc *VaultClient) GetStringSliceSecret(path, key string) ([]string, error) {
	value, err := vc.GetStringSecret(path, key)
	if err != nil {
		return nil, err
	}
	if value == "" {
		return []string{}, nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, len(parts))
	for i, part := range parts {
		result[i] = strings.TrimSpace(part)
	}
	return result, nil
}

// ApplyVaultSecrets loads secrets from Vault and applies them to the config
func ApplyVaultSecrets(config *Config, logger *errors.Logger) error {
	vaultConfig := config.Vault
	if !vaultConfig.Enabled {
		if logger != nil {
			logger.Debug("Vault integration disabled, skipping secret loading")
		}
		return nil // Vault not enabled, skip
	}

	if logger != nil {
		logger.Info("Loading secrets from Vault",
			"api_keys_path", vaultConfig.Secrets.APIKeys,
			"gemini_key_path", vaultConfig.Secrets.GeminiKey,
			"tls_certs_path", vaultConfig.Secrets.TLSCerts)
	}

	client, err := NewVaultClient(vaultConfig, logger)
	if err != nil {
		if logger != nil {
			logger.LogError(err, "Failed to initialize Vault client")
		}
		return fmt.Errorf("failed to initialize vault client: %w", err)
	}
	if client == nil {
		return nil // Not an error, just disabled
	}

	// Load API keys if path is configured
	if vaultConfig.Secrets.APIKeys != "" {
		if logger != nil {
			logger.Debug("Loading API keys from Vault", "path", vaultConfig.Secrets.APIKeys)
		}
		apiKeys, err := client.GetStringSliceSecret(vaultConfig.Secrets.APIKeys, "keys")
		if err != nil {
			if logger != nil {
				logger.LogError(err, "Failed to load API keys from Vault", "path", vaultConfig.Secrets.APIKeys)
			}
			return fmt.Errorf("failed to load API keys from vault: %w", err)
		}
		if len(apiKeys) > 0 {
			config.Server.APIKeys = apiKeys
			if logger != nil {
				logger.Info("API keys loaded from Vault", "count", len(apiKeys))
			}
		} else {
			if logger != nil {
				logger.Warn("No API keys found in Vault", "path", vaultConfig.Secrets.APIKeys)
			}
		}
	}

	// Load Gemini API key if path is configured
	if vaultConfig.Secrets.GeminiKey != "" {
		if logger != nil {
			logger.Debug("Loading Gemini API key from Vault", "path", vaultConfig.Secrets.GeminiKey)
		}
		geminiKey, err := client.GetStringSecret(vaultConfig.Secrets.GeminiKey, "api_key")
		if err != nil {
			if logger != nil {
				logger.LogError(err, "Failed to load Gemini API key from Vault", "path", vaultConfig.Secrets.GeminiKey)
			}
			return fmt.Errorf("failed to load Gemini API key from vault: %w", err)
		}
		if geminiKey != "" {
			// Apply to global and operation-specific configs
			config.AI.APIKey = geminiKey
			if config.AI.Tailor.APIKey == "" {
				config.AI.Tailor.APIKey = geminiKey
			}
			if config.AI.Evaluate.APIKey == "" {
				config.AI.Evaluate.APIKey = geminiKey
			}
			if config.AI.Analyze.APIKey == "" {
				config.AI.Analyze.APIKey = geminiKey
			}
			if logger != nil {
				logger.Info("Gemini API key loaded from Vault and applied to all AI configurations")
			}
		} else {
			if logger != nil {
				logger.Warn("Empty Gemini API key found in Vault", "path", vaultConfig.Secrets.GeminiKey)
			}
		}
	}

	// Load TLS certificates if path is configured
	if vaultConfig.Secrets.TLSCerts != "" {
		if logger != nil {
			logger.Debug("Loading TLS certificates from Vault", "path", vaultConfig.Secrets.TLSCerts)
		}
		tlsData, err := client.GetSecretV2(vaultConfig.Secrets.TLSCerts)
		if err != nil {
			if logger != nil {
				logger.LogError(err, "Failed to load TLS certificates from Vault", "path", vaultConfig.Secrets.TLSCerts)
			}
			return fmt.Errorf("failed to load TLS certificates from vault: %w", err)
		}

		certCount := 0

		// Load certificate content from Vault (only secure approach supported)
		if certContent, ok := tlsData.Data["cert"].(string); ok && certContent != "" {
			config.Server.TLS.CertContent = certContent
			certCount++
			if logger != nil {
				logger.Debug("TLS certificate content loaded from Vault", "content_length", len(certContent))
			}
		}

		if keyContent, ok := tlsData.Data["key"].(string); ok && keyContent != "" {
			config.Server.TLS.KeyContent = keyContent
			certCount++
			if logger != nil {
				logger.Debug("TLS private key content loaded from Vault", "content_length", len(keyContent))
			}
		}

		if caContent, ok := tlsData.Data["ca"].(string); ok && caContent != "" {
			config.Server.TLS.CAContent = caContent
			certCount++
			if logger != nil {
				logger.Debug("TLS CA certificate content loaded from Vault", "content_length", len(caContent))
			}
		}

		// Check for deprecated file path fields and provide clear error
		if _, hasOldCert := tlsData.Data["cert_file"]; hasOldCert {
			if logger != nil {
				logger.LogError(fmt.Errorf("deprecated field detected"), "cert_file field is no longer supported in Vault. Use 'cert' field with certificate content instead.")
			}
			return fmt.Errorf("vault TLS configuration error: 'cert_file' field is no longer supported. Store certificate content in 'cert' field instead")
		}
		if _, hasOldKey := tlsData.Data["key_file"]; hasOldKey {
			if logger != nil {
				logger.LogError(fmt.Errorf("deprecated field detected"), "key_file field is no longer supported in Vault. Use 'key' field with private key content instead.")
			}
			return fmt.Errorf("vault TLS configuration error: 'key_file' field is no longer supported. Store private key content in 'key' field instead")
		}
		if _, hasOldCA := tlsData.Data["ca_file"]; hasOldCA {
			if logger != nil {
				logger.LogError(fmt.Errorf("deprecated field detected"), "ca_file field is no longer supported in Vault. Use 'ca' field with CA certificate content instead.")
			}
			return fmt.Errorf("vault TLS configuration error: 'ca_file' field is no longer supported. Store CA certificate content in 'ca' field instead")
		}

		if logger != nil {
			logger.Info("TLS certificates loaded from Vault", "certificates_loaded", certCount)
		}
	}

	if logger != nil {
		logger.Info("Successfully completed applying secrets from Vault")
	}

	return nil
}
