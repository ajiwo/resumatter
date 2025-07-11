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

	client, err := createVaultAPIClient(config, logger)
	if err != nil {
		return nil, err
	}

	token, err := resolveVaultToken(config, logger)
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	if logger != nil {
		logger.Debug("Vault token configured", "token_prefix", token[:min(len(token), 8)]+"...")
	}

	if err := testVaultConnection(client, config.Address, logger); err != nil {
		return nil, err
	}

	return &VaultClient{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// createVaultAPIClient creates and configures the Vault API client
func createVaultAPIClient(config VaultConfig, logger *errors.Logger) (*api.Client, error) {
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

	return client, nil
}

// resolveVaultToken resolves the Vault token from config or file
func resolveVaultToken(config VaultConfig, logger *errors.Logger) (string, error) {
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
			return "", fmt.Errorf("failed to read vault token file: %w", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}

	if token == "" {
		if logger != nil {
			logger.LogError(fmt.Errorf("vault token is required"), "Vault token is required when Vault is enabled")
		}
		return "", fmt.Errorf("vault token is required when vault is enabled")
	}

	return token, nil
}

// testVaultConnection tests the connection to Vault
func testVaultConnection(client *api.Client, address string, logger *errors.Logger) error {
	if logger != nil {
		logger.Debug("Testing Vault connection", "address", address)
	}

	health, err := client.Sys().Health()
	if err != nil {
		if logger != nil {
			logger.LogError(err, "Failed to connect to Vault", "address", address)
		}
		return fmt.Errorf("failed to connect to vault: %w", err)
	}

	if logger != nil {
		logger.Info("Successfully connected to Vault",
			"address", address,
			"version", health.Version,
			"sealed", health.Sealed,
			"cluster_name", health.ClusterName)
	}

	return nil
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

	secret, err := vc.readSecretFromVault(path)
	if err != nil {
		return nil, err
	}

	data, err := vc.extractSecretData(secret, path)
	if err != nil {
		return nil, err
	}

	version, err := vc.extractSecretVersion(secret, path)
	if err != nil {
		return nil, err
	}

	return &VaultSecret{
		Data:    data,
		Version: version,
	}, nil
}

// readSecretFromVault reads the raw secret from Vault
func (vc *VaultClient) readSecretFromVault(path string) (*api.Secret, error) {
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

	return secret, nil
}

// extractSecretData extracts the data field from a KVv2 secret
func (vc *VaultClient) extractSecretData(secret *api.Secret, path string) (map[string]any, error) {
	data, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("secret at %s is not in KVv2 format (missing 'data' field)", path)
	}
	return data, nil
}

// extractSecretVersion extracts and parses the version from a KVv2 secret
func (vc *VaultClient) extractSecretVersion(secret *api.Secret, path string) (int64, error) {
	metadata, ok := secret.Data["metadata"].(map[string]any)
	if !ok {
		return 0, fmt.Errorf("secret at %s is not in KVv2 format (missing 'metadata' field)", path)
	}

	versionRaw, ok := metadata["version"]
	if !ok {
		return 0, fmt.Errorf("secret metadata at %s is missing 'version' field", path)
	}

	return parseVersionValue(versionRaw, path)
}

// parseVersionValue parses version value from various types
func parseVersionValue(versionRaw any, path string) (int64, error) {
	switch v := versionRaw.(type) {
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	case string:
		version, err := parseInt64(v)
		if err != nil {
			return 0, fmt.Errorf("could not parse secret version at %s: %w", path, err)
		}
		return version, nil
	default:
		return 0, fmt.Errorf("unexpected type for version at %s: %T", path, versionRaw)
	}
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
	if !config.Vault.Enabled {
		if logger != nil {
			logger.Debug("Vault integration disabled, skipping secret loading")
		}
		return nil // Vault not enabled, skip
	}

	client, err := initializeVaultClient(config.Vault, logger)
	if err != nil {
		return err
	}
	if client == nil {
		return nil // Not an error, just disabled
	}

	return loadAllSecretsFromVault(client, config, logger)
}

// initializeVaultClient initializes the Vault client with proper logging
func initializeVaultClient(vaultConfig VaultConfig, logger *errors.Logger) (*VaultClient, error) {
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
		return nil, fmt.Errorf("failed to initialize vault client: %w", err)
	}

	return client, nil
}

// loadAllSecretsFromVault loads all configured secrets from Vault
func loadAllSecretsFromVault(client *VaultClient, config *Config, logger *errors.Logger) error {
	vaultConfig := config.Vault

	// Load each type of secret
	if err := loadAPIKeysFromVault(client, config, vaultConfig, logger); err != nil {
		return err
	}

	if err := loadGeminiKeyFromVault(client, config, vaultConfig, logger); err != nil {
		return err
	}

	if err := loadTLSCertsFromVault(client, config, vaultConfig, logger); err != nil {
		return err
	}

	if logger != nil {
		logger.Info("Successfully completed applying secrets from Vault")
	}

	return nil
}

// loadAPIKeysFromVault loads API keys from Vault
func loadAPIKeysFromVault(client *VaultClient, config *Config, vaultConfig VaultConfig, logger *errors.Logger) error {
	if vaultConfig.Secrets.APIKeys == "" {
		return nil
	}

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

	return nil
}

// loadGeminiKeyFromVault loads Gemini API key from Vault
func loadGeminiKeyFromVault(client *VaultClient, config *Config, vaultConfig VaultConfig, logger *errors.Logger) error {
	if vaultConfig.Secrets.GeminiKey == "" {
		return nil
	}

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
		applyGeminiKeyToConfig(config, geminiKey)
		if logger != nil {
			logger.Info("Gemini API key loaded from Vault and applied to all AI configurations")
		}
	} else {
		if logger != nil {
			logger.Warn("Empty Gemini API key found in Vault", "path", vaultConfig.Secrets.GeminiKey)
		}
	}

	return nil
}

// applyGeminiKeyToConfig applies the Gemini API key to all AI configurations
func applyGeminiKeyToConfig(config *Config, geminiKey string) {
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
}

// loadTLSCertsFromVault loads TLS certificates from Vault
func loadTLSCertsFromVault(client *VaultClient, config *Config, vaultConfig VaultConfig, logger *errors.Logger) error {
	if vaultConfig.Secrets.TLSCerts == "" {
		return nil
	}

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

	certCount := loadTLSCertificateContent(config, tlsData, logger)

	if err := validateTLSDeprecatedFields(tlsData, logger); err != nil {
		return err
	}

	if logger != nil {
		logger.Info("TLS certificates loaded from Vault", "certificates_loaded", certCount)
	}

	return nil
}

// loadTLSCertificateContent loads certificate content from Vault data
func loadTLSCertificateContent(config *Config, tlsData *VaultSecret, logger *errors.Logger) int {
	certCount := 0

	certCount += loadSingleCertificate(tlsData, "cert", &config.Server.TLS.CertContent, "TLS certificate content", logger)
	certCount += loadSingleCertificate(tlsData, "key", &config.Server.TLS.KeyContent, "TLS private key content", logger)
	certCount += loadSingleCertificate(tlsData, "ca", &config.Server.TLS.CAContent, "TLS CA certificate content", logger)

	return certCount
}

// loadSingleCertificate loads a single certificate field from Vault data
func loadSingleCertificate(tlsData *VaultSecret, key string, target *string, description string, logger *errors.Logger) int {
	if content, ok := tlsData.Data[key].(string); ok && content != "" {
		*target = content
		if logger != nil {
			logger.Debug(description+" loaded from Vault", "content_length", len(content))
		}
		return 1
	}
	return 0
}

// validateTLSDeprecatedFields checks for deprecated TLS field usage
func validateTLSDeprecatedFields(tlsData *VaultSecret, logger *errors.Logger) error {
	deprecatedFields := map[string]string{
		"cert_file": "cert_file field is no longer supported in Vault. Use 'cert' field with certificate content instead.",
		"key_file":  "key_file field is no longer supported in Vault. Use 'key' field with private key content instead.",
		"ca_file":   "ca_file field is no longer supported in Vault. Use 'ca' field with CA certificate content instead.",
	}

	for field, message := range deprecatedFields {
		if _, hasField := tlsData.Data[field]; hasField {
			if logger != nil {
				logger.LogError(fmt.Errorf("deprecated field detected"), message)
			}
			return fmt.Errorf("vault TLS configuration error: '%s' field is no longer supported. Store certificate content in '%s' field instead",
				field, strings.TrimSuffix(field, "_file"))
		}
	}

	return nil
}
