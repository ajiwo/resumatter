package config

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// applyFallbacks applies environment variable fallbacks
func (c *Config) applyFallbacks() {
	// Note: API key fallbacks are now handled in Get...Config() methods to avoid duplication

	c.applyServerAPIKeyFallbacks()
	c.applyTLSDefaults()
	c.applyObservabilityDefaults()
}

// applyServerAPIKeyFallbacks applies API key fallbacks from environment variables
func (c *Config) applyServerAPIKeyFallbacks() {
	if len(c.Server.APIKeys) == 0 {
		if apiKeysEnv := os.Getenv("RESUMATTER_SERVER_APIKEYS"); apiKeysEnv != "" {
			c.Server.APIKeys = strings.Split(apiKeysEnv, ",")
			// Trim whitespace from each key
			for i, key := range c.Server.APIKeys {
				c.Server.APIKeys[i] = strings.TrimSpace(key)
			}
		}
	}
}

// applyTLSDefaults applies default TLS configuration values
func (c *Config) applyTLSDefaults() {
	// Set default client auth policy for mutual TLS if not specified
	if c.Server.TLS.Mode == "mutual" && c.Server.TLS.ClientAuthPolicy == "" {
		c.Server.TLS.ClientAuthPolicy = "require"
	}

	// Set default TLS version if not specified
	if c.Server.TLS.MinVersion == "" && c.Server.TLS.Mode != "disabled" {
		c.Server.TLS.MinVersion = "1.2"
	}
}

// applyObservabilityDefaults applies default observability configuration values
func (c *Config) applyObservabilityDefaults() {
	if c.Observability.ServiceInstance == "" {
		c.Observability.ServiceInstance = generateServiceInstanceID(c.Observability.ServiceName)
	}
}

// generateServiceInstanceID generates a unique service instance ID
func generateServiceInstanceID(serviceName string) string {
	// Try to get hostname, fallback to default
	if hostname, err := os.Hostname(); err == nil {
		return fmt.Sprintf("%s-%s", serviceName, hostname)
	}
	return fmt.Sprintf("%s-1", serviceName)
}

// logConfigurationSources logs a summary of configuration sources being used
func (c *Config) logConfigurationSources(configFileUsed string) {
	log.Println("[CONFIG] === Configuration Sources Summary ===")

	// Log config file source
	if configFileUsed != "" {
		log.Printf("[CONFIG] Config file: %s", configFileUsed)
	} else {
		log.Println("[CONFIG] Config file: None (using defaults)")
	}

	// Log environment variables that are set
	envVars := []string{
		"RESUMATTER_AI_APIKEY",
		"RESUMATTER_AI_PROVIDER",
		"RESUMATTER_AI_MODEL",
		"RESUMATTER_SERVER_PORT",
		"RESUMATTER_SERVER_HOST",
		"RESUMATTER_APP_LOGLEVEL",
		"RESUMATTER_VAULT_ENABLED",
		"GEMINI_API_KEY", // Legacy support
	}

	log.Println("[CONFIG] Environment variables:")
	hasEnvVars := false
	for _, envVar := range envVars {
		if value := os.Getenv(envVar); value != "" {
			// Mask sensitive values
			if strings.Contains(strings.ToLower(envVar), "apikey") || strings.Contains(strings.ToLower(envVar), "key") {
				log.Printf("[CONFIG]   %s=***MASKED***", envVar)
			} else {
				log.Printf("[CONFIG]   %s=%s", envVar, value)
			}
			hasEnvVars = true
		}
	}
	if !hasEnvVars {
		log.Println("[CONFIG]   None set")
	}

	// Log key configuration values (with sensitive data masked)
	log.Println("[CONFIG] === Key Configuration Values ===")
	log.Printf("[CONFIG] AI Provider: %s", c.AI.Provider)
	log.Printf("[CONFIG] AI Model: %s", c.AI.Model)
	if c.AI.APIKey != "" {
		log.Println("[CONFIG] AI API Key: ***CONFIGURED***")
	} else {
		log.Println("[CONFIG] AI API Key: ***NOT SET***")
	}
	log.Printf("[CONFIG] Server Host: %s", c.Server.Host)
	log.Printf("[CONFIG] Server Port: %s", c.Server.Port)
	log.Printf("[CONFIG] Log Level: %s", c.App.LogLevel)
	log.Printf("[CONFIG] TLS Mode: %s", c.Server.TLS.Mode)
	log.Printf("[CONFIG] Vault Enabled: %t", c.Vault.Enabled)
	log.Printf("[CONFIG] Observability Enabled: %t", c.Observability.Enabled)

	// Log operation-specific configurations
	log.Println("[CONFIG] === Operation-Specific AI Configurations ===")
	log.Printf("[CONFIG] Tailor - Provider: %s, Model: %s", c.AI.Tailor.Provider, c.AI.Tailor.Model)
	log.Printf("[CONFIG] Evaluate - Provider: %s, Model: %s", c.AI.Evaluate.Provider, c.AI.Evaluate.Model)
	log.Printf("[CONFIG] Analyze - Provider: %s, Model: %s", c.AI.Analyze.Provider, c.AI.Analyze.Model)

	log.Println("[CONFIG] =====================================")
}