package config

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all application configuration
// API Key Precedence Order:
// 1. Vault (if configured) - Highest priority
// 2. Config File values
// 3. Environment Variables (RESUMATTER_AI_APIKEY, etc.)
// 4. Default values - Lowest priority
type Config struct {
	AI            AIConfig            `mapstructure:"ai"`
	Server        ServerConfig        `mapstructure:"server"`
	App           AppConfig           `mapstructure:"app"`
	Vault         VaultConfig         `mapstructure:"vault"`
	Observability ObservabilityConfig `mapstructure:"observability"`
}

// AIConfig holds AI service configuration
type AIConfig struct {
	// Global/fallback configuration (for backward compatibility)
	Provider         string        `mapstructure:"provider"`
	Model            string        `mapstructure:"model"`
	Timeout          time.Duration `mapstructure:"timeout"`
	APIKey           string        `mapstructure:"apiKey"`
	MaxRetries       int           `mapstructure:"maxRetries"`
	Temperature      float32       `mapstructure:"temperature"`
	UseSystemPrompts bool          `mapstructure:"useSystemPrompts"`
	CustomPrompts    PromptConfig  `mapstructure:"customPrompts"`

	// Operation-specific configurations
	Tailor   OperationAIConfig `mapstructure:"tailor"`
	Evaluate OperationAIConfig `mapstructure:"evaluate"`
	Analyze  OperationAIConfig `mapstructure:"analyze"`
}

// CircuitBreakerConfig represents circuit breaker configuration
type CircuitBreakerConfig struct {
	Enabled          bool          `mapstructure:"enabled"`          // Whether circuit breaker is enabled
	MaxRequests      uint32        `mapstructure:"maxRequests"`      // Max requests allowed when half-open
	Interval         time.Duration `mapstructure:"interval"`         // Interval to clear counts
	Timeout          time.Duration `mapstructure:"timeout"`          // Timeout for half-open to open
	MinRequests      uint32        `mapstructure:"minRequests"`      // Minimum requests before tripping
	FailureThreshold float64       `mapstructure:"failureThreshold"` // Failure ratio threshold (0.0-1.0)
}

// OperationAIConfig holds AI configuration for specific operations
type OperationAIConfig struct {
	Provider         string               `mapstructure:"provider"`
	Model            string               `mapstructure:"model"`
	Timeout          *time.Duration       `mapstructure:"timeout"`
	APIKey           string               `mapstructure:"apiKey"`
	MaxRetries       *int                 `mapstructure:"maxRetries"`
	Temperature      *float32             `mapstructure:"temperature"`
	UseSystemPrompts *bool                `mapstructure:"useSystemPrompts"`
	CustomPrompts    PromptConfig         `mapstructure:"customPrompts"`
	CircuitBreaker   CircuitBreakerConfig `mapstructure:"circuitBreaker"`
}

// PromptConfig holds configuration for customizable prompts
type PromptConfig struct {
	SystemPrompts SystemPrompts `mapstructure:"systemPrompts"`
	UserPrompts   UserPrompts   `mapstructure:"userPrompts"`
}

// SystemPrompts contains system-level instructions
type SystemPrompts struct {
	TailorResume       string `mapstructure:"tailorResume"`
	TailorResumeFile   string `mapstructure:"tailorResumeFile"`
	EvaluateResume     string `mapstructure:"evaluateResume"`
	EvaluateResumeFile string `mapstructure:"evaluateResumeFile"`
	AnalyzeJob         string `mapstructure:"analyzeJob"`
	AnalyzeJobFile     string `mapstructure:"analyzeJobFile"`
}

// UserPrompts contains user-level prompt templates
type UserPrompts struct {
	TailorResume       string `mapstructure:"tailorResume"`
	TailorResumeFile   string `mapstructure:"tailorResumeFile"`
	EvaluateResume     string `mapstructure:"evaluateResume"`
	EvaluateResumeFile string `mapstructure:"evaluateResumeFile"`
	AnalyzeJob         string `mapstructure:"analyzeJob"`
	AnalyzeJobFile     string `mapstructure:"analyzeJobFile"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         string        `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"readTimeout"`
	WriteTimeout time.Duration `mapstructure:"writeTimeout"`
	IdleTimeout  time.Duration `mapstructure:"idleTimeout"`

	// TLS Configuration
	TLS TLSConfig `mapstructure:"tls"`

	// API Authentication
	APIKeys []string `mapstructure:"apiKeys"` // Valid API keys for authentication

	// Rate Limiting Configuration
	RateLimit RateLimitConfig `mapstructure:"rateLimit"`
}

// TLSConfig holds TLS/mTLS configuration
type TLSConfig struct {
	Mode     string `mapstructure:"mode"`     // TLS mode: "disabled", "server", "mutual"
	CertFile string `mapstructure:"certFile"` // Server certificate file (PEM)
	KeyFile  string `mapstructure:"keyFile"`  // Server private key file (PEM)
	CAFile   string `mapstructure:"caFile"`   // CA certificate file for client cert verification (PEM, required for mutual mode)

	// Certificate content (used when loaded from Vault instead of files)
	CertContent string `mapstructure:"certContent"` // Server certificate content (PEM)
	KeyContent  string `mapstructure:"keyContent"`  // Server private key content (PEM)
	CAContent   string `mapstructure:"caContent"`   // CA certificate content (PEM)

	// Advanced TLS options
	MinVersion       string   `mapstructure:"minVersion"`       // Minimum TLS version: "1.2", "1.3"
	CipherSuites     []string `mapstructure:"cipherSuites"`     // Allowed cipher suites (optional)
	ClientAuthPolicy string   `mapstructure:"clientAuthPolicy"` // Client auth policy for mutual mode: "require", "request", "verify"

	// Certificate validation options
	InsecureSkipVerify bool   `mapstructure:"insecureSkipVerify"` // Skip certificate verification (dev only)
	ServerName         string `mapstructure:"serverName"`         // Expected server name for client connections

	// Auto-reload configuration
	AutoReload AutoReloadConfig `mapstructure:"autoReload"`
}

// AutoReloadConfig holds configuration for automatic certificate reloading
type AutoReloadConfig struct {
	Enabled           bool               `mapstructure:"enabled"`           // Enable auto-reload functionality
	CheckInterval     time.Duration      `mapstructure:"checkInterval"`     // Interval for checking certificate expiry
	PreemptiveRenewal time.Duration      `mapstructure:"preemptiveRenewal"` // Renew certificates this duration before expiry
	MaxRetries        int                `mapstructure:"maxRetries"`        // Maximum retry attempts for failed reloads
	RetryDelay        time.Duration      `mapstructure:"retryDelay"`        // Delay between retry attempts
	FileWatcher       FileWatcherConfig  `mapstructure:"fileWatcher"`       // File-based watching configuration
	VaultWatcher      VaultWatcherConfig `mapstructure:"vaultWatcher"`      // Vault-based watching configuration
}

// FileWatcherConfig holds configuration for file-based certificate watching
type FileWatcherConfig struct {
	Enabled       bool          `mapstructure:"enabled"`       // Enable file watching
	DebounceDelay time.Duration `mapstructure:"debounceDelay"` // Debounce delay for file change events
}

// VaultWatcherConfig holds configuration for Vault-based certificate watching
type VaultWatcherConfig struct {
	Enabled        bool          `mapstructure:"enabled"`        // Enable Vault watching
	PollInterval   time.Duration `mapstructure:"pollInterval"`   // Polling interval for Vault secrets
	AutoRenew      bool          `mapstructure:"autoRenew"`      // Enable automatic lease renewal
	RenewThreshold time.Duration `mapstructure:"renewThreshold"` // Renew leases this duration before expiry
	SecretPath     string        `mapstructure:"secretPath"`     // Vault secret path for TLS certificates
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool          `mapstructure:"enabled"`        // Enable/disable rate limiting
	RequestsPerMin int           `mapstructure:"requestsPerMin"` // Requests allowed per minute
	BurstCapacity  int           `mapstructure:"burstCapacity"`  // Burst capacity for token bucket
	ByIP           bool          `mapstructure:"byIP"`           // Enable per-IP rate limiting
	ByAPIKey       bool          `mapstructure:"byAPIKey"`       // Enable per-API-key rate limiting
	Window         time.Duration `mapstructure:"window"`         // Rate limiting window duration
}

// AppConfig holds general application configuration
type AppConfig struct {
	LogLevel         string   `mapstructure:"logLevel"`
	DefaultFormat    string   `mapstructure:"defaultFormat"`
	SupportedFormats []string `mapstructure:"supportedFormats"`
	MaxFileSize      int64    `mapstructure:"maxFileSize"`
}

// ObservabilityConfig holds observability configuration
type ObservabilityConfig struct {
	Enabled         bool                `mapstructure:"enabled"`
	ServiceName     string              `mapstructure:"serviceName"`
	ServiceVersion  string              `mapstructure:"serviceVersion"`
	ServiceInstance string              `mapstructure:"serviceInstance"`
	ConsoleOutput   bool                `mapstructure:"consoleOutput"`
	SampleRate      float64             `mapstructure:"sampleRate"`
	Tracing         TracingConfig       `mapstructure:"tracing"`
	Metrics         MetricsConfig       `mapstructure:"metrics"`
	CustomMetrics   CustomMetricsConfig `mapstructure:"customMetrics"`
	Console         ConsoleConfig       `mapstructure:"console"`
	Prometheus      PrometheusConfig    `mapstructure:"prometheus"`
	OTLP            OTLPConfig          `mapstructure:"otlp"`
	HealthCheck     HealthCheckConfig   `mapstructure:"healthCheck"`
}

// TracingConfig holds tracing configuration
type TracingConfig struct {
	Enabled    bool    `mapstructure:"enabled"`
	SampleRate float64 `mapstructure:"sampleRate"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	CollectionInterval time.Duration `mapstructure:"collectionInterval"`
}

// ConsoleConfig holds console output configuration
type ConsoleConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	PrettyPrint bool `mapstructure:"prettyPrint"`
}

// CustomMetricsConfig holds fine-grained custom metrics configuration
type CustomMetricsConfig struct {
	AIOperations    AIOperationsMetricsConfig   `mapstructure:"aiOperations"`
	BusinessMetrics BusinessMetricsConfig       `mapstructure:"businessMetrics"`
	Infrastructure  InfrastructureMetricsConfig `mapstructure:"infrastructure"`
}

// AIOperationsMetricsConfig holds AI operation metrics configuration
type AIOperationsMetricsConfig struct {
	Enabled         bool `mapstructure:"enabled"`
	TrackDuration   bool `mapstructure:"trackDuration"`
	TrackTokenUsage bool `mapstructure:"trackTokenUsage"`
	TrackModelInfo  bool `mapstructure:"trackModelInfo"`
}

// BusinessMetricsConfig holds business metrics configuration
type BusinessMetricsConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	TrackSuccessRates bool `mapstructure:"trackSuccessRates"`
	TrackContentSizes bool `mapstructure:"trackContentSizes"`
}

// InfrastructureMetricsConfig holds infrastructure metrics configuration
type InfrastructureMetricsConfig struct {
	Enabled         bool `mapstructure:"enabled"`
	TrackRateLimits bool `mapstructure:"trackRateLimits"`
	TrackCertExpiry bool `mapstructure:"trackCertExpiry"`
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Endpoint string `mapstructure:"endpoint"`
	Port     string `mapstructure:"port"`
}

// OTLPConfig holds OTLP exporter configuration
type OTLPConfig struct {
	Enabled  bool              `mapstructure:"enabled"`
	Endpoint string            `mapstructure:"endpoint"`
	Insecure bool              `mapstructure:"insecure"`
	Headers  map[string]string `mapstructure:"headers"`
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Timeout             time.Duration `mapstructure:"timeout"`
	AIModelCheckTimeout time.Duration `mapstructure:"aiModelCheckTimeout"`
}

// LoadConfig loads configuration from environment variables and a config file
func LoadConfig() (*Config, error) {
	log.Println("[CONFIG] Starting configuration loading process")

	v := viper.New()

	// Set default values
	setDefaults(v)
	log.Println("[CONFIG] Applied default configuration values")

	// Set up environment variable handling
	v.SetEnvPrefix("RESUMATTER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	log.Println("[CONFIG] Configured environment variable handling with prefix 'RESUMATTER'")

	// Set up config file handling
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/resumatter/")
	v.AddConfigPath("$HOME/.resumatter")
	v.AddConfigPath(".")
	log.Println("[CONFIG] Configured config file search paths: /etc/resumatter/, $HOME/.resumatter, .")

	// Read the config file
	configFileUsed := ""
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		log.Println("[CONFIG] No config file found, using defaults and environment variables")
	} else {
		configFileUsed = v.ConfigFileUsed()
		log.Printf("[CONFIG] Successfully loaded config file: %s", configFileUsed)
	}

	// Unmarshal the configuration into the Config struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	log.Println("[CONFIG] Successfully unmarshaled configuration")

	// Apply fallback logic for backward compatibility
	config.applyFallbacks()
	log.Println("[CONFIG] Applied configuration fallbacks and environment variable overrides")

	// Log configuration sources summary
	config.logConfigurationSources(configFileUsed)

	// Validate prompt files before attempting to load them
	if err := config.validatePromptFiles(); err != nil {
		return nil, fmt.Errorf("prompt file validation failed: %w", err)
	}

	// Load custom prompts from external files
	if err := config.loadPromptsFromFiles(); err != nil {
		return nil, fmt.Errorf("failed to load custom prompts from files: %w", err)
	}

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	log.Println("[CONFIG] Configuration loading completed successfully")
	return &config, nil
}

// setDefaults sets the default configuration values
func setDefaults(v *viper.Viper) {
	// AI Configuration - Global defaults
	v.SetDefault("ai.provider", "gemini")
	v.SetDefault("ai.model", "gemini-2.0-flash")
	v.SetDefault("ai.timeout", 60*time.Second)
	v.SetDefault("ai.apiKey", "")
	v.SetDefault("ai.maxRetries", 3)
	v.SetDefault("ai.temperature", 0.7)
	v.SetDefault("ai.useSystemPrompts", true)

	// AI Configuration - Tailor operation defaults
	v.SetDefault("ai.tailor.provider", "gemini")
	v.SetDefault("ai.tailor.model", "")
	v.SetDefault("ai.tailor.timeout", 90*time.Second) // Longer timeout for complex operations
	v.SetDefault("ai.tailor.apiKey", "")
	v.SetDefault("ai.tailor.maxRetries", 2)
	v.SetDefault("ai.tailor.temperature", 0.3) // Lower temperature for consistency
	v.SetDefault("ai.tailor.useSystemPrompts", true)

	// AI Configuration - Evaluate operation defaults
	v.SetDefault("ai.evaluate.provider", "gemini")
	v.SetDefault("ai.evaluate.model", "")
	v.SetDefault("ai.evaluate.timeout", 60*time.Second) // Standard timeout
	v.SetDefault("ai.evaluate.apiKey", "")
	v.SetDefault("ai.evaluate.maxRetries", 3)
	v.SetDefault("ai.evaluate.temperature", 0.1) // Very low temperature for factual analysis
	v.SetDefault("ai.evaluate.useSystemPrompts", true)

	// AI Configuration - Analyze operation defaults
	v.SetDefault("ai.analyze.provider", "gemini")
	v.SetDefault("ai.analyze.model", "")
	v.SetDefault("ai.analyze.timeout", 75*time.Second) // Moderate timeout for analysis
	v.SetDefault("ai.analyze.apiKey", "")
	v.SetDefault("ai.analyze.maxRetries", 2)
	v.SetDefault("ai.analyze.temperature", 0.2) // Low temperature for consistent analysis
	v.SetDefault("ai.analyze.useSystemPrompts", true)

	// Circuit Breaker Configuration defaults for all operations
	v.SetDefault("ai.tailor.circuitBreaker.enabled", true)
	v.SetDefault("ai.tailor.circuitBreaker.maxRequests", 3)
	v.SetDefault("ai.tailor.circuitBreaker.interval", 60*time.Second)
	v.SetDefault("ai.tailor.circuitBreaker.timeout", 60*time.Second)
	v.SetDefault("ai.tailor.circuitBreaker.minRequests", 3)
	v.SetDefault("ai.tailor.circuitBreaker.failureThreshold", 0.6)

	v.SetDefault("ai.evaluate.circuitBreaker.enabled", true)
	v.SetDefault("ai.evaluate.circuitBreaker.maxRequests", 3)
	v.SetDefault("ai.evaluate.circuitBreaker.interval", 60*time.Second)
	v.SetDefault("ai.evaluate.circuitBreaker.timeout", 60*time.Second)
	v.SetDefault("ai.evaluate.circuitBreaker.minRequests", 3)
	v.SetDefault("ai.evaluate.circuitBreaker.failureThreshold", 0.6)

	v.SetDefault("ai.analyze.circuitBreaker.enabled", true)
	v.SetDefault("ai.analyze.circuitBreaker.maxRequests", 3)
	v.SetDefault("ai.analyze.circuitBreaker.interval", 60*time.Second)
	v.SetDefault("ai.analyze.circuitBreaker.timeout", 60*time.Second)
	v.SetDefault("ai.analyze.circuitBreaker.minRequests", 3)
	v.SetDefault("ai.analyze.circuitBreaker.failureThreshold", 0.6)

	// Server Configuration
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", "8080")
	v.SetDefault("server.readTimeout", 30*time.Second)
	v.SetDefault("server.writeTimeout", 30*time.Second)
	v.SetDefault("server.idleTimeout", 120*time.Second)
	// TLS Configuration defaults
	v.SetDefault("server.tls.mode", "disabled") // disabled, server, mutual
	v.SetDefault("server.tls.certFile", "")
	v.SetDefault("server.tls.keyFile", "")
	v.SetDefault("server.tls.caFile", "")
	v.SetDefault("server.tls.minVersion", "1.2")           // TLS 1.2 minimum
	v.SetDefault("server.tls.cipherSuites", []string{})    // Use Go defaults
	v.SetDefault("server.tls.clientAuthPolicy", "require") // require, request, verify
	v.SetDefault("server.tls.insecureSkipVerify", false)
	v.SetDefault("server.tls.serverName", "")

	// Auto-reload configuration defaults
	v.SetDefault("server.tls.autoReload.enabled", true)
	v.SetDefault("server.tls.autoReload.checkInterval", 30*time.Second)
	v.SetDefault("server.tls.autoReload.preemptiveRenewal", 72*time.Hour) // 72 hours before expiry
	v.SetDefault("server.tls.autoReload.maxRetries", 3)
	v.SetDefault("server.tls.autoReload.retryDelay", 10*time.Second)

	// File watcher defaults
	v.SetDefault("server.tls.autoReload.fileWatcher.enabled", true)
	v.SetDefault("server.tls.autoReload.fileWatcher.debounceDelay", time.Second)

	// Vault watcher defaults
	v.SetDefault("server.tls.autoReload.vaultWatcher.enabled", false)
	v.SetDefault("server.tls.autoReload.vaultWatcher.pollInterval", 5*time.Minute)
	v.SetDefault("server.tls.autoReload.vaultWatcher.autoRenew", true)
	v.SetDefault("server.tls.autoReload.vaultWatcher.renewThreshold", 24*time.Hour)
	v.SetDefault("server.tls.autoReload.vaultWatcher.secretPath", "")
	// API Authentication defaults
	v.SetDefault("server.apiKeys", []string{})
	// Rate limiting defaults
	v.SetDefault("server.rateLimit.enabled", false)
	v.SetDefault("server.rateLimit.requestsPerMin", 60)
	v.SetDefault("server.rateLimit.burstCapacity", 10)
	v.SetDefault("server.rateLimit.byIP", true)
	v.SetDefault("server.rateLimit.byAPIKey", false)
	v.SetDefault("server.rateLimit.window", time.Minute)

	// App Configuration
	v.SetDefault("app.logLevel", "info")
	v.SetDefault("app.defaultFormat", "json")
	v.SetDefault("app.supportedFormats", []string{"json", "text", "markdown"})
	v.SetDefault("app.maxFileSize", 1024*1024) // 1MB

	// Vault Configuration
	v.SetDefault("vault.enabled", false)
	v.SetDefault("vault.address", "")
	v.SetDefault("vault.token", "")
	v.SetDefault("vault.tokenFile", "")
	v.SetDefault("vault.namespace", "")
	v.SetDefault("vault.secrets.apiKeys", "")
	v.SetDefault("vault.secrets.geminiKey", "")
	v.SetDefault("vault.secrets.tlsCerts", "")

	// Observability Configuration
	v.SetDefault("observability.enabled", true)
	v.SetDefault("observability.serviceName", "resumatter")
	v.SetDefault("observability.serviceVersion", "")  // Will use app version if empty
	v.SetDefault("observability.serviceInstance", "") // Will be auto-generated if empty
	v.SetDefault("observability.consoleOutput", false)
	v.SetDefault("observability.sampleRate", 1.0)

	// Tracing Configuration
	v.SetDefault("observability.tracing.enabled", true)
	v.SetDefault("observability.tracing.sampleRate", 1.0)

	// Metrics Configuration
	v.SetDefault("observability.metrics.enabled", true)
	v.SetDefault("observability.metrics.collectionInterval", 15*time.Second)

	// Custom Metrics Configuration
	v.SetDefault("observability.customMetrics.aiOperations.enabled", true)
	v.SetDefault("observability.customMetrics.aiOperations.trackDuration", true)
	v.SetDefault("observability.customMetrics.aiOperations.trackTokenUsage", true)
	v.SetDefault("observability.customMetrics.aiOperations.trackModelInfo", true)
	v.SetDefault("observability.customMetrics.businessMetrics.enabled", true)
	v.SetDefault("observability.customMetrics.businessMetrics.trackSuccessRates", true)
	v.SetDefault("observability.customMetrics.businessMetrics.trackContentSizes", true)
	v.SetDefault("observability.customMetrics.infrastructure.enabled", true)
	v.SetDefault("observability.customMetrics.infrastructure.trackRateLimits", true)
	v.SetDefault("observability.customMetrics.infrastructure.trackCertExpiry", true)

	// Console Configuration
	v.SetDefault("observability.console.enabled", false)
	v.SetDefault("observability.console.prettyPrint", true)

	// Prometheus Configuration
	v.SetDefault("observability.prometheus.enabled", true)
	v.SetDefault("observability.prometheus.endpoint", "/metrics")
	v.SetDefault("observability.prometheus.port", "9090")

	// OTLP Configuration
	v.SetDefault("observability.otlp.enabled", false)
	v.SetDefault("observability.otlp.endpoint", "http://localhost:4318")
	v.SetDefault("observability.otlp.insecure", true)
	v.SetDefault("observability.otlp.headers", map[string]string{})

	// Health Check Configuration
	v.SetDefault("observability.healthCheck.timeout", 15*time.Second)
	v.SetDefault("observability.healthCheck.aiModelCheckTimeout", 10*time.Second)
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.AI.APIKey == "" {
		return fmt.Errorf("AI API key is required (set RESUMATTER_AI_APIKEY environment variable)")
	}

	if c.AI.Timeout <= 0 {
		return fmt.Errorf("AI timeout must be positive")
	}

	if c.Server.Port == "" {
		return fmt.Errorf("server port is required")
	}

	validFormats := make(map[string]bool)
	for _, format := range c.App.SupportedFormats {
		validFormats[format] = true
	}
	if !validFormats[c.App.DefaultFormat] {
		return fmt.Errorf("invalid default format: %s", c.App.DefaultFormat)
	}

	// Validate TLS configuration
	if err := c.ValidateTLSConfig(); err != nil {
		return fmt.Errorf("TLS configuration error: %w", err)
	}

	return nil
}

// applyOperationDefaults applies global defaults to operation-specific configuration
func (c *Config) applyOperationDefaults(opCfg *OperationAIConfig) {
	if opCfg.Provider == "" {
		opCfg.Provider = c.AI.Provider
	}
	if opCfg.Model == "" {
		opCfg.Model = c.AI.Model
	}
	if opCfg.Timeout == nil {
		opCfg.Timeout = &c.AI.Timeout
	}
	if opCfg.APIKey == "" {
		opCfg.APIKey = c.AI.APIKey
	}
	if opCfg.MaxRetries == nil {
		opCfg.MaxRetries = &c.AI.MaxRetries
	}
	if opCfg.Temperature == nil {
		opCfg.Temperature = &c.AI.Temperature
	}
	// UseSystemPrompts: apply global default only if not explicitly set
	if opCfg.UseSystemPrompts == nil {
		opCfg.UseSystemPrompts = &c.AI.UseSystemPrompts
	}
}

// GetTailorConfig returns the AI configuration for tailor operations with fallback to global config
func (c *Config) GetTailorConfig() OperationAIConfig {
	config := c.AI.Tailor

	// Apply common defaults
	c.applyOperationDefaults(&config)

	// Apply tailor-specific prompt fallbacks
	if config.CustomPrompts.SystemPrompts.TailorResume == "" {
		config.CustomPrompts.SystemPrompts.TailorResume = c.AI.CustomPrompts.SystemPrompts.TailorResume
	}
	if config.CustomPrompts.UserPrompts.TailorResume == "" {
		config.CustomPrompts.UserPrompts.TailorResume = c.AI.CustomPrompts.UserPrompts.TailorResume
	}
	// Also copy file paths for potential later loading
	if config.CustomPrompts.SystemPrompts.TailorResumeFile == "" {
		config.CustomPrompts.SystemPrompts.TailorResumeFile = c.AI.CustomPrompts.SystemPrompts.TailorResumeFile
	}
	if config.CustomPrompts.UserPrompts.TailorResumeFile == "" {
		config.CustomPrompts.UserPrompts.TailorResumeFile = c.AI.CustomPrompts.UserPrompts.TailorResumeFile
	}

	return config
}

// GetEvaluateConfig returns the AI configuration for evaluate operations with fallback to global config
func (c *Config) GetEvaluateConfig() OperationAIConfig {
	config := c.AI.Evaluate

	// Apply common defaults
	c.applyOperationDefaults(&config)

	// Apply evaluate-specific prompt fallbacks
	if config.CustomPrompts.SystemPrompts.EvaluateResume == "" {
		config.CustomPrompts.SystemPrompts.EvaluateResume = c.AI.CustomPrompts.SystemPrompts.EvaluateResume
	}
	if config.CustomPrompts.UserPrompts.EvaluateResume == "" {
		config.CustomPrompts.UserPrompts.EvaluateResume = c.AI.CustomPrompts.UserPrompts.EvaluateResume
	}
	// Also copy file paths for potential later loading
	if config.CustomPrompts.SystemPrompts.EvaluateResumeFile == "" {
		config.CustomPrompts.SystemPrompts.EvaluateResumeFile = c.AI.CustomPrompts.SystemPrompts.EvaluateResumeFile
	}
	if config.CustomPrompts.UserPrompts.EvaluateResumeFile == "" {
		config.CustomPrompts.UserPrompts.EvaluateResumeFile = c.AI.CustomPrompts.UserPrompts.EvaluateResumeFile
	}

	return config
}

// GetAnalyzeConfig returns the AI configuration for analyze operations with fallback to global config
func (c *Config) GetAnalyzeConfig() OperationAIConfig {
	config := c.AI.Analyze

	// Apply common defaults
	c.applyOperationDefaults(&config)

	// Apply analyze-specific prompt fallbacks
	if config.CustomPrompts.SystemPrompts.AnalyzeJob == "" {
		config.CustomPrompts.SystemPrompts.AnalyzeJob = c.AI.CustomPrompts.SystemPrompts.AnalyzeJob
	}
	if config.CustomPrompts.UserPrompts.AnalyzeJob == "" {
		config.CustomPrompts.UserPrompts.AnalyzeJob = c.AI.CustomPrompts.UserPrompts.AnalyzeJob
	}
	// Also copy file paths for potential later loading
	if config.CustomPrompts.SystemPrompts.AnalyzeJobFile == "" {
		config.CustomPrompts.SystemPrompts.AnalyzeJobFile = c.AI.CustomPrompts.SystemPrompts.AnalyzeJobFile
	}
	if config.CustomPrompts.UserPrompts.AnalyzeJobFile == "" {
		config.CustomPrompts.UserPrompts.AnalyzeJobFile = c.AI.CustomPrompts.UserPrompts.AnalyzeJobFile
	}

	return config
}

// GetLoadedTailorPrompts returns a copy of the loaded prompts for tailor operation
func (c *Config) GetLoadedTailorPrompts() OperationLoadedPrompts {
	return loadedPrompts.Tailor
}

// GetLoadedEvaluatePrompts returns a copy of the loaded prompts for evaluate operation
func (c *Config) GetLoadedEvaluatePrompts() OperationLoadedPrompts {
	return loadedPrompts.Evaluate
}

// GetLoadedAnalyzePrompts returns a copy of the loaded prompts for analyze operation
func (c *Config) GetLoadedAnalyzePrompts() OperationLoadedPrompts {
	return loadedPrompts.Analyze
}

// GetLoadedGlobalPrompts returns a copy of the loaded global prompts
func (c *Config) GetLoadedGlobalPrompts() LoadedPrompts {
	return loadedPrompts.Global
}

// ValidateTLSConfig validates the TLS configuration
func (c *Config) ValidateTLSConfig() error {
	tls := c.Server.TLS

	switch tls.Mode {
	case "disabled":
		// No validation needed for disabled mode
		return nil
	case "server":
		// Check if we have either files or content for cert and key
		if (tls.CertFile == "" && tls.CertContent == "") || (tls.KeyFile == "" && tls.KeyContent == "") {
			return fmt.Errorf("TLS certificate and key are required for server mode (provide either files or content)")
		}
		// Ensure we don't have both file and content for the same certificate
		if tls.CertFile != "" && tls.CertContent != "" {
			return fmt.Errorf("cannot specify both certFile and certContent - choose one")
		}
		if tls.KeyFile != "" && tls.KeyContent != "" {
			return fmt.Errorf("cannot specify both keyFile and keyContent - choose one")
		}
	case "mutual":
		// Check if we have either files or content for cert and key
		if (tls.CertFile == "" && tls.CertContent == "") || (tls.KeyFile == "" && tls.KeyContent == "") {
			return fmt.Errorf("TLS certificate and key are required for mutual mode (provide either files or content)")
		}
		// Check if we have either file or content for CA
		if tls.CAFile == "" && tls.CAContent == "" {
			return fmt.Errorf("CA certificate is required for mutual TLS mode (provide either caFile or caContent)")
		}
		// Ensure we don't have both file and content for the same certificate
		if tls.CertFile != "" && tls.CertContent != "" {
			return fmt.Errorf("cannot specify both certFile and certContent - choose one")
		}
		if tls.KeyFile != "" && tls.KeyContent != "" {
			return fmt.Errorf("cannot specify both keyFile and keyContent - choose one")
		}
		if tls.CAFile != "" && tls.CAContent != "" {
			return fmt.Errorf("cannot specify both caFile and caContent - choose one")
		}
		// Validate client auth policy
		switch tls.ClientAuthPolicy {
		case "require", "request", "verify":
			// Valid policies
		case "":
			// Default to require for mutual mode
		default:
			return fmt.Errorf("invalid clientAuthPolicy: %s (must be 'require', 'request', or 'verify')", tls.ClientAuthPolicy)
		}
	default:
		return fmt.Errorf("invalid TLS mode: %s (must be 'disabled', 'server', or 'mutual')", tls.Mode)
	}

	// Validate TLS version
	switch tls.MinVersion {
	case "", "1.2", "1.3":
		// Valid versions (empty defaults to 1.2)
	default:
		return fmt.Errorf("invalid TLS minVersion: %s (must be '1.2' or '1.3')", tls.MinVersion)
	}

	return nil
}

// applyFallbacks applies environment variable fallbacks
func (c *Config) applyFallbacks() {
	// Note: API key fallbacks are now handled in Get...Config() methods to avoid duplication

	// Parse API keys from environment variable if not set in config
	if len(c.Server.APIKeys) == 0 {
		if apiKeysEnv := os.Getenv("RESUMATTER_SERVER_APIKEYS"); apiKeysEnv != "" {
			c.Server.APIKeys = strings.Split(apiKeysEnv, ",")
			// Trim whitespace from each key
			for i, key := range c.Server.APIKeys {
				c.Server.APIKeys[i] = strings.TrimSpace(key)
			}
		}
	}

	// Set default client auth policy for mutual TLS if not specified
	if c.Server.TLS.Mode == "mutual" && c.Server.TLS.ClientAuthPolicy == "" {
		c.Server.TLS.ClientAuthPolicy = "require"
	}

	// Set default TLS version if not specified
	if c.Server.TLS.MinVersion == "" && c.Server.TLS.Mode != "disabled" {
		c.Server.TLS.MinVersion = "1.2"
	}

	// Set dynamic service instance ID if not specified
	if c.Observability.ServiceInstance == "" {
		// Try to get hostname, fallback to default
		if hostname, err := os.Hostname(); err == nil {
			c.Observability.ServiceInstance = fmt.Sprintf("%s-%s", c.Observability.ServiceName, hostname)
		} else {
			c.Observability.ServiceInstance = fmt.Sprintf("%s-1", c.Observability.ServiceName)
		}
	}

	// Set console output based on log level if not explicitly configured
	if c.App.LogLevel == "debug" && !c.Observability.ConsoleOutput {
		c.Observability.ConsoleOutput = true
	}
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

// Global configuration instance
var GlobalConfig *Config

// InitConfig initializes the global configuration
func InitConfig() error {
	config, err := LoadConfig()
	if err != nil {
		return err
	}
	GlobalConfig = config
	return nil
}
