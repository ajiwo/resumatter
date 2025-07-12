package config

import (
	"fmt"
	"log"
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
