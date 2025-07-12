package config

import (
	"time"

	"github.com/spf13/viper"
)

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