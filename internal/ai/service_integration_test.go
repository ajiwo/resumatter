package ai

import (
	"log/slog"
	"testing"
	"time"

	"resumatter/internal/config"
	"resumatter/internal/errors"
)

// Helper functions to create pointers for test values
func timePtr(d time.Duration) *time.Duration { return &d }
func intPtr(i int) *int                      { return &i }
func float32Ptr(f float32) *float32          { return &f }
func boolPtr(b bool) *bool                   { return &b }

var testLogger = errors.NewLogger(slog.LevelDebug)

// TestOperationSpecificConfigDerivation verifies that operation-specific configurations
// are correctly derived, with fallbacks to the global configuration.
// This replaces the old TestServiceSpecificCircuitBreakerConfigurations.
func TestOperationSpecificConfigDerivation(t *testing.T) {
	// Set up a mock config with different settings for each operation,
	// mirroring the new dependency injection pattern.
	testConfig := createTestConfigWithOverrides()

	testCases := []struct {
		name           string
		getConfig      func() config.OperationAIConfig
		expectedValues map[string]interface{}
		fallbackValues map[string]interface{}
	}{
		{
			name:      "TailorConfigDerivation",
			getConfig: testConfig.GetTailorConfig,
			expectedValues: map[string]interface{}{
				"Model":       "tailor-specific-model",
				"Timeout":     90 * time.Second,
				"Temperature": float32(0.3),
			},
			fallbackValues: map[string]interface{}{
				"APIKey":     "global-api-key",
				"MaxRetries": 5,
			},
		},
		{
			name:      "EvaluateConfigDerivation",
			getConfig: testConfig.GetEvaluateConfig,
			expectedValues: map[string]interface{}{
				"Model":      "evaluate-specific-model",
				"MaxRetries": 1,
			},
			fallbackValues: map[string]interface{}{
				"Timeout": 60 * time.Second,
			},
		},
		{
			name:           "AnalyzeConfigDerivation",
			getConfig:      testConfig.GetAnalyzeConfig,
			expectedValues: map[string]interface{}{
				// All values should fall back to global defaults
			},
			fallbackValues: map[string]interface{}{
				"Model":   "global-model",
				"Timeout": 60 * time.Second,
				"APIKey":  "global-api-key",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.getConfig()
			assertConfigValues(t, cfg, tc.expectedValues, tc.fallbackValues)
			assertServiceCreation(t, cfg, tc.name)
		})
	}
}

// createTestConfigWithOverrides creates a test config with operation-specific overrides
func createTestConfigWithOverrides() *config.Config {
	return &config.Config{
		AI: config.AIConfig{
			// Global defaults that should be used as fallbacks
			Provider:         "gemini",
			Model:            "global-model",
			Timeout:          60 * time.Second,
			APIKey:           "global-api-key",
			MaxRetries:       5,
			Temperature:      0.9,
			UseSystemPrompts: true,

			// Operation-specific configurations that override globals
			Tailor: config.OperationAIConfig{
				Model:       "tailor-specific-model",   // Override
				Timeout:     timePtr(90 * time.Second), // Override
				Temperature: float32Ptr(0.3),           // Override
				// APIKey and MaxRetries should fall back to global values.
			},

			Evaluate: config.OperationAIConfig{
				Model:      "evaluate-specific-model", // Override
				MaxRetries: intPtr(1),                 // Override
				// Other values should fall back.
			},

			Analyze: config.OperationAIConfig{
				// This operation has no specific overrides, so it should use all global values.
			},
		},
	}
}

// assertConfigValues verifies that config values match expected and fallback values
func assertConfigValues(t *testing.T, cfg config.OperationAIConfig, expectedValues, fallbackValues map[string]interface{}) {
	t.Helper()

	// Check expected overrides
	for key, expected := range expectedValues {
		assertConfigValue(t, cfg, key, expected)
	}

	// Check fallback values
	for key, expected := range fallbackValues {
		assertConfigValue(t, cfg, key, expected)
	}
}

// assertConfigValue checks a specific config value
func assertConfigValue(t *testing.T, cfg config.OperationAIConfig, key string, expected interface{}) {
	t.Helper()

	switch key {
	case "Model":
		if cfg.Model != expected.(string) {
			t.Errorf("Expected %s '%s', got '%s'", key, expected, cfg.Model)
		}
	case "Timeout":
		if *cfg.Timeout != expected.(time.Duration) {
			t.Errorf("Expected %s %v, got %v", key, expected, *cfg.Timeout)
		}
	case "Temperature":
		if *cfg.Temperature != expected.(float32) {
			t.Errorf("Expected %s %f, got %f", key, expected, *cfg.Temperature)
		}
	case "APIKey":
		if cfg.APIKey != expected.(string) {
			t.Errorf("Expected %s '%s', got '%s'", key, expected, cfg.APIKey)
		}
	case "MaxRetries":
		if *cfg.MaxRetries != expected.(int) {
			t.Errorf("Expected %s %d, got %d", key, expected, *cfg.MaxRetries)
		}
	}
}

// assertServiceCreation verifies that a service can be created with the derived config
func assertServiceCreation(t *testing.T, cfg config.OperationAIConfig, operation string) {
	t.Helper()

	_, err := NewService(&cfg, operation, testLogger)
	if err != nil {
		// We expect an error due to the dummy API key, but not a panic.
		// This confirms the factory function can consume the derived config.
		t.Logf("Received expected error when creating service with test key: %v", err)
	}
}

func TestCircuitBreakerIntegrationWithServices(t *testing.T) {
	// Create a service with specific circuit breaker config
	testOpConfig := &config.OperationAIConfig{
		Provider:         "gemini",
		Model:            "test-model",
		Timeout:          timePtr(30 * time.Second),
		APIKey:           "test-key",
		MaxRetries:       intPtr(1),
		Temperature:      float32Ptr(0.5),
		UseSystemPrompts: boolPtr(true),
		CircuitBreaker: config.CircuitBreakerConfig{
			Enabled:          true,
			MaxRequests:      5,
			Interval:         30 * time.Second,
			Timeout:          45 * time.Second,
			MinRequests:      2,
			FailureThreshold: 0.8,
		},
	}

	service, err := NewService(testOpConfig, "test-op", testLogger)
	if err != nil {
		t.Logf("Received expected error when creating service with test key: %v", err)
	}

	// Verify the service has the correct configuration
	if service.config.CircuitBreaker.MaxRequests != 5 {
		t.Errorf("Expected circuit breaker max requests 5, got %d", service.config.CircuitBreaker.MaxRequests)
	}
	if service.config.CircuitBreaker.FailureThreshold != 0.8 {
		t.Errorf("Expected circuit breaker failure threshold 0.8, got %f", service.config.CircuitBreaker.FailureThreshold)
	}

	// Test that the provider has a circuit breaker
	if geminiProvider, ok := service.Provider.(*GeminiProvider); ok {
		stats := geminiProvider.GetCircuitBreakerStats()

		aiOpsStats, ok := stats["ai_operations"].(map[string]any)
		if !ok {
			t.Fatal("AI operations stats should exist and be a map")
		}
		if name, _ := aiOpsStats["name"].(string); name != "AI-test-op" {
			t.Errorf("Expected circuit breaker name 'AI-test-op', got '%s'", name)
		}

		modelOpsStats, ok := stats["model_operations"].(map[string]any)
		if !ok {
			t.Fatal("Model operations stats should exist and be a map")
		}
		if name, _ := modelOpsStats["name"].(string); name != "AI-Model-test-op" {
			t.Errorf("Expected model circuit breaker name 'AI-Model-test-op', got '%s'", name)
		}

		// Check overall health
		if overallHealthy, _ := stats["overall_healthy"].(bool); !overallHealthy {
			t.Error("Circuit breaker should be healthy initially")
		}
	} else {
		t.Fatal("Service provider is not of type *GeminiProvider")
	}
}
