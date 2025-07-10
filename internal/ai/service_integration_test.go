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
	testConfig := &config.Config{
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

	t.Run("TailorConfigDerivation", func(t *testing.T) {
		// 1. Test the config derivation logic
		tailorCfg := testConfig.GetTailorConfig()

		// 2. Assert that the derived config is correct
		if tailorCfg.Model != "tailor-specific-model" {
			t.Errorf("Expected tailor model 'tailor-specific-model', got '%s'", tailorCfg.Model)
		}
		if *tailorCfg.Timeout != 90*time.Second {
			t.Errorf("Expected tailor timeout 90s, got %v", *tailorCfg.Timeout)
		}
		if *tailorCfg.Temperature != 0.3 {
			t.Errorf("Expected tailor temperature 0.3, got %f", *tailorCfg.Temperature)
		}
		// Assert fallback behavior
		if tailorCfg.APIKey != "global-api-key" {
			t.Errorf("Expected tailor APIKey to fall back to 'global-api-key', got '%s'", tailorCfg.APIKey)
		}
		if *tailorCfg.MaxRetries != 5 {
			t.Errorf("Expected tailor MaxRetries to fall back to 5, got %d", *tailorCfg.MaxRetries)
		}

		// 3. (Optional but good) Verify service can be created with this derived config
		_, err := NewService(&tailorCfg, "tailor", testLogger)
		if err != nil {
			// We expect an error due to the dummy API key, but not a panic.
			// This confirms the factory function can consume the derived config.
			t.Logf("Received expected error when creating service with test key: %v", err)
		}
	})

	t.Run("EvaluateConfigDerivation", func(t *testing.T) {
		evaluateCfg := testConfig.GetEvaluateConfig()

		if evaluateCfg.Model != "evaluate-specific-model" {
			t.Errorf("Expected evaluate model 'evaluate-specific-model', got '%s'", evaluateCfg.Model)
		}
		if *evaluateCfg.MaxRetries != 1 {
			t.Errorf("Expected evaluate MaxRetries to be 1, got %d", *evaluateCfg.MaxRetries)
		}
		// Assert fallback behavior
		if *evaluateCfg.Timeout != 60*time.Second {
			t.Errorf("Expected evaluate timeout to fall back to 60s, got %v", *evaluateCfg.Timeout)
		}
	})

	t.Run("AnalyzeConfigDerivation", func(t *testing.T) {
		analyzeCfg := testConfig.GetAnalyzeConfig()

		// Assert all values fall back to global defaults
		if analyzeCfg.Model != "global-model" {
			t.Errorf("Expected analyze model to fall back to 'global-model', got '%s'", analyzeCfg.Model)
		}
		if *analyzeCfg.Timeout != 60*time.Second {
			t.Errorf("Expected analyze timeout to fall back to 60s, got %v", *analyzeCfg.Timeout)
		}
		if analyzeCfg.APIKey != "global-api-key" {
			t.Errorf("Expected analyze APIKey to fall back to 'global-api-key', got '%s'", analyzeCfg.APIKey)
		}
	})
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
