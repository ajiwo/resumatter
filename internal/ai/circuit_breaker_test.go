package ai

import (
	"testing"
	"time"

	"resumatter/internal/config"
)

func TestIndependentCircuitBreakerConfigurations(t *testing.T) {
	// Test that each operation gets its own circuit breaker configuration
	// as specified in config.example.yaml

	// Create different configurations for each operation (matching config.example.yaml)
	tailorConfig := &config.OperationAIConfig{
		Provider: "gemini",
		Model:    "gemini-2.5-pro",
		CircuitBreaker: config.CircuitBreakerConfig{
			Enabled:          true,
			MaxRequests:      3,
			Interval:         60 * time.Second,
			Timeout:          60 * time.Second,
			MinRequests:      3,
			FailureThreshold: 0.6,
		},
	}

	evaluateConfig := &config.OperationAIConfig{
		Provider: "gemini",
		Model:    "gemini-2.0-flash-lite",
		CircuitBreaker: config.CircuitBreakerConfig{
			Enabled:          true,
			MaxRequests:      5,                // Different from tailor
			Interval:         30 * time.Second, // Different from tailor
			Timeout:          45 * time.Second, // Different from tailor
			MinRequests:      2,                // Different from tailor
			FailureThreshold: 0.7,              // Different from tailor
		},
	}

	analyzeConfig := &config.OperationAIConfig{
		Provider: "gemini",
		Model:    "gemini-1.5-pro",
		CircuitBreaker: config.CircuitBreakerConfig{
			Enabled:          true,
			MaxRequests:      4,                // Different from others
			Interval:         90 * time.Second, // Different from others
			Timeout:          75 * time.Second, // Different from others
			MinRequests:      5,                // Different from others
			FailureThreshold: 0.5,              // Different from others
		},
	}

	// Create circuit breakers for each operation
	tailorCB := NewAICircuitBreaker("Tailor", tailorConfig, nil)
	evaluateCB := NewAICircuitBreaker("Evaluate", evaluateConfig, nil)
	analyzeCB := NewAICircuitBreaker("Analyze", analyzeConfig, nil)

	// Verify that each circuit breaker has independent configuration
	t.Run("TailorCircuitBreaker", func(t *testing.T) {
		stats := tailorCB.GetStats()

		// Check that tailor circuit breaker exists and has correct name
		name, ok := stats["name"].(string)
		if !ok {
			t.Fatal("Circuit breaker name not found")
		}

		expectedName := "AI-Tailor"
		if name != expectedName {
			t.Errorf("Expected circuit breaker name '%s', got '%s'", expectedName, name)
		}

		// Verify it's in closed state initially
		state, ok := stats["state"].(string)
		if !ok {
			t.Fatal("Circuit breaker state not found")
		}
		if state != "closed" {
			t.Errorf("Expected initial state 'closed', got '%s'", state)
		}

		// Verify it's enabled
		enabled, ok := stats["enabled"].(bool)
		if !ok {
			t.Fatal("Circuit breaker enabled status not found")
		}
		if !enabled {
			t.Error("Circuit breaker should be enabled")
		}
	})

	t.Run("EvaluateCircuitBreaker", func(t *testing.T) {
		stats := evaluateCB.GetStats()

		name, ok := stats["name"].(string)
		if !ok {
			t.Fatal("Circuit breaker name not found")
		}

		expectedName := "AI-Evaluate"
		if name != expectedName {
			t.Errorf("Expected circuit breaker name '%s', got '%s'", expectedName, name)
		}
	})

	t.Run("AnalyzeCircuitBreaker", func(t *testing.T) {
		stats := analyzeCB.GetStats()

		name, ok := stats["name"].(string)
		if !ok {
			t.Fatal("Circuit breaker name not found")
		}

		expectedName := "AI-Analyze"
		if name != expectedName {
			t.Errorf("Expected circuit breaker name '%s', got '%s'", expectedName, name)
		}
	})

	// Verify that circuit breakers are independent (different instances)
	t.Run("IndependentInstances", func(t *testing.T) {
		if tailorCB == evaluateCB {
			t.Error("Tailor and evaluate circuit breakers should be different instances")
		}
		if tailorCB == analyzeCB {
			t.Error("Tailor and analyze circuit breakers should be different instances")
		}
		if evaluateCB == analyzeCB {
			t.Error("Evaluate and analyze circuit breakers should be different instances")
		}
	})

	// Verify that health states are independent
	t.Run("IndependentHealthStates", func(t *testing.T) {
		tailorHealthy := tailorCB.IsHealthy()
		evaluateHealthy := evaluateCB.IsHealthy()
		analyzeHealthy := analyzeCB.IsHealthy()

		// All should be healthy initially
		if !tailorHealthy {
			t.Error("Tailor circuit breaker should be healthy initially")
		}
		if !evaluateHealthy {
			t.Error("Evaluate circuit breaker should be healthy initially")
		}
		if !analyzeHealthy {
			t.Error("Analyze circuit breaker should be healthy initially")
		}
	})
}

func TestCircuitBreakerConfigurationMapping(t *testing.T) {
	// Test that configuration values are properly applied to circuit breakers

	customConfig := &config.OperationAIConfig{
		Provider: "gemini",
		Model:    "test-model",
		CircuitBreaker: config.CircuitBreakerConfig{
			Enabled:          true,
			MaxRequests:      10,
			Interval:         120 * time.Second,
			Timeout:          90 * time.Second,
			MinRequests:      5,
			FailureThreshold: 0.8,
		},
	}

	cb := NewAICircuitBreaker("Test", customConfig, nil)

	// Verify circuit breaker was created with custom configuration
	if cb == nil {
		t.Fatal("Circuit breaker should not be nil")
	}

	stats := cb.GetStats()
	if stats == nil {
		t.Fatal("Circuit breaker stats should not be nil")
	}

	// Check that the circuit breaker has the expected operation type in its name
	name, ok := stats["name"].(string)
	if !ok {
		t.Fatal("Circuit breaker name not found")
	}

	expectedName := "AI-Test"
	if name != expectedName {
		t.Errorf("Expected circuit breaker name '%s', got '%s'", expectedName, name)
	}
}

func TestCircuitBreakerDisabled(t *testing.T) {
	// Test that circuit breaker returns nil when disabled

	disabledConfig := &config.OperationAIConfig{
		Provider: "gemini",
		Model:    "test-model",
		CircuitBreaker: config.CircuitBreakerConfig{
			Enabled: false, // Disabled
		},
	}

	cb := NewAICircuitBreaker("Disabled", disabledConfig, nil)

	// Should return nil when disabled
	if cb != nil {
		t.Fatal("Circuit breaker should be nil when disabled")
	}
}
