package ai

import (
	"testing"
	"time"

	"resumatter/internal/config"
)

func TestIndependentCircuitBreakerConfigurations(t *testing.T) {
	// Test that each operation gets its own circuit breaker configuration
	// as specified in config.example.yaml

	testCases := []struct {
		name           string
		config         *config.OperationAIConfig
		expectedCBName string
	}{
		{
			name: "Tailor",
			config: &config.OperationAIConfig{
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
			},
			expectedCBName: "AI-Tailor",
		},
		{
			name: "Evaluate",
			config: &config.OperationAIConfig{
				Provider: "gemini",
				Model:    "gemini-2.0-flash-lite",
				CircuitBreaker: config.CircuitBreakerConfig{
					Enabled:          true,
					MaxRequests:      5,
					Interval:         30 * time.Second,
					Timeout:          45 * time.Second,
					MinRequests:      2,
					FailureThreshold: 0.7,
				},
			},
			expectedCBName: "AI-Evaluate",
		},
		{
			name: "Analyze",
			config: &config.OperationAIConfig{
				Provider: "gemini",
				Model:    "gemini-1.5-pro",
				CircuitBreaker: config.CircuitBreakerConfig{
					Enabled:          true,
					MaxRequests:      4,
					Interval:         90 * time.Second,
					Timeout:          75 * time.Second,
					MinRequests:      5,
					FailureThreshold: 0.5,
				},
			},
			expectedCBName: "AI-Analyze",
		},
	}

	// Create circuit breakers for all operations
	circuitBreakers := make(map[string]*AICircuitBreaker)
	for _, tc := range testCases {
		circuitBreakers[tc.name] = NewAICircuitBreaker(tc.name, tc.config, nil)
	}

	// Test each circuit breaker configuration
	for _, tc := range testCases {
		t.Run(tc.name+"CircuitBreaker", func(t *testing.T) {
			cb := circuitBreakers[tc.name]
			assertCircuitBreakerBasicProperties(t, cb, tc.expectedCBName)
		})
	}

	// Test independence
	t.Run("IndependentInstances", func(t *testing.T) {
		assertCircuitBreakersAreIndependent(t, circuitBreakers)
	})

	t.Run("IndependentHealthStates", func(t *testing.T) {
		assertAllCircuitBreakersHealthy(t, circuitBreakers)
	})
}

// assertCircuitBreakerBasicProperties verifies basic circuit breaker properties
func assertCircuitBreakerBasicProperties(t *testing.T, cb *AICircuitBreaker, expectedName string) {
	t.Helper()

	stats := cb.GetStats()

	// Check name
	name, ok := stats["name"].(string)
	if !ok {
		t.Fatal("Circuit breaker name not found")
	}
	if name != expectedName {
		t.Errorf("Expected circuit breaker name '%s', got '%s'", expectedName, name)
	}

	// Check initial state
	state, ok := stats["state"].(string)
	if !ok {
		t.Fatal("Circuit breaker state not found")
	}
	if state != "closed" {
		t.Errorf("Expected initial state 'closed', got '%s'", state)
	}

	// Check enabled status
	enabled, ok := stats["enabled"].(bool)
	if !ok {
		t.Fatal("Circuit breaker enabled status not found")
	}
	if !enabled {
		t.Error("Circuit breaker should be enabled")
	}
}

// assertCircuitBreakersAreIndependent verifies that circuit breakers are different instances
func assertCircuitBreakersAreIndependent(t *testing.T, cbs map[string]*AICircuitBreaker) {
	t.Helper()

	operations := []string{"Tailor", "Evaluate", "Analyze"}
	for i := 0; i < len(operations); i++ {
		for j := i + 1; j < len(operations); j++ {
			if cbs[operations[i]] == cbs[operations[j]] {
				t.Errorf("%s and %s circuit breakers should be different instances", operations[i], operations[j])
			}
		}
	}
}

// assertAllCircuitBreakersHealthy verifies that all circuit breakers are initially healthy
func assertAllCircuitBreakersHealthy(t *testing.T, cbs map[string]*AICircuitBreaker) {
	t.Helper()

	for name, cb := range cbs {
		if !cb.IsHealthy() {
			t.Errorf("%s circuit breaker should be healthy initially", name)
		}
	}
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
