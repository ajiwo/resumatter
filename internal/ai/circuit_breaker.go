package ai

import (
	"fmt"

	"resumatter/internal/config"
	"resumatter/internal/errors"

	"github.com/sony/gobreaker/v2"
	"google.golang.org/genai"
)

// AICircuitBreaker wraps AI operations with circuit breaker pattern
// Now focused on a single operation type
type AICircuitBreaker struct {
	cb *gobreaker.CircuitBreaker[*genai.GenerateContentResponse]
}

// ModelCircuitBreaker wraps model info operations with circuit breaker pattern
type ModelCircuitBreaker struct {
	cb *gobreaker.CircuitBreaker[*genai.Model]
}

// NewAICircuitBreaker creates a circuit breaker configured for a specific operation type
func NewAICircuitBreaker(operationType string, cfg *config.OperationAIConfig, logger *errors.Logger) *AICircuitBreaker {
	// If circuit breaker is disabled, return nil to indicate no circuit breaker
	if !cfg.CircuitBreaker.Enabled {
		return nil
	}

	settings := gobreaker.Settings{
		Name:        fmt.Sprintf("AI-%s", operationType),
		MaxRequests: cfg.CircuitBreaker.MaxRequests,
		Interval:    cfg.CircuitBreaker.Interval,
		Timeout:     cfg.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= cfg.CircuitBreaker.MinRequests &&
				failureRatio >= cfg.CircuitBreaker.FailureThreshold
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				"name", name,
				"operation_type", operationType,
				"from", from.String(),
				"to", to.String(),
				"max_requests", cfg.CircuitBreaker.MaxRequests,
				"failure_threshold", cfg.CircuitBreaker.FailureThreshold)
		},
	}

	return &AICircuitBreaker{
		cb: gobreaker.NewCircuitBreaker[*genai.GenerateContentResponse](settings),
	}
}

// NewModelCircuitBreaker creates a model circuit breaker configured for a specific operation type
func NewModelCircuitBreaker(operationType string, cfg *config.OperationAIConfig, logger *errors.Logger) *ModelCircuitBreaker {
	// If circuit breaker is disabled, return nil to indicate no circuit breaker
	if !cfg.CircuitBreaker.Enabled {
		return nil
	}

	settings := gobreaker.Settings{
		Name:        fmt.Sprintf("AI-Model-%s", operationType),
		MaxRequests: cfg.CircuitBreaker.MaxRequests,
		Interval:    cfg.CircuitBreaker.Interval,
		Timeout:     cfg.CircuitBreaker.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			// Model info is less critical, so use more lenient settings
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 5 && failureRatio >= 0.8
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			logger.Info("Circuit breaker state changed",
				"name", name,
				"operation_type", operationType,
				"from", from.String(),
				"to", to.String(),
				"max_requests", cfg.CircuitBreaker.MaxRequests)
		},
	}

	return &ModelCircuitBreaker{
		cb: gobreaker.NewCircuitBreaker[*genai.Model](settings),
	}
}

// Execute executes the provided function with circuit breaker protection
func (cb *AICircuitBreaker) Execute(fn func() (*genai.GenerateContentResponse, error)) (*genai.GenerateContentResponse, error) {
	if cb == nil || cb.cb == nil {
		// If breaker is disabled/nil, just execute the function directly
		return fn()
	}
	return cb.cb.Execute(fn)
}

// ExecuteModel executes the provided model function with circuit breaker protection
func (cb *ModelCircuitBreaker) ExecuteModel(fn func() (*genai.Model, error)) (*genai.Model, error) {
	if cb == nil || cb.cb == nil {
		// If breaker is disabled/nil, just execute the function directly
		return fn()
	}
	return cb.cb.Execute(fn)
}

// GetStats returns circuit breaker statistics
func (cb *AICircuitBreaker) GetStats() map[string]any {
	if cb == nil || cb.cb == nil {
		return map[string]any{
			"enabled": false,
		}
	}

	return map[string]any{
		"name":    cb.cb.Name(),
		"state":   cb.cb.State().String(),
		"counts":  cb.cb.Counts(),
		"enabled": true,
	}
}

// GetModelStats returns model circuit breaker statistics
func (cb *ModelCircuitBreaker) GetModelStats() map[string]any {
	if cb == nil || cb.cb == nil {
		return map[string]any{
			"enabled": false,
		}
	}

	return map[string]any{
		"name":    cb.cb.Name(),
		"state":   cb.cb.State().String(),
		"counts":  cb.cb.Counts(),
		"enabled": true,
	}
}

// IsHealthy returns true if the circuit breaker is in closed state
func (cb *AICircuitBreaker) IsHealthy() bool {
	if cb == nil || cb.cb == nil {
		return true // If no circuit breaker, consider it healthy
	}
	return cb.cb.State() == gobreaker.StateClosed
}

// IsModelHealthy returns true if the model circuit breaker is in closed state
func (cb *ModelCircuitBreaker) IsModelHealthy() bool {
	if cb == nil || cb.cb == nil {
		return true // If no circuit breaker, consider it healthy
	}
	return cb.cb.State() == gobreaker.StateClosed
}
