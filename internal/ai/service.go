package ai

import (
	"context"
	"fmt"

	"resumatter/internal/config"
	"resumatter/internal/errors"
)

// Service handles AI operations for resume processing
type Service struct {
	Provider AIProvider // Exported for access from server package
	config   *config.OperationAIConfig
	logger   *errors.Logger
}

// NewService creates a new AI service instance with configuration for a specific operation
func NewService(cfg *config.OperationAIConfig, operationType string, logger *errors.Logger) (*Service, error) {
	var provider AIProvider
	var err error

	// Debug logging for service initialization
	logger.Debug("Initializing AI service",
		"provider", cfg.Provider,
		"operation_type", operationType,
		"model", cfg.Model,
		"temperature", *cfg.Temperature,
		"timeout", *cfg.Timeout,
		"max_retries", *cfg.MaxRetries,
		"use_system_prompts", *cfg.UseSystemPrompts)

	switch cfg.Provider {
	case "gemini":
		provider, err = NewGeminiProvider(cfg, operationType, logger)
	default:
		return nil, errors.NewConfigError(errors.ErrCodeInvalidConfig,
			fmt.Sprintf("Unsupported AI provider: %s", cfg.Provider), nil)
	}

	if err != nil {
		return nil, errors.NewAIError(errors.ErrCodeAIServiceFailed,
			"Failed to create AI provider", err)
	}

	return &Service{
		Provider: provider,
		config:   cfg,
		logger:   logger,
	}, nil
}

// GetModelInfo returns information about the AI model for health checks
func (s *Service) GetModelInfo(ctx context.Context) any {
	return s.Provider.GetModelInfo(ctx)
}
