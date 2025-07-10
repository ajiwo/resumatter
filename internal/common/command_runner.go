package common

import (
	"context"
	"fmt"
	"os"

	"resumatter/internal/ai"
	"resumatter/internal/errors"
)

// CommandConfig is assumed to be defined elsewhere in the common package.

// CreateInputFunc defines how to create the specific AI input from file contents.
type CreateInputFunc[Input any] func(contents []string) (Input, error)

// LogDetailsFunc defines how to log the start of an operation.
type LogDetailsFunc[Input any] func(input Input, cfg CommandConfig)

// AIOperationFunc is a generic function signature for any AI operation with context and token usage.
type AIOperationFunc[Input, Output any] func(context.Context, Input) (Output, *ai.TokenUsage, error)

// RunAICommand encapsulates the common logic for file-based CLI commands with token usage reporting.
func RunAICommand[Input, Output any](
	ctx context.Context,
	logger *errors.Logger,
	cmdConfig CommandConfig,
	args []string,
	createInput CreateInputFunc[Input],
	aiOperation AIOperationFunc[Input, Output],
	logDetails LogDetailsFunc[Input],
) error {
	// Pass the logger when creating helpers
	fileProcessor := NewFileProcessor(logger)
	outputHandler := NewOutputHandler(logger)

	contents, err := fileProcessor.ValidateAndReadFiles(args...)
	if err != nil {
		return err
	}

	input, err := createInput(contents)
	if err != nil {
		return fmt.Errorf("failed to create input from file contents: %w", err)
	}

	logDetails(input, cmdConfig)

	result, tokenUsage, err := aiOperation(ctx, input)
	if err != nil {
		return err
	}

	// Report token usage
	if tokenUsage != nil {
		if logger != nil {
			logger.Info("AI token usage", "input_tokens", tokenUsage.InputTokens, "output_tokens", tokenUsage.OutputTokens, "total_tokens", tokenUsage.TotalTokens)
		} else {
			fmt.Fprintf(os.Stderr, "AI token usage: input=%d, output=%d, total=%d\n", tokenUsage.InputTokens, tokenUsage.OutputTokens, tokenUsage.TotalTokens)
		}
	}

	return outputHandler.HandleOutput(result, cmdConfig)
}
