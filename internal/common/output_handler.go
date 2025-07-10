package common

import (
	"fmt"

	"resumatter/internal/errors"
	"resumatter/internal/formatters"
)

// CommandConfig holds common configuration for commands
type CommandConfig struct {
	OutputFile   string
	OutputFormat string
}

// OutputHandler handles formatting and writing output
type OutputHandler struct {
	fileProcessor *FileProcessor
	registry      *formatters.FormatterRegistry
	logger        *errors.Logger
}

// NewOutputHandler creates a new output handler
func NewOutputHandler(logger *errors.Logger) *OutputHandler {
	return &OutputHandler{
		fileProcessor: NewFileProcessor(logger),
		registry:      formatters.GlobalRegistry,
		logger:        logger,
	}
}

// HandleOutput formats data and writes it to the specified output
func (oh *OutputHandler) HandleOutput(data any, config CommandConfig) error {
	// Validate output file
	if err := oh.fileProcessor.ValidateOutputFile(config.OutputFile); err != nil {
		return err
	}

	// Format output using the registry
	output, err := oh.registry.Format(data, config.OutputFormat)
	if err != nil {
		return errors.NewValidationError(errors.ErrCodeInvalidFormat,
			fmt.Sprintf("Failed to format output as %s", config.OutputFormat), err)
	}

	// Write output
	if config.OutputFile != "" {
		err = oh.fileProcessor.WriteFile(config.OutputFile, output)
		if err != nil {
			return err // Error already wrapped by WriteFile
		}

		// Log success
		oh.logger.Info("Output written successfully",
			"file", config.OutputFile, "format", config.OutputFormat)
	} else {
		fmt.Print(output)
	}

	return nil
}

// GetSupportedFormats returns all supported output formats
func (oh *OutputHandler) GetSupportedFormats() []string {
	return oh.registry.GetSupportedFormats()
}
