package cli

import (
	"context"

	"resumatter/internal/config"
	"resumatter/internal/errors"

	"github.com/spf13/cobra"
)

// Define custom private types for context keys.
type configKeyType struct{}
type loggerKeyType struct{}

// Use variables of these types as the keys.
var configKey = configKeyType{}
var loggerKey = loggerKeyType{}

var rootCmd = &cobra.Command{
	Use:   "resumatter",
	Short: "A CLI tool for tailoring resumes using AI",
	Long: `Resumatter is a command-line tool that helps you tailor your resume
for specific job descriptions using AI. It can also evaluate tailored resumes
for accuracy and potential issues.`,
}

func Execute(ctx context.Context, cfg *config.Config, logger *errors.Logger) error {
	// Attach the config and logger to the context, making them available to all subcommands
	ctx = context.WithValue(ctx, configKey, cfg)
	ctx = context.WithValue(ctx, loggerKey, logger)
	rootCmd.SetContext(ctx)
	return rootCmd.Execute()
}

// getConfigFromContext is a helper function to get config from context
func getConfigFromContext(ctx context.Context) *config.Config {
	if cfg, ok := ctx.Value(configKey).(*config.Config); ok {
		return cfg
	}
	panic("config not found in context") // Should not happen if properly initialized
}

// getLoggerFromContext is a helper function to get logger from context
func getLoggerFromContext(ctx context.Context) *errors.Logger {
	if logger, ok := ctx.Value(loggerKey).(*errors.Logger); ok {
		return logger
	}
	panic("logger not found in context") // Should not happen if properly initialized
}

func init() {
	rootCmd.AddCommand(tailorCmd)
	rootCmd.AddCommand(evaluateCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(serveCmd)
}
