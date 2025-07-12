package cli

import (
	"context"
	"fmt"

	"resumatter/internal/ai"
	"resumatter/internal/common"
	"resumatter/internal/types"

	"github.com/spf13/cobra"
)

var evaluateCmd = &cobra.Command{
	Use:   "evaluate [base-resume-file] [tailored-resume-file]",
	Short: "Evaluate a tailored resume for accuracy",
	Long: `Evaluate a tailored resume against the base resume to identify
potential fabrications, exaggerations, or incorrect attributions.
The command takes two arguments: the path to the base resume file and 
the path to the tailored resume file.`,
	Args: cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := getConfigFromContext(cmd.Context())
		if err != nil {
			return err
		}
		// Apply default format if not specified
		if evaluateConfig.OutputFormat == "" {
			evaluateConfig.OutputFormat = cfg.App.DefaultFormat
		}
		// Validate format against supported formats
		return common.ValidateOutputFormat(evaluateConfig.OutputFormat, cfg.App.SupportedFormats)
	},
	RunE: runEvaluate,
}

var evaluateConfig common.CommandConfig

func init() {
	evaluateCmd.Flags().StringVarP(&evaluateConfig.OutputFile, "output", "o", "", "Output file path (default: stdout)")
	evaluateCmd.Flags().StringVar(&evaluateConfig.OutputFormat, "format", "", "Output format: json, text, or markdown")

	// Add completion for format flag
	_ = evaluateCmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := getConfigFromContext(cmd.Context())
		if err != nil {
			return []string{}, cobra.ShellCompDirectiveError
		}
		return common.GetSupportedFormats(cfg.App.SupportedFormats), cobra.ShellCompDirectiveNoFileComp
	})
}

func runEvaluate(cmd *cobra.Command, args []string) error {
	cfg, err := getConfigFromContext(cmd.Context())
	if err != nil {
		return err
	}
	logger, err := getLoggerFromContext(cmd.Context())
	if err != nil {
		return err
	}

	// Create AI service for evaluate operation
	evaluateAIConfig := cfg.GetEvaluateConfig()
	aiService, err := ai.NewService(&evaluateAIConfig, "evaluate", logger)
	if err != nil {
		return fmt.Errorf("failed to create AI service: %w", err)
	}

	createInput := func(contents []string) (types.EvaluateResumeInput, error) {
		if len(contents) != 2 {
			return types.EvaluateResumeInput{}, fmt.Errorf("expected 2 file paths, got %d", len(contents))
		}
		return types.EvaluateResumeInput{
			BaseResume:     contents[0],
			TailoredResume: contents[1],
		}, nil
	}

	logDetails := func(input types.EvaluateResumeInput, cfg common.CommandConfig) {
		logger.Info("Starting resume evaluation",
			"base_resume_chars", len(input.BaseResume),
			"tailored_resume_chars", len(input.TailoredResume),
			"output_format", cfg.OutputFormat)
	}

	// Create a wrapper function that uses our specific AI service
	evaluateOperation := func(ctx context.Context, input types.EvaluateResumeInput) (types.EvaluateResumeOutput, *ai.TokenUsage, error) {
		return aiService.Provider.EvaluateResume(ctx, input)
	}

	err = common.RunAICommand(
		cmd.Context(),
		logger,
		evaluateConfig,
		args,
		createInput,
		evaluateOperation,
		logDetails,
	)

	if err != nil {
		return fmt.Errorf("failed to evaluate resume: %w", err)
	}
	logger.Info("Resume evaluation completed successfully")
	return nil
}
