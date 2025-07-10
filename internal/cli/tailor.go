package cli

import (
	"context"
	"fmt"

	"resumatter/internal/ai"
	"resumatter/internal/common"
	"resumatter/internal/types"

	"github.com/spf13/cobra"
)

var tailorCmd = &cobra.Command{
	Use:   "tailor [resume-file] [job-description-file]",
	Short: "Tailor a resume for a specific job description",
	Long: `Tailor your resume for a specific job description using AI.
The command takes two arguments: the path to your base resume file and 
the path to the job description file. Both files should be in plain text format.`,
	Args: cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		cfg := getConfigFromContext(cmd.Context())
		// Apply default format if not specified
		if tailorConfig.OutputFormat == "" {
			tailorConfig.OutputFormat = cfg.App.DefaultFormat
		}
		// Validate format against supported formats
		return common.ValidateOutputFormat(tailorConfig.OutputFormat, cfg.App.SupportedFormats)
	},
	RunE: runTailor,
}

var tailorConfig common.CommandConfig

func init() {
	tailorCmd.Flags().StringVarP(&tailorConfig.OutputFile, "output", "o", "", "Output file path (default: stdout)")
	tailorCmd.Flags().StringVar(&tailorConfig.OutputFormat, "format", "", "Output format: json, text, or markdown")

	// Add completion for format flag
	_ = tailorCmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg := getConfigFromContext(cmd.Context())
		return common.GetSupportedFormats(cfg.App.SupportedFormats), cobra.ShellCompDirectiveNoFileComp
	})
}

func runTailor(cmd *cobra.Command, args []string) error {
	cfg := getConfigFromContext(cmd.Context())
	logger := getLoggerFromContext(cmd.Context())

	// Create AI service for tailor operation
	tailorAIConfig := cfg.GetTailorConfig()
	aiService, err := ai.NewService(&tailorAIConfig, "tailor", logger)
	if err != nil {
		return fmt.Errorf("failed to create AI service: %w", err)
	}

	createInput := func(contents []string) (types.TailorResumeInput, error) {
		if len(contents) != 2 {
			return types.TailorResumeInput{}, fmt.Errorf("expected 2 file paths, got %d", len(contents))
		}
		return types.TailorResumeInput{
			BaseResume:     contents[0],
			JobDescription: contents[1],
		}, nil
	}

	logDetails := func(input types.TailorResumeInput, cfg common.CommandConfig) {
		logger.Info("Starting resume tailoring",
			"resume_chars", len(input.BaseResume),
			"job_chars", len(input.JobDescription),
			"output_format", cfg.OutputFormat)
	}

	// Create a wrapper function that uses our specific AI service
	tailorOperation := func(ctx context.Context, input types.TailorResumeInput) (types.TailorResumeOutput, *ai.TokenUsage, error) {
		return aiService.Provider.TailorResume(ctx, input)
	}

	err = common.RunAICommand(
		cmd.Context(),
		logger,
		tailorConfig,
		args,
		createInput,
		tailorOperation,
		logDetails,
	)

	if err != nil {
		return fmt.Errorf("failed to tailor resume: %w", err)
	}
	logger.Info("Resume tailoring completed successfully")
	return nil
}
