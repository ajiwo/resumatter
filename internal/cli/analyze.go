package cli

import (
	"context"
	"fmt"

	"resumatter/internal/ai"
	"resumatter/internal/common"
	"resumatter/internal/types"

	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze [job-description-file]",
	Short: "Analyze a job description for quality and effectiveness",
	Long: `Analyze a job description to evaluate its quality, inclusivity, clarity,
and effectiveness in attracting qualified candidates. This tool is designed for
HR managers and recruiters to optimize their job postings.

The analysis includes:
- Job quality scoring and recommendations
- Clarity and readability assessment
- Inclusivity and bias detection
- Candidate attraction optimization
- Market competitiveness evaluation`,
	Args: cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := getConfigFromContext(cmd.Context())
		if err != nil {
			return err
		}
		// Apply default format if not specified
		if analyzeConfig.OutputFormat == "" {
			analyzeConfig.OutputFormat = cfg.App.DefaultFormat
		}
		// Validate format against supported formats
		return common.ValidateOutputFormat(analyzeConfig.OutputFormat, cfg.App.SupportedFormats)
	},
	RunE: runAnalyze,
}

var analyzeConfig common.CommandConfig

func init() {
	analyzeCmd.Flags().StringVarP(&analyzeConfig.OutputFile, "output", "o", "", "Output file path (default: stdout)")
	analyzeCmd.Flags().StringVar(&analyzeConfig.OutputFormat, "format", "", "Output format: json, text, or markdown")

	// Add completion for format flag
	_ = analyzeCmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := getConfigFromContext(cmd.Context())
		if err != nil {
			return []string{}, cobra.ShellCompDirectiveError
		}
		return common.GetSupportedFormats(cfg.App.SupportedFormats), cobra.ShellCompDirectiveNoFileComp
	})
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	cfg, err := getConfigFromContext(cmd.Context())
	if err != nil {
		return err
	}
	logger, err := getLoggerFromContext(cmd.Context())
	if err != nil {
		return err
	}

	// Create AI service for analyze operation
	analyzeAIConfig := cfg.GetAnalyzeConfig()
	aiService, err := ai.NewService(&analyzeAIConfig, "analyze", logger)
	if err != nil {
		return fmt.Errorf("failed to create AI service: %w", err)
	}

	createInput := func(contents []string) (types.AnalyzeJobInput, error) {
		if len(contents) != 1 {
			return types.AnalyzeJobInput{}, fmt.Errorf("expected 1 file path, got %d", len(contents))
		}
		return types.AnalyzeJobInput{
			JobDescription: contents[0],
		}, nil
	}

	logDetails := func(input types.AnalyzeJobInput, cfg common.CommandConfig) {
		logger.Info("Starting job description analysis",
			"job_chars", len(input.JobDescription),
			"output_format", cfg.OutputFormat)
	}

	// Create a wrapper function that uses our specific AI service
	analyzeOperation := func(ctx context.Context, input types.AnalyzeJobInput) (types.AnalyzeJobOutput, *ai.TokenUsage, error) {
		return aiService.Provider.AnalyzeJob(ctx, input)
	}

	err = common.RunAICommand(
		cmd.Context(),
		logger,
		analyzeConfig,
		args,
		createInput,
		analyzeOperation,
		logDetails,
	)

	if err != nil {
		return fmt.Errorf("failed to analyze job description: %w", err)
	}
	logger.Info("Job description analysis completed successfully")
	return nil
}
