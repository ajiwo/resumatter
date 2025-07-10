package formatters

import (
	"encoding/json"
	"fmt"
	"strings"

	"resumatter/internal/types"
)

// Formatter interface for different output formats
type Formatter interface {
	Format(data any) (string, error)
	SupportedType() string
}

// FormatterRegistry manages all available formatters
type FormatterRegistry struct {
	formatters map[string]map[string]Formatter // format -> type -> formatter
}

// NewFormatterRegistry creates a new formatter registry with default formatters
func NewFormatterRegistry() *FormatterRegistry {
	registry := &FormatterRegistry{
		formatters: make(map[string]map[string]Formatter),
	}

	// Register default formatters
	registry.RegisterFormatter("json", "any", &JSONFormatter{})
	registry.RegisterFormatter("text", "TailorResumeOutput", &TailorTextFormatter{})
	registry.RegisterFormatter("markdown", "TailorResumeOutput", &TailorMarkdownFormatter{})
	registry.RegisterFormatter("text", "EvaluateResumeOutput", &EvaluateTextFormatter{})
	registry.RegisterFormatter("markdown", "EvaluateResumeOutput", &EvaluateMarkdownFormatter{})
	registry.RegisterFormatter("text", "AnalyzeJobOutput", &AnalyzeJobTextFormatter{})
	registry.RegisterFormatter("markdown", "AnalyzeJobOutput", &AnalyzeJobMarkdownFormatter{})

	return registry
}

// RegisterFormatter registers a new formatter for a specific format and data type
func (fr *FormatterRegistry) RegisterFormatter(format, dataType string, formatter Formatter) {
	if fr.formatters[format] == nil {
		fr.formatters[format] = make(map[string]Formatter)
	}
	fr.formatters[format][dataType] = formatter
}

// Format formats data using the appropriate formatter
func (fr *FormatterRegistry) Format(data any, format string) (string, error) {
	dataType := getDataType(data)

	// Try specific formatter first
	if formatters, exists := fr.formatters[format]; exists {
		if formatter, exists := formatters[dataType]; exists {
			return formatter.Format(data)
		}
		// Fall back to generic formatter
		if formatter, exists := formatters["any"]; exists {
			return formatter.Format(data)
		}
	}

	return "", fmt.Errorf("no formatter found for format '%s' and type '%s'", format, dataType)
}

// GetSupportedFormats returns all supported formats
func (fr *FormatterRegistry) GetSupportedFormats() []string {
	formats := make([]string, 0, len(fr.formatters))
	for format := range fr.formatters {
		formats = append(formats, format)
	}
	return formats
}

func getDataType(data any) string {
	switch data.(type) {
	case types.TailorResumeOutput:
		return "TailorResumeOutput"
	case types.EvaluateResumeOutput:
		return "EvaluateResumeOutput"
	case types.AnalyzeJobOutput:
		return "AnalyzeJobOutput"
	default:
		return "any"
	}
}

// JSONFormatter handles JSON formatting for any data type
type JSONFormatter struct{}

func (jf *JSONFormatter) Format(data any) (string, error) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

func (jf *JSONFormatter) SupportedType() string {
	return "any"
}

// TailorTextFormatter handles text formatting for tailor results
type TailorTextFormatter struct{}

func (ttf *TailorTextFormatter) Format(data any) (string, error) {
	result, ok := data.(types.TailorResumeOutput)
	if !ok {
		return "", fmt.Errorf("expected TailorResumeOutput, got %T", data)
	}

	var output strings.Builder

	output.WriteString("=== TAILORED RESUME ===\n\n")
	output.WriteString(result.TailoredResume)
	output.WriteString("\n\n")

	output.WriteString("=== ATS ANALYSIS ===\n")
	output.WriteString(fmt.Sprintf("Score: %d/100\n\n", result.ATSAnalysis.Score))
	output.WriteString("Strengths:\n")
	output.WriteString(result.ATSAnalysis.Strengths)
	output.WriteString("\n\n")
	output.WriteString("Weaknesses:\n")
	output.WriteString(result.ATSAnalysis.Weaknesses)
	output.WriteString("\n\n")

	output.WriteString("=== JOB POSTING ANALYSIS ===\n")
	output.WriteString("Clarity:\n")
	output.WriteString(result.JobPostingAnalysis.Clarity)
	output.WriteString("\n\n")
	output.WriteString("Inclusivity:\n")
	output.WriteString(result.JobPostingAnalysis.Inclusivity)
	output.WriteString("\n\n")
	output.WriteString("Quality:\n")
	output.WriteString(result.JobPostingAnalysis.Quality)
	output.WriteString("\n")

	return output.String(), nil
}

func (ttf *TailorTextFormatter) SupportedType() string {
	return "TailorResumeOutput"
}

// TailorMarkdownFormatter handles markdown formatting for tailor results
type TailorMarkdownFormatter struct{}

func (tmf *TailorMarkdownFormatter) Format(data any) (string, error) {
	result, ok := data.(types.TailorResumeOutput)
	if !ok {
		return "", fmt.Errorf("expected TailorResumeOutput, got %T", data)
	}

	var output strings.Builder

	output.WriteString("# Tailored Resume\n\n")
	output.WriteString(result.TailoredResume)
	output.WriteString("\n\n")

	output.WriteString("## ATS Analysis\n\n")
	output.WriteString(fmt.Sprintf("**Score:** %d/100\n\n", result.ATSAnalysis.Score))
	output.WriteString("### Strengths\n")
	output.WriteString(result.ATSAnalysis.Strengths)
	output.WriteString("\n\n")
	output.WriteString("### Weaknesses\n")
	output.WriteString(result.ATSAnalysis.Weaknesses)
	output.WriteString("\n\n")

	output.WriteString("## Job Posting Analysis\n\n")
	output.WriteString("### Clarity\n")
	output.WriteString(result.JobPostingAnalysis.Clarity)
	output.WriteString("\n\n")
	output.WriteString("### Inclusivity\n")
	output.WriteString(result.JobPostingAnalysis.Inclusivity)
	output.WriteString("\n\n")
	output.WriteString("### Quality\n")
	output.WriteString(result.JobPostingAnalysis.Quality)
	output.WriteString("\n")

	return output.String(), nil
}

func (tmf *TailorMarkdownFormatter) SupportedType() string {
	return "TailorResumeOutput"
}

// EvaluateTextFormatter handles text formatting for evaluation results
type EvaluateTextFormatter struct{}

func (etf *EvaluateTextFormatter) Format(data any) (string, error) {
	result, ok := data.(types.EvaluateResumeOutput)
	if !ok {
		return "", fmt.Errorf("expected EvaluateResumeOutput, got %T", data)
	}

	var output strings.Builder

	output.WriteString("=== RESUME EVALUATION ===\n\n")
	output.WriteString("Summary:\n")
	output.WriteString(result.Summary)
	output.WriteString("\n\n")

	if len(result.Findings) > 0 {
		output.WriteString("=== FINDINGS ===\n\n")
		for i, finding := range result.Findings {
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, finding.Type))
			output.WriteString("   Description: ")
			output.WriteString(finding.Description)
			output.WriteString("\n")
			output.WriteString("   Evidence: ")
			output.WriteString(finding.Evidence)
			output.WriteString("\n\n")
		}
	} else {
		output.WriteString("No issues found.\n")
	}

	return output.String(), nil
}

func (etf *EvaluateTextFormatter) SupportedType() string {
	return "EvaluateResumeOutput"
}

// EvaluateMarkdownFormatter handles markdown formatting for evaluation results
type EvaluateMarkdownFormatter struct{}

func (emf *EvaluateMarkdownFormatter) Format(data any) (string, error) {
	result, ok := data.(types.EvaluateResumeOutput)
	if !ok {
		return "", fmt.Errorf("expected EvaluateResumeOutput, got %T", data)
	}

	var output strings.Builder

	output.WriteString("# Resume Evaluation\n\n")
	output.WriteString("## Summary\n\n")
	output.WriteString(result.Summary)
	output.WriteString("\n\n")

	if len(result.Findings) > 0 {
		output.WriteString("## Findings\n\n")
		for i, finding := range result.Findings {
			output.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, finding.Type))
			output.WriteString("**Description:** ")
			output.WriteString(finding.Description)
			output.WriteString("\n\n")
			output.WriteString("**Evidence:** ")
			output.WriteString(finding.Evidence)
			output.WriteString("\n\n")
		}
	} else {
		output.WriteString("## No Issues Found\n\nThe tailored resume appears to be accurate and truthful.\n")
	}

	return output.String(), nil
}

func (emf *EvaluateMarkdownFormatter) SupportedType() string {
	return "EvaluateResumeOutput"
}

// AnalyzeJobTextFormatter handles text formatting for job analysis results
type AnalyzeJobTextFormatter struct{}

func (ajf *AnalyzeJobTextFormatter) Format(data any) (string, error) {
	result, ok := data.(types.AnalyzeJobOutput)
	if !ok {
		return "", fmt.Errorf("expected AnalyzeJobOutput, got %T", data)
	}

	var output strings.Builder

	output.WriteString("=== JOB DESCRIPTION ANALYSIS ===\n\n")
	output.WriteString(fmt.Sprintf("Overall Job Quality Score: %d/100\n\n", result.JobQualityScore))

	output.WriteString("=== CLARITY ASSESSMENT ===\n")
	output.WriteString(fmt.Sprintf("Score: %d/100\n\n", result.Clarity.Score))
	output.WriteString("Analysis:\n")
	output.WriteString(result.Clarity.Analysis)
	output.WriteString("\n\n")
	if len(result.Clarity.Improvements) > 0 {
		output.WriteString("Improvements:\n")
		for _, improvement := range result.Clarity.Improvements {
			output.WriteString(fmt.Sprintf("- %s\n", improvement))
		}
		output.WriteString("\n")
	}

	output.WriteString("=== INCLUSIVITY ANALYSIS ===\n")
	output.WriteString(fmt.Sprintf("Score: %d/100\n\n", result.Inclusivity.Score))
	output.WriteString("Analysis:\n")
	output.WriteString(result.Inclusivity.Analysis)
	output.WriteString("\n\n")
	if len(result.Inclusivity.FlaggedTerms) > 0 {
		output.WriteString("Flagged Terms:\n")
		for _, term := range result.Inclusivity.FlaggedTerms {
			output.WriteString(fmt.Sprintf("- %s\n", term))
		}
		output.WriteString("\n")
	}
	if len(result.Inclusivity.Suggestions) > 0 {
		output.WriteString("Suggestions:\n")
		for _, suggestion := range result.Inclusivity.Suggestions {
			output.WriteString(fmt.Sprintf("- %s\n", suggestion))
		}
		output.WriteString("\n")
	}

	output.WriteString("=== CANDIDATE ATTRACTION ===\n")
	output.WriteString(fmt.Sprintf("Score: %d/100\n\n", result.CandidateAttraction.Score))
	if len(result.CandidateAttraction.Strengths) > 0 {
		output.WriteString("Strengths:\n")
		for _, strength := range result.CandidateAttraction.Strengths {
			output.WriteString(fmt.Sprintf("- %s\n", strength))
		}
		output.WriteString("\n")
	}
	if len(result.CandidateAttraction.Weaknesses) > 0 {
		output.WriteString("Weaknesses:\n")
		for _, weakness := range result.CandidateAttraction.Weaknesses {
			output.WriteString(fmt.Sprintf("- %s\n", weakness))
		}
		output.WriteString("\n")
	}

	output.WriteString("=== MARKET COMPETITIVENESS ===\n")
	output.WriteString("Salary Transparency:\n")
	output.WriteString(result.MarketCompetitiveness.SalaryTransparency)
	output.WriteString("\n\n")
	output.WriteString("Requirements Realism:\n")
	output.WriteString(result.MarketCompetitiveness.RequirementsRealism)
	output.WriteString("\n\n")
	output.WriteString("Industry Alignment:\n")
	output.WriteString(result.MarketCompetitiveness.IndustryAlignment)
	output.WriteString("\n\n")

	if len(result.Recommendations) > 0 {
		output.WriteString("=== TOP RECOMMENDATIONS ===\n")
		for i, recommendation := range result.Recommendations {
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, recommendation))
		}
	}

	return output.String(), nil
}

func (ajf *AnalyzeJobTextFormatter) SupportedType() string {
	return "AnalyzeJobOutput"
}

// AnalyzeJobMarkdownFormatter handles markdown formatting for job analysis results
type AnalyzeJobMarkdownFormatter struct{}

func (ajmf *AnalyzeJobMarkdownFormatter) Format(data any) (string, error) {
	result, ok := data.(types.AnalyzeJobOutput)
	if !ok {
		return "", fmt.Errorf("expected AnalyzeJobOutput, got %T", data)
	}

	var output strings.Builder

	output.WriteString("# Job Description Analysis\n\n")
	output.WriteString(fmt.Sprintf("**Overall Job Quality Score:** %d/100\n\n", result.JobQualityScore))

	output.WriteString("## Clarity Assessment\n\n")
	output.WriteString(fmt.Sprintf("**Score:** %d/100\n\n", result.Clarity.Score))
	output.WriteString("### Analysis\n")
	output.WriteString(result.Clarity.Analysis)
	output.WriteString("\n\n")
	if len(result.Clarity.Improvements) > 0 {
		output.WriteString("### Improvements\n")
		for _, improvement := range result.Clarity.Improvements {
			output.WriteString(fmt.Sprintf("- %s\n", improvement))
		}
		output.WriteString("\n")
	}

	output.WriteString("## Inclusivity Analysis\n\n")
	output.WriteString(fmt.Sprintf("**Score:** %d/100\n\n", result.Inclusivity.Score))
	output.WriteString("### Analysis\n")
	output.WriteString(result.Inclusivity.Analysis)
	output.WriteString("\n\n")
	if len(result.Inclusivity.FlaggedTerms) > 0 {
		output.WriteString("### Flagged Terms\n")
		for _, term := range result.Inclusivity.FlaggedTerms {
			output.WriteString(fmt.Sprintf("- %s\n", term))
		}
		output.WriteString("\n")
	}
	if len(result.Inclusivity.Suggestions) > 0 {
		output.WriteString("### Suggestions\n")
		for _, suggestion := range result.Inclusivity.Suggestions {
			output.WriteString(fmt.Sprintf("- %s\n", suggestion))
		}
		output.WriteString("\n")
	}

	output.WriteString("## Candidate Attraction\n\n")
	output.WriteString(fmt.Sprintf("**Score:** %d/100\n\n", result.CandidateAttraction.Score))
	if len(result.CandidateAttraction.Strengths) > 0 {
		output.WriteString("### Strengths\n")
		for _, strength := range result.CandidateAttraction.Strengths {
			output.WriteString(fmt.Sprintf("- %s\n", strength))
		}
		output.WriteString("\n")
	}
	if len(result.CandidateAttraction.Weaknesses) > 0 {
		output.WriteString("### Weaknesses\n")
		for _, weakness := range result.CandidateAttraction.Weaknesses {
			output.WriteString(fmt.Sprintf("- %s\n", weakness))
		}
		output.WriteString("\n")
	}

	output.WriteString("## Market Competitiveness\n\n")
	output.WriteString("### Salary Transparency\n")
	output.WriteString(result.MarketCompetitiveness.SalaryTransparency)
	output.WriteString("\n\n")
	output.WriteString("### Requirements Realism\n")
	output.WriteString(result.MarketCompetitiveness.RequirementsRealism)
	output.WriteString("\n\n")
	output.WriteString("### Industry Alignment\n")
	output.WriteString(result.MarketCompetitiveness.IndustryAlignment)
	output.WriteString("\n\n")

	if len(result.Recommendations) > 0 {
		output.WriteString("## Top Recommendations\n\n")
		for i, recommendation := range result.Recommendations {
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, recommendation))
		}
	}

	return output.String(), nil
}

func (ajmf *AnalyzeJobMarkdownFormatter) SupportedType() string {
	return "AnalyzeJobOutput"
}

// Global formatter registry
var GlobalRegistry = NewFormatterRegistry()
