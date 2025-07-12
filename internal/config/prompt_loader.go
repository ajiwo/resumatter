package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// PromptSource represents where a prompt was loaded from
type PromptSource struct {
	Source    string // "file", "operation-config", "global-config", or "default"
	FilePath  string // Set if Source is "file"
	Operation string // The operation this prompt is for
	Type      string // "system" or "user"
}

// GetLoadedPrompts returns the loaded prompt content in a thread-safe way
func GetLoadedPrompts() *AllLoadedPrompts {
	return &loadedPrompts
}

// trackPromptSource tracks the source of a prompt for debugging
func (c *Config) trackPromptSource(source PromptSource) {
	// Prompt source tracking can be implemented when new logging is hooked up
}

// loadPromptsFromFiles loads custom prompts from external files if file paths are specified
func (c *Config) loadPromptsFromFiles() error {
	log.Println("[CONFIG] Starting custom prompt loading from files")

	// Initialize loaded prompts exactly once
	loadedPromptsOnce.Do(func() {
		loadedPrompts = AllLoadedPrompts{}
	})

	// Load global prompts
	if err := c.loadSystemPromptsFromFiles(&c.AI.CustomPrompts.SystemPrompts, &loadedPrompts.Global.SystemPrompts); err != nil {
		return fmt.Errorf("failed to load global system prompts: %w", err)
	}
	if err := c.loadUserPromptsFromFiles(&c.AI.CustomPrompts.UserPrompts, &loadedPrompts.Global.UserPrompts); err != nil {
		return fmt.Errorf("failed to load global user prompts: %w", err)
	}

	// Load operation-specific prompts
	if err := c.loadSystemPromptsFromFiles(&c.AI.Tailor.CustomPrompts.SystemPrompts, &loadedPrompts.Tailor.SystemPrompts); err != nil {
		return fmt.Errorf("failed to load tailor system prompts: %w", err)
	}
	if err := c.loadUserPromptsFromFiles(&c.AI.Tailor.CustomPrompts.UserPrompts, &loadedPrompts.Tailor.UserPrompts); err != nil {
		return fmt.Errorf("failed to load tailor user prompts: %w", err)
	}

	if err := c.loadSystemPromptsFromFiles(&c.AI.Evaluate.CustomPrompts.SystemPrompts, &loadedPrompts.Evaluate.SystemPrompts); err != nil {
		return fmt.Errorf("failed to load evaluate system prompts: %w", err)
	}
	if err := c.loadUserPromptsFromFiles(&c.AI.Evaluate.CustomPrompts.UserPrompts, &loadedPrompts.Evaluate.UserPrompts); err != nil {
		return fmt.Errorf("failed to load evaluate user prompts: %w", err)
	}

	if err := c.loadSystemPromptsFromFiles(&c.AI.Analyze.CustomPrompts.SystemPrompts, &loadedPrompts.Analyze.SystemPrompts); err != nil {
		return fmt.Errorf("failed to load analyze system prompts: %w", err)
	}
	if err := c.loadUserPromptsFromFiles(&c.AI.Analyze.CustomPrompts.UserPrompts, &loadedPrompts.Analyze.UserPrompts); err != nil {
		return fmt.Errorf("failed to load analyze user prompts: %w", err)
	}

	// Log summary of prompt sources after loading
	c.logPromptLoadingSummary()

	return nil
}

// loadSystemPromptsFromFiles loads system prompts from files if file paths are specified
func (c *Config) loadSystemPromptsFromFiles(prompts *SystemPrompts, target *LoadedSystemPrompts) error {
	// Load TailorResume prompt from file if specified
	if prompts.TailorResumeFile != "" {
		content, err := c.loadPromptFromFile(prompts.TailorResumeFile, "system", "tailorResume")
		if err != nil {
			return err
		}
		target.TailorResume = content
	}

	// Load EvaluateResume prompt from file if specified
	if prompts.EvaluateResumeFile != "" {
		content, err := c.loadPromptFromFile(prompts.EvaluateResumeFile, "system", "evaluateResume")
		if err != nil {
			return err
		}
		target.EvaluateResume = content
	}

	// Load AnalyzeJob prompt from file if specified
	if prompts.AnalyzeJobFile != "" {
		content, err := c.loadPromptFromFile(prompts.AnalyzeJobFile, "system", "analyzeJob")
		if err != nil {
			return err
		}
		target.AnalyzeJob = content
	}

	return nil
}

// loadUserPromptsFromFiles loads user prompts from files if file paths are specified
func (c *Config) loadUserPromptsFromFiles(prompts *UserPrompts, target *LoadedUserPrompts) error {
	// Load TailorResume prompt from file if specified
	if prompts.TailorResumeFile != "" {
		content, err := c.loadPromptFromFile(prompts.TailorResumeFile, "user", "tailorResume")
		if err != nil {
			return err
		}
		target.TailorResume = content
	}

	// Load EvaluateResume prompt from file if specified
	if prompts.EvaluateResumeFile != "" {
		content, err := c.loadPromptFromFile(prompts.EvaluateResumeFile, "user", "evaluateResume")
		if err != nil {
			return err
		}
		target.EvaluateResume = content
	}

	// Load AnalyzeJob prompt from file if specified
	if prompts.AnalyzeJobFile != "" {
		content, err := c.loadPromptFromFile(prompts.AnalyzeJobFile, "user", "analyzeJob")
		if err != nil {
			return err
		}
		target.AnalyzeJob = content
	}

	return nil
}

// loadPromptFromFile loads a prompt from a file with proper error handling and logging
func (c *Config) loadPromptFromFile(filePath, promptType, operation string) (string, error) {
	// Track prompt source
	c.trackPromptSource(PromptSource{
		Source:    "file",
		FilePath:  filePath,
		Operation: operation,
		Type:      promptType,
	})

	// Resolve relative paths
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path for %s %s prompt file '%s': %w", promptType, operation, filePath, err)
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("%s %s prompt file not found: %s", promptType, operation, absPath)
	}

	// Read file content
	content, err := os.ReadFile(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s %s prompt file '%s': %w", promptType, operation, absPath, err)
	}

	// Validate content is not empty
	trimmedContent := strings.TrimSpace(string(content))
	if trimmedContent == "" {
		return "", fmt.Errorf("%s %s prompt file '%s' is empty", promptType, operation, absPath)
	}

	// Log successful loading
	log.Printf("[CONFIG] Successfully loaded %s %s prompt from file: %s (%d characters)",
		promptType, operation, absPath, len(trimmedContent))

	return trimmedContent, nil
}

// validatePromptFiles validates that prompt files exist and are readable before loading
func (c *Config) validatePromptFiles() error {
	var validationErrors []string

	// Helper function to validate a file path
	validateFile := func(filePath, promptType, operation string) {
		if filePath == "" {
			return // No file specified, skip validation
		}

		absPath, err := filepath.Abs(filePath)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("invalid path for %s %s prompt: %s", promptType, operation, filePath))
			return
		}

		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			validationErrors = append(validationErrors, fmt.Sprintf("%s %s prompt file not found: %s", promptType, operation, absPath))
		}
	}

	// Validate global prompt files
	validateFile(c.AI.CustomPrompts.SystemPrompts.TailorResumeFile, "system", "tailorResume")
	validateFile(c.AI.CustomPrompts.SystemPrompts.EvaluateResumeFile, "system", "evaluateResume")
	validateFile(c.AI.CustomPrompts.SystemPrompts.AnalyzeJobFile, "system", "analyzeJob")
	validateFile(c.AI.CustomPrompts.UserPrompts.TailorResumeFile, "user", "tailorResume")
	validateFile(c.AI.CustomPrompts.UserPrompts.EvaluateResumeFile, "user", "evaluateResume")
	validateFile(c.AI.CustomPrompts.UserPrompts.AnalyzeJobFile, "user", "analyzeJob")

	// Validate operation-specific prompt files
	validateFile(c.AI.Tailor.CustomPrompts.SystemPrompts.TailorResumeFile, "tailor system", "tailorResume")
	validateFile(c.AI.Tailor.CustomPrompts.UserPrompts.TailorResumeFile, "tailor user", "tailorResume")
	validateFile(c.AI.Evaluate.CustomPrompts.SystemPrompts.EvaluateResumeFile, "evaluate system", "evaluateResume")
	validateFile(c.AI.Evaluate.CustomPrompts.UserPrompts.EvaluateResumeFile, "evaluate user", "evaluateResume")
	validateFile(c.AI.Analyze.CustomPrompts.SystemPrompts.AnalyzeJobFile, "analyze system", "analyzeJob")
	validateFile(c.AI.Analyze.CustomPrompts.UserPrompts.AnalyzeJobFile, "analyze user", "analyzeJob")

	if len(validationErrors) > 0 {
		return fmt.Errorf("prompt file validation failed:\n%s", strings.Join(validationErrors, "\n"))
	}

	return nil
}

// logPromptLoadingSummary logs a summary of loaded prompts
func (c *Config) logPromptLoadingSummary() {
	log.Println("[CONFIG] === Custom Prompt Loading Summary ===")

	promptCount := c.countAndLogLoadedPrompts()

	c.logPromptSummaryFooter(promptCount)
}

// countAndLogLoadedPrompts counts and logs all loaded prompts, returning the total count
func (c *Config) countAndLogLoadedPrompts() int {
	promptCount := 0

	// Check global prompts
	promptCount += c.logGlobalPrompts()

	// Check operation-specific prompts
	promptCount += c.logOperationSpecificPrompts()

	return promptCount
}

// logGlobalPrompts logs global prompt status and returns count
func (c *Config) logGlobalPrompts() int {
	count := 0

	promptChecks := []struct {
		content string
		message string
	}{
		{loadedPrompts.Global.SystemPrompts.TailorResume, "[CONFIG] Global system tailor prompt: loaded from config/file"},
		{loadedPrompts.Global.SystemPrompts.EvaluateResume, "[CONFIG] Global system evaluate prompt: loaded from config/file"},
		{loadedPrompts.Global.SystemPrompts.AnalyzeJob, "[CONFIG] Global system analyze prompt: loaded from config/file"},
		{loadedPrompts.Global.UserPrompts.TailorResume, "[CONFIG] Global user tailor prompt: loaded from config/file"},
		{loadedPrompts.Global.UserPrompts.EvaluateResume, "[CONFIG] Global user evaluate prompt: loaded from config/file"},
		{loadedPrompts.Global.UserPrompts.AnalyzeJob, "[CONFIG] Global user analyze prompt: loaded from config/file"},
	}

	for _, check := range promptChecks {
		if check.content != "" {
			log.Println(check.message)
			count++
		}
	}

	return count
}

// logOperationSpecificPrompts logs operation-specific prompt status and returns count
func (c *Config) logOperationSpecificPrompts() int {
	count := 0

	promptChecks := []struct {
		content string
		message string
	}{
		{loadedPrompts.Tailor.SystemPrompts.TailorResume, "[CONFIG] Tailor-specific system prompt: loaded from config/file"},
		{loadedPrompts.Tailor.UserPrompts.TailorResume, "[CONFIG] Tailor-specific user prompt: loaded from config/file"},
		{loadedPrompts.Evaluate.SystemPrompts.EvaluateResume, "[CONFIG] Evaluate-specific system prompt: loaded from config/file"},
		{loadedPrompts.Evaluate.UserPrompts.EvaluateResume, "[CONFIG] Evaluate-specific user prompt: loaded from config/file"},
		{loadedPrompts.Analyze.SystemPrompts.AnalyzeJob, "[CONFIG] Analyze-specific system prompt: loaded from config/file"},
		{loadedPrompts.Analyze.UserPrompts.AnalyzeJob, "[CONFIG] Analyze-specific user prompt: loaded from config/file"},
	}

	for _, check := range promptChecks {
		if check.content != "" {
			log.Println(check.message)
			count++
		}
	}

	return count
}

// logPromptSummaryFooter logs the summary footer with total count
func (c *Config) logPromptSummaryFooter(promptCount int) {
	if promptCount == 0 {
		log.Println("[CONFIG] No custom prompts loaded - using built-in defaults")
	} else {
		log.Printf("[CONFIG] Total custom prompts loaded: %d", promptCount)
	}

	log.Println("[CONFIG] ==========================================")
}
