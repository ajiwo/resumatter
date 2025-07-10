package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadPromptsFromFiles(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Create test prompt files
	systemPromptContent := "Test system prompt for tailoring"
	userPromptContent := "Test user prompt template: %s and %s"

	systemPromptFile := filepath.Join(tempDir, "system.tailor.md")
	userPromptFile := filepath.Join(tempDir, "user.tailor.md")

	if err := os.WriteFile(systemPromptFile, []byte(systemPromptContent), 0600); err != nil {
		t.Fatalf("Failed to create test system prompt file: %v", err)
	}

	if err := os.WriteFile(userPromptFile, []byte(userPromptContent), 0600); err != nil {
		t.Fatalf("Failed to create test user prompt file: %v", err)
	}

	// Create test config
	config := &Config{
		AI: AIConfig{
			Tailor: OperationAIConfig{
				CustomPrompts: PromptConfig{
					SystemPrompts: SystemPrompts{
						TailorResumeFile: systemPromptFile,
					},
					UserPrompts: UserPrompts{
						TailorResumeFile: userPromptFile,
					},
				},
			},
		},
	}

	// Test file loading
	err := config.loadPromptsFromFiles()
	if err != nil {
		t.Fatalf("Failed to load prompts from files: %v", err)
	}

	// Verify content was loaded into global loadedPrompts
	loadedOps := GetPromptsForOperation("tailor")

	if loadedOps.SystemPrompts.TailorResume != systemPromptContent {
		t.Errorf("Expected loaded system prompt content '%s', got '%s'",
			systemPromptContent, loadedOps.SystemPrompts.TailorResume)
	}

	if loadedOps.UserPrompts.TailorResume != userPromptContent {
		t.Errorf("Expected loaded user prompt content '%s', got '%s'",
			userPromptContent, loadedOps.UserPrompts.TailorResume)
	}

	// Verify file paths are preserved (new immutable design)
	if config.AI.Tailor.CustomPrompts.SystemPrompts.TailorResumeFile != systemPromptFile {
		t.Error("Expected system prompt file path to be preserved")
	}

	if config.AI.Tailor.CustomPrompts.UserPrompts.TailorResumeFile != userPromptFile {
		t.Error("Expected user prompt file path to be preserved")
	}
}

func TestValidatePromptFiles(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Create a valid test file
	validFile := filepath.Join(tempDir, "valid.md")
	if err := os.WriteFile(validFile, []byte("Valid content"), 0600); err != nil {
		t.Fatalf("Failed to create valid test file: %v", err)
	}

	// Test with valid file
	config := &Config{
		AI: AIConfig{
			Tailor: OperationAIConfig{
				CustomPrompts: PromptConfig{
					SystemPrompts: SystemPrompts{
						TailorResumeFile: validFile,
					},
				},
			},
		},
	}

	err := config.validatePromptFiles()
	if err != nil {
		t.Errorf("Expected validation to pass for valid file, got error: %v", err)
	}

	// Test with non-existent file
	config.AI.Tailor.CustomPrompts.SystemPrompts.TailorResumeFile = filepath.Join(tempDir, "nonexistent.md")

	err = config.validatePromptFiles()
	if err == nil {
		t.Error("Expected validation to fail for non-existent file")
	}
}

func TestLoadPromptFromFile(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Test with valid file
	content := "Test prompt content"
	testFile := filepath.Join(tempDir, "test.md")
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config := &Config{}
	loadedContent, err := config.loadPromptFromFile(testFile, "system", "tailor")
	if err != nil {
		t.Fatalf("Failed to load prompt from file: %v", err)
	}

	if loadedContent != content {
		t.Errorf("Expected content '%s', got '%s'", content, loadedContent)
	}

	// Test with empty file
	emptyFile := filepath.Join(tempDir, "empty.md")
	if err := os.WriteFile(emptyFile, []byte(""), 0600); err != nil {
		t.Fatalf("Failed to create empty test file: %v", err)
	}

	_, err = config.loadPromptFromFile(emptyFile, "system", "tailor")
	if err == nil {
		t.Error("Expected error for empty file")
	}

	// Test with non-existent file
	_, err = config.loadPromptFromFile(filepath.Join(tempDir, "nonexistent.md"), "system", "tailor")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestPromptFileIntegration(t *testing.T) {
	// Create temporary directory and config file
	tempDir := t.TempDir()

	// Create test prompt files
	systemPrompt := "Custom system prompt for testing"
	userPrompt := "Custom user prompt: %s %s"

	systemFile := filepath.Join(tempDir, "system.md")
	userFile := filepath.Join(tempDir, "user.md")

	if err := os.WriteFile(systemFile, []byte(systemPrompt), 0600); err != nil {
		t.Fatalf("Failed to create system prompt file: %v", err)
	}

	if err := os.WriteFile(userFile, []byte(userPrompt), 0600); err != nil {
		t.Fatalf("Failed to create user prompt file: %v", err)
	}

	// Create a minimal config that would load these files
	config := &Config{
		AI: AIConfig{
			Provider:    "gemini",
			Model:       "test-model",
			Timeout:     60 * time.Second,
			APIKey:      "test-key",
			MaxRetries:  3,
			Temperature: 0.7,
			Tailor: OperationAIConfig{
				CustomPrompts: PromptConfig{
					SystemPrompts: SystemPrompts{
						TailorResumeFile: systemFile,
					},
					UserPrompts: UserPrompts{
						TailorResumeFile: userFile,
					},
				},
			},
		},
		App: AppConfig{
			LogLevel:         "info",
			DefaultFormat:    "json",
			SupportedFormats: []string{"json", "text", "markdown"},
			MaxFileSize:      1024 * 1024,
		},
		Server: ServerConfig{
			Host: "localhost",
			Port: "8080",
		},
	}

	// Apply fallbacks (simulating the full config loading process)
	config.applyFallbacks()

	// Validate and load prompt files
	if err := config.validatePromptFiles(); err != nil {
		t.Fatalf("Prompt file validation failed: %v", err)
	}

	if err := config.loadPromptsFromFiles(); err != nil {
		t.Fatalf("Failed to load prompts from files: %v", err)
	}

	// Verify the prompts were loaded correctly into the global store
	loadedOps := GetPromptsForOperation("tailor")

	if loadedOps.SystemPrompts.TailorResume != systemPrompt {
		t.Errorf("Expected system prompt '%s', got '%s'",
			systemPrompt, loadedOps.SystemPrompts.TailorResume)
	}

	if loadedOps.UserPrompts.TailorResume != userPrompt {
		t.Errorf("Expected user prompt '%s', got '%s'",
			userPrompt, loadedOps.UserPrompts.TailorResume)
	}

	// Verify the original config paths are preserved
	if config.AI.Tailor.CustomPrompts.SystemPrompts.TailorResumeFile != systemFile {
		t.Error("Expected system prompt file path to be preserved")
	}

	if config.AI.Tailor.CustomPrompts.UserPrompts.TailorResumeFile != userFile {
		t.Error("Expected user prompt file path to be preserved")
	}
}
