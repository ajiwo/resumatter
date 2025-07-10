package config

import (
	"sync"
)

var (
	loadedPrompts     AllLoadedPrompts
	loadedPromptsOnce sync.Once
)

// LoadedPrompts holds the content of prompts loaded from files
type LoadedPrompts struct {
	SystemPrompts LoadedSystemPrompts
	UserPrompts   LoadedUserPrompts
}

// LoadedSystemPrompts contains loaded system-level instructions
type LoadedSystemPrompts struct {
	TailorResume   string
	EvaluateResume string
	AnalyzeJob     string
}

// LoadedUserPrompts contains loaded user-level prompt templates
type LoadedUserPrompts struct {
	TailorResume   string
	EvaluateResume string
	AnalyzeJob     string
}

// OperationLoadedPrompts holds loaded prompts for a specific operation
type OperationLoadedPrompts struct {
	SystemPrompts LoadedSystemPrompts
	UserPrompts   LoadedUserPrompts
}

// AllLoadedPrompts holds all loaded prompts for all operations
type AllLoadedPrompts struct {
	Global   LoadedPrompts
	Tailor   OperationLoadedPrompts
	Evaluate OperationLoadedPrompts
	Analyze  OperationLoadedPrompts
}

// GetPromptsForOperation returns a copy of the loaded prompts for an operation type
func GetPromptsForOperation(operationType string) OperationLoadedPrompts {
	var result OperationLoadedPrompts

	switch operationType {
	case "tailor":
		result = loadedPrompts.Tailor
		logPromptSource("tailor", &result)
	case "evaluate":
		result = loadedPrompts.Evaluate
		logPromptSource("evaluate", &result)
	case "analyze":
		result = loadedPrompts.Analyze
		logPromptSource("analyze", &result)
	default:
		result = OperationLoadedPrompts{
			SystemPrompts: loadedPrompts.Global.SystemPrompts,
			UserPrompts:   loadedPrompts.Global.UserPrompts,
		}
		logPromptSource("global", &result)
	}

	return result
}

// logPromptSource logs where each prompt came from for debugging purposes
func logPromptSource(operationType string, prompts *OperationLoadedPrompts) {
	// Prompt source information can be determined if needed for debugging
}
