package config

// applyOperationDefaults applies global defaults to operation-specific configuration
func (c *Config) applyOperationDefaults(opCfg *OperationAIConfig) {
	if opCfg.Provider == "" {
		opCfg.Provider = c.AI.Provider
	}
	if opCfg.Model == "" {
		opCfg.Model = c.AI.Model
	}
	if opCfg.Timeout == nil {
		opCfg.Timeout = &c.AI.Timeout
	}
	if opCfg.APIKey == "" {
		opCfg.APIKey = c.AI.APIKey
	}
	if opCfg.MaxRetries == nil {
		opCfg.MaxRetries = &c.AI.MaxRetries
	}
	if opCfg.Temperature == nil {
		opCfg.Temperature = &c.AI.Temperature
	}
	// UseSystemPrompts: apply global default only if not explicitly set
	if opCfg.UseSystemPrompts == nil {
		opCfg.UseSystemPrompts = &c.AI.UseSystemPrompts
	}
}

// GetTailorConfig returns the AI configuration for tailor operations with fallback to global config
func (c *Config) GetTailorConfig() OperationAIConfig {
	config := c.AI.Tailor

	// Apply common defaults
	c.applyOperationDefaults(&config)

	// Apply tailor-specific prompt fallbacks
	if config.CustomPrompts.SystemPrompts.TailorResume == "" {
		config.CustomPrompts.SystemPrompts.TailorResume = c.AI.CustomPrompts.SystemPrompts.TailorResume
	}
	if config.CustomPrompts.UserPrompts.TailorResume == "" {
		config.CustomPrompts.UserPrompts.TailorResume = c.AI.CustomPrompts.UserPrompts.TailorResume
	}
	// Also copy file paths for potential later loading
	if config.CustomPrompts.SystemPrompts.TailorResumeFile == "" {
		config.CustomPrompts.SystemPrompts.TailorResumeFile = c.AI.CustomPrompts.SystemPrompts.TailorResumeFile
	}
	if config.CustomPrompts.UserPrompts.TailorResumeFile == "" {
		config.CustomPrompts.UserPrompts.TailorResumeFile = c.AI.CustomPrompts.UserPrompts.TailorResumeFile
	}

	return config
}

// GetEvaluateConfig returns the AI configuration for evaluate operations with fallback to global config
func (c *Config) GetEvaluateConfig() OperationAIConfig {
	config := c.AI.Evaluate

	// Apply common defaults
	c.applyOperationDefaults(&config)

	// Apply evaluate-specific prompt fallbacks
	if config.CustomPrompts.SystemPrompts.EvaluateResume == "" {
		config.CustomPrompts.SystemPrompts.EvaluateResume = c.AI.CustomPrompts.SystemPrompts.EvaluateResume
	}
	if config.CustomPrompts.UserPrompts.EvaluateResume == "" {
		config.CustomPrompts.UserPrompts.EvaluateResume = c.AI.CustomPrompts.UserPrompts.EvaluateResume
	}
	// Also copy file paths for potential later loading
	if config.CustomPrompts.SystemPrompts.EvaluateResumeFile == "" {
		config.CustomPrompts.SystemPrompts.EvaluateResumeFile = c.AI.CustomPrompts.SystemPrompts.EvaluateResumeFile
	}
	if config.CustomPrompts.UserPrompts.EvaluateResumeFile == "" {
		config.CustomPrompts.UserPrompts.EvaluateResumeFile = c.AI.CustomPrompts.UserPrompts.EvaluateResumeFile
	}

	return config
}

// GetAnalyzeConfig returns the AI configuration for analyze operations with fallback to global config
func (c *Config) GetAnalyzeConfig() OperationAIConfig {
	config := c.AI.Analyze

	// Apply common defaults
	c.applyOperationDefaults(&config)

	// Apply analyze-specific prompt fallbacks
	if config.CustomPrompts.SystemPrompts.AnalyzeJob == "" {
		config.CustomPrompts.SystemPrompts.AnalyzeJob = c.AI.CustomPrompts.SystemPrompts.AnalyzeJob
	}
	if config.CustomPrompts.UserPrompts.AnalyzeJob == "" {
		config.CustomPrompts.UserPrompts.AnalyzeJob = c.AI.CustomPrompts.UserPrompts.AnalyzeJob
	}
	// Also copy file paths for potential later loading
	if config.CustomPrompts.SystemPrompts.AnalyzeJobFile == "" {
		config.CustomPrompts.SystemPrompts.AnalyzeJobFile = c.AI.CustomPrompts.SystemPrompts.AnalyzeJobFile
	}
	if config.CustomPrompts.UserPrompts.AnalyzeJobFile == "" {
		config.CustomPrompts.UserPrompts.AnalyzeJobFile = c.AI.CustomPrompts.UserPrompts.AnalyzeJobFile
	}

	return config
}

// GetLoadedTailorPrompts returns a copy of the loaded prompts for tailor operation
func (c *Config) GetLoadedTailorPrompts() OperationLoadedPrompts {
	return loadedPrompts.Tailor
}

// GetLoadedEvaluatePrompts returns a copy of the loaded prompts for evaluate operation
func (c *Config) GetLoadedEvaluatePrompts() OperationLoadedPrompts {
	return loadedPrompts.Evaluate
}

// GetLoadedAnalyzePrompts returns a copy of the loaded prompts for analyze operation
func (c *Config) GetLoadedAnalyzePrompts() OperationLoadedPrompts {
	return loadedPrompts.Analyze
}

// GetLoadedGlobalPrompts returns a copy of the loaded global prompts
func (c *Config) GetLoadedGlobalPrompts() LoadedPrompts {
	return loadedPrompts.Global
}