package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"resumatter/internal/cli"
	"resumatter/internal/config"
	"resumatter/internal/errors"
)

func main() {
	// Create a context that is canceled on interrupt signals
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logging
	logger, err := errors.New(cfg.App.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// Log startup
	logger.Info("Starting resumatter application",
		"version", cli.Version,
		"log_level", cfg.App.LogLevel,
		"ai_provider", cfg.AI.Provider)

	// Execute command with cancellable context
	if err := cli.Execute(ctx, cfg, logger); err != nil {
		logger.LogError(err, "Application execution failed")
		os.Exit(1)
	}
}
