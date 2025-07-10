package cli

import (
	"fmt"
	"resumatter/internal/config"
	"resumatter/internal/server"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP server for resume tailoring and evaluation",
	Long: `Start an HTTP server that provides REST API endpoints for resume tailoring and evaluation.
	
Available endpoints:
- POST /tailor: Tailor a resume for a job description
- POST /evaluate: Evaluate a tailored resume for accuracy
- POST /analyze: Analyze a job description for quality and effectiveness
- GET /health: Health check endpoint
- GET /stats: Server statistics and rate limiting info

TLS Configuration:
- Use --tls-mode to set TLS mode: disabled, server, mutual
- Use --cert-file and --key-file for TLS certificates
- Use --ca-file for mutual TLS client certificate verification`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringP("port", "p", "", "Port to listen on (default from config)")
	serveCmd.Flags().String("host", "", "Host to bind to (default from config)")
	serveCmd.Flags().String("tls-mode", "", "TLS mode: disabled, server, mutual (overrides config)")
	serveCmd.Flags().String("cert-file", "", "Server certificate file (PEM, overrides config)")
	serveCmd.Flags().String("key-file", "", "Server private key file (PEM, overrides config)")
	serveCmd.Flags().String("ca-file", "", "CA certificate file for client cert verification (PEM, overrides config)")

	// Bind flags to viper config keys
	bindFlag := func(key, flagName string) {
		if err := viper.BindPFlag(key, serveCmd.Flags().Lookup(flagName)); err != nil {
			panic(err)
		}
	}

	bindFlag("server.port", "port")
	bindFlag("server.host", "host")
	bindFlag("server.tls.mode", "tls-mode")
	bindFlag("server.tls.certfile", "cert-file")
	bindFlag("server.tls.keyfile", "key-file")
	bindFlag("server.tls.cafile", "ca-file")
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg := getConfigFromContext(cmd.Context())
	logger := getLoggerFromContext(cmd.Context())

	// Validate TLS configuration after applying overrides
	tempConfig := &config.Config{Server: cfg.Server}
	if err := tempConfig.ValidateTLSConfig(); err != nil {
		return fmt.Errorf("invalid TLS configuration: %w", err)
	}

	serverCfg := server.ServerConfig{
		Host:           cfg.Server.Host,
		Port:           cfg.Server.Port,
		Version:        Version,
		TLSConfig:      cfg.Server.TLS,
		APIKeys:        cfg.Server.APIKeys,
		ReadTimeout:    cfg.Server.ReadTimeout,
		WriteTimeout:   cfg.Server.WriteTimeout,
		IdleTimeout:    cfg.Server.IdleTimeout,
		MaxRequestSize: int64(cfg.App.MaxFileSize),
		RateLimit:      &cfg.Server.RateLimit,
	}
	return server.NewServer(cfg, serverCfg, logger).Start()
}
