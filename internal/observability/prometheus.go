package observability

import (
	"fmt"
	"net/http"
	"time"

	"resumatter/internal/config"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/sdk/metric"
)

// PrometheusConfig holds Prometheus-specific configuration
type PrometheusConfig struct {
	Enabled  bool
	Endpoint string
	Port     string
}

// SetupPrometheusExporter creates and configures a Prometheus metrics exporter
func SetupPrometheusExporter(config PrometheusConfig) (metric.Reader, *http.ServeMux, error) {
	if !config.Enabled {
		return nil, nil, nil
	}

	// Create Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}

	// Create HTTP handler for metrics endpoint
	mux := http.NewServeMux()
	// Use the promhttp.Handler to serve the metrics.
	// This handler will use the default registry which the OTel exporter registers to.
	mux.Handle(config.Endpoint, promhttp.Handler())

	return exporter, mux, nil
}

// StartPrometheusServer starts a dedicated HTTP server for Prometheus metrics
func StartPrometheusServer(mux *http.ServeMux, port string) error {
	if mux == nil {
		return nil // No Prometheus server to start
	}

	addr := ":" + port
	fmt.Printf("Starting Prometheus metrics server on http://localhost%s\n", addr)
	fmt.Printf("Metrics available at: http://localhost%s/metrics\n", addr)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in background
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Prometheus server error: %v\n", err)
		}
	}()

	return nil
}

// GetPrometheusConfig creates Prometheus configuration from provided config
func GetPrometheusConfig(cfg *config.Config) PrometheusConfig {
	if cfg != nil {
		return PrometheusConfig{
			Enabled:  cfg.Observability.Prometheus.Enabled,
			Endpoint: cfg.Observability.Prometheus.Endpoint,
			Port:     cfg.Observability.Prometheus.Port,
		}
	}

	// Fallback to defaults if config not available
	return PrometheusConfig{
		Enabled:  true,
		Endpoint: "/metrics",
		Port:     "9090",
	}
}
