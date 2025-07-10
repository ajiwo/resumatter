package observability

import (
	"net/http"

	"resumatter/internal/config"

	"go.opentelemetry.io/otel/attribute"
)

// GetObservabilityConfig creates observability config from provided config
func GetObservabilityConfig(cfg *config.Config, version string) ObservabilityConfig {
	if cfg == nil {
		// Fallback to defaults if config not available
		return ObservabilityConfig{
			ServiceName:    "resumatter",
			ServiceVersion: version,
			Enabled:        true,
			ConsoleOutput:  true, // Default to console output for fallback
			PrettyPrint:    true,
			SampleRate:     1.0,
			Prometheus:     GetPrometheusConfig(cfg),
		}
	}

	obsConfig := cfg.Observability

	// Use app version if service version not specified
	serviceVersion := obsConfig.ServiceVersion
	if serviceVersion == "" {
		serviceVersion = version
	}

	return ObservabilityConfig{
		ServiceName:    obsConfig.ServiceName,
		ServiceVersion: serviceVersion,
		Enabled:        obsConfig.Enabled,
		ConsoleOutput:  obsConfig.ConsoleOutput,
		PrettyPrint:    obsConfig.Console.PrettyPrint,
		SampleRate:     obsConfig.SampleRate,
		Prometheus: PrometheusConfig{
			Enabled:  obsConfig.Prometheus.Enabled,
			Endpoint: obsConfig.Prometheus.Endpoint,
			Port:     obsConfig.Prometheus.Port,
		},
	}
}

// ObservabilityMiddleware creates a middleware function that can be used in the server
func ObservabilityMiddleware(om *ObservabilityManager) func(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(next func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			// Add observability context to request
			ctx := r.Context()

			// Add trace context if available
			if om.config.Enabled {
				// The HTTP middleware will handle tracing automatically
				// We can add custom attributes here if needed
				tracer := om.Tracer("resumatter.http")
				ctx, span := tracer.Start(ctx, r.URL.Path)
				defer span.End()

				// Add request attributes
				span.SetAttributes(
					attribute.String("http.method", r.Method),
					attribute.String("http.url", r.URL.String()),
					attribute.String("http.user_agent", r.UserAgent()),
				)

				r = r.WithContext(ctx)
			}

			next(w, r)
		}
	}
}
