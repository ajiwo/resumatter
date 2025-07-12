package observability

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"resumatter/internal/config"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// ObservabilityConfig holds configuration for observability
type ObservabilityConfig struct {
	ServiceName    string
	ServiceVersion string
	Enabled        bool
	ConsoleOutput  bool
	PrettyPrint    bool
	SampleRate     float64
	Prometheus     PrometheusConfig
}

// Metrics holds all custom metrics for Resumatter
type Metrics struct {
	// AI operation metrics
	AIProcessingTime metric.Float64Histogram
	AIRequestCount   metric.Int64Counter
	AIErrorCount     metric.Int64Counter
	AITokenUsage     metric.Int64Histogram

	// Business metrics
	ResumesTailored  metric.Int64Counter
	JobsAnalyzed     metric.Int64Counter
	ResumesEvaluated metric.Int64Counter

	// Certificate metrics
	CertReloadCount metric.Int64Counter
	CertExpiryTime  metric.Float64Gauge

	// Rate limiting metrics
	RateLimitHits metric.Int64Counter
}

// ObservabilityManager manages OpenTelemetry setup
type ObservabilityManager struct {
	config           ObservabilityConfig
	fullConfig       *config.Config // Store full config for access to nested settings
	tracerProvider   *trace.TracerProvider
	meterProvider    *sdkmetric.MeterProvider
	metrics          *Metrics
	shutdownFuncs    []func(context.Context) error
	prometheusServer *http.ServeMux
}

// NewObservabilityManager creates a new observability manager
func NewObservabilityManager(obsConfig ObservabilityConfig, fullConfig *config.Config) (*ObservabilityManager, error) {
	if !obsConfig.Enabled {
		return &ObservabilityManager{config: obsConfig, fullConfig: fullConfig}, nil
	}

	om := &ObservabilityManager{
		config:        obsConfig,
		fullConfig:    fullConfig,
		shutdownFuncs: make([]func(context.Context) error, 0),
	}

	if err := om.initResource(); err != nil {
		return nil, fmt.Errorf("failed to initialize resource: %w", err)
	}

	if err := om.initTracing(); err != nil {
		return nil, fmt.Errorf("failed to initialize tracing: %w", err)
	}

	if err := om.initMetrics(); err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return om, nil
}

// initResource creates the OpenTelemetry resource
func (om *ObservabilityManager) initResource() error {
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(om.config.ServiceName),
			semconv.ServiceVersion(om.config.ServiceVersion),
			attribute.String("service.instance.id", om.getServiceInstanceID()),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Store resource for later use
	_ = res
	return nil
}

// initTracing sets up OpenTelemetry tracing
func (om *ObservabilityManager) initTracing() error {
	var exporter trace.SpanExporter
	var err error

	if om.config.ConsoleOutput {
		// Console exporter for development
		opts := []stdouttrace.Option{}
		if om.config.PrettyPrint {
			opts = append(opts, stdouttrace.WithPrettyPrint())
		}
		exporter, err = stdouttrace.New(opts...)
	} else if om.fullConfig != nil && om.fullConfig.Observability.OTLP.Enabled {
		// OTLP exporter for production
		exporter, err = om.createOTLPExporter()
	} else {
		// No-op exporter when no production exporter is configured
		exporter = &noOpSpanExporter{}
	}

	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(om.config.ServiceName),
			semconv.ServiceVersion(om.config.ServiceVersion),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
		trace.WithSampler(trace.TraceIDRatioBased(om.config.SampleRate)),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	om.tracerProvider = tp
	om.shutdownFuncs = append(om.shutdownFuncs, tp.Shutdown)

	return nil
}

// initMetrics sets up OpenTelemetry metrics
func (om *ObservabilityManager) initMetrics() error {
	readers, err := om.setupMetricReaders()
	if err != nil {
		return err
	}

	// Create resource
	res, err := om.createMetricsResource()
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create meter provider with all readers
	meterProviderOptions := []sdkmetric.Option{
		sdkmetric.WithResource(res),
	}
	for _, reader := range readers {
		meterProviderOptions = append(meterProviderOptions, sdkmetric.WithReader(reader))
	}

	mp := sdkmetric.NewMeterProvider(meterProviderOptions...)

	otel.SetMeterProvider(mp)
	om.meterProvider = mp
	om.shutdownFuncs = append(om.shutdownFuncs, mp.Shutdown)

	// Initialize custom metrics
	return om.initCustomMetrics()
}

// setupMetricReaders sets up all metric readers based on configuration
func (om *ObservabilityManager) setupMetricReaders() ([]sdkmetric.Reader, error) {
	var readers []sdkmetric.Reader

	// Console exporter for development
	if err := om.setupConsoleReader(&readers); err != nil {
		return nil, err
	}

	// OTLP exporter for production metrics
	if err := om.setupOTLPReader(&readers); err != nil {
		return nil, err
	}

	// Prometheus exporter for Phase 2
	if err := om.setupPrometheusReader(&readers); err != nil {
		return nil, err
	}

	// If no readers configured, use manual reader as fallback
	if len(readers) == 0 {
		readers = append(readers, sdkmetric.NewManualReader())
	}

	return readers, nil
}

// setupConsoleReader sets up console metric reader if enabled
func (om *ObservabilityManager) setupConsoleReader(readers *[]sdkmetric.Reader) error {
	if !om.config.ConsoleOutput {
		return nil
	}

	exporter, err := stdoutmetric.New()
	if err != nil {
		return fmt.Errorf("failed to create console metric exporter: %w", err)
	}

	// Use configurable collection interval
	interval := om.getMetricsCollectionInterval()
	*readers = append(*readers, sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval)))
	return nil
}

// setupOTLPReader sets up OTLP metric reader if enabled
func (om *ObservabilityManager) setupOTLPReader(readers *[]sdkmetric.Reader) error {
	if om.fullConfig == nil || !om.fullConfig.Observability.OTLP.Enabled {
		return nil
	}

	otlpReader, err := om.createOTLPMetricsReader()
	if err != nil {
		return fmt.Errorf("failed to create OTLP metrics reader: %w", err)
	}
	if otlpReader != nil {
		*readers = append(*readers, otlpReader)
	}
	return nil
}

// setupPrometheusReader sets up Prometheus metric reader if enabled
func (om *ObservabilityManager) setupPrometheusReader(readers *[]sdkmetric.Reader) error {
	if !om.config.Prometheus.Enabled {
		return nil
	}

	prometheusReader, prometheusMux, err := SetupPrometheusExporter(om.config.Prometheus)
	if err != nil {
		return fmt.Errorf("failed to create Prometheus exporter: %w", err)
	}
	if prometheusReader != nil {
		*readers = append(*readers, prometheusReader)
		om.prometheusServer = prometheusMux

		// Start Prometheus server
		if err := StartPrometheusServer(prometheusMux, om.config.Prometheus.Port); err != nil {
			return fmt.Errorf("failed to start Prometheus server: %w", err)
		}
	}
	return nil
}

// createMetricsResource creates the OpenTelemetry resource for metrics
func (om *ObservabilityManager) createMetricsResource() (*resource.Resource, error) {
	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(om.config.ServiceName),
			semconv.ServiceVersion(om.config.ServiceVersion),
		),
	)
}

// initCustomMetrics creates all custom metrics for Resumatter
func (om *ObservabilityManager) initCustomMetrics() error {
	meter := om.meterProvider.Meter(om.config.ServiceName)
	om.metrics = &Metrics{}

	if err := om.createAIMetrics(meter); err != nil {
		return err
	}

	if err := om.createBusinessMetrics(meter); err != nil {
		return err
	}

	if err := om.createCertificateMetrics(meter); err != nil {
		return err
	}

	if err := om.createRateLimitMetrics(meter); err != nil {
		return err
	}

	return nil
}

// createAIMetrics creates AI-related metrics
func (om *ObservabilityManager) createAIMetrics(meter metric.Meter) error {
	var err error

	// AI operation metrics
	om.metrics.AIProcessingTime, err = meter.Float64Histogram(
		"resumatter_ai_processing_duration_seconds",
		metric.WithDescription("Time spent processing AI requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("failed to create AI processing time metric: %w", err)
	}

	om.metrics.AIRequestCount, err = meter.Int64Counter(
		"resumatter_ai_requests_total",
		metric.WithDescription("Total number of AI requests"),
	)
	if err != nil {
		return fmt.Errorf("failed to create AI request count metric: %w", err)
	}

	om.metrics.AIErrorCount, err = meter.Int64Counter(
		"resumatter_ai_errors_total",
		metric.WithDescription("Total number of AI request errors"),
	)
	if err != nil {
		return fmt.Errorf("failed to create AI error count metric: %w", err)
	}

	// AI token usage tracking
	om.metrics.AITokenUsage, err = meter.Int64Histogram(
		"resumatter_ai_token_usage_total",
		metric.WithDescription("Token usage for AI requests (input, output, total)"),
		metric.WithUnit("tokens"),
	)
	if err != nil {
		return fmt.Errorf("failed to create AI token usage metric: %w", err)
	}

	return nil
}

// createBusinessMetrics creates business-related metrics
func (om *ObservabilityManager) createBusinessMetrics(meter metric.Meter) error {
	var err error

	om.metrics.ResumesTailored, err = meter.Int64Counter(
		"resumatter_resumes_tailored_total",
		metric.WithDescription("Total number of resumes tailored"),
	)
	if err != nil {
		return fmt.Errorf("failed to create resumes tailored metric: %w", err)
	}

	om.metrics.JobsAnalyzed, err = meter.Int64Counter(
		"resumatter_jobs_analyzed_total",
		metric.WithDescription("Total number of job descriptions analyzed"),
	)
	if err != nil {
		return fmt.Errorf("failed to create jobs analyzed metric: %w", err)
	}

	om.metrics.ResumesEvaluated, err = meter.Int64Counter(
		"resumatter_resumes_evaluated_total",
		metric.WithDescription("Total number of resumes evaluated"),
	)
	if err != nil {
		return fmt.Errorf("failed to create resumes evaluated metric: %w", err)
	}

	return nil
}

// createCertificateMetrics creates certificate-related metrics
func (om *ObservabilityManager) createCertificateMetrics(meter metric.Meter) error {
	var err error

	om.metrics.CertReloadCount, err = meter.Int64Counter(
		"resumatter_cert_reloads_total",
		metric.WithDescription("Total number of certificate reloads"),
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate reload count metric: %w", err)
	}

	// Certificate expiry time gauge (populated by CertificateManager)
	om.metrics.CertExpiryTime, err = meter.Float64Gauge(
		"resumatter_cert_expiry_seconds",
		metric.WithDescription("Seconds until certificate expiry"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate expiry time metric: %w", err)
	}

	return nil
}

// createRateLimitMetrics creates rate limiting metrics
func (om *ObservabilityManager) createRateLimitMetrics(meter metric.Meter) error {
	var err error

	om.metrics.RateLimitHits, err = meter.Int64Counter(
		"resumatter_rate_limit_hits_total",
		metric.WithDescription("Total number of rate limit hits"),
	)
	if err != nil {
		return fmt.Errorf("failed to create rate limit hits metric: %w", err)
	}

	return nil
}

// GetMetrics returns the metrics instance
func (om *ObservabilityManager) GetMetrics() *Metrics {
	if om.metrics == nil {
		return &Metrics{} // Return empty metrics if not initialized
	}
	return om.metrics
}

// HTTPMiddleware returns HTTP middleware with OpenTelemetry instrumentation
func (om *ObservabilityManager) HTTPMiddleware() func(http.Handler) http.Handler {
	if !om.config.Enabled {
		return func(h http.Handler) http.Handler { return h }
	}

	return otelhttp.NewMiddleware(
		om.config.ServiceName,
		otelhttp.WithTracerProvider(om.tracerProvider),
		otelhttp.WithMeterProvider(om.meterProvider),
	)
}

// Tracer returns a tracer for the service
func (om *ObservabilityManager) Tracer(name string) oteltrace.Tracer {
	if !om.config.Enabled {
		return noop.NewTracerProvider().Tracer(name)
	}
	return otel.Tracer(name)
}

// Shutdown gracefully shuts down all observability components
func (om *ObservabilityManager) Shutdown(ctx context.Context) error {
	for _, shutdown := range om.shutdownFuncs {
		if err := shutdown(ctx); err != nil {
			return err
		}
	}
	return nil
}

// AIOperationResult holds the result of an AI operation including token usage
type AIOperationResult struct {
	Error      error
	TokenUsage *TokenUsage
}

// TokenUsage represents token usage information from AI responses
type TokenUsage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

// // TrackAIOperation instruments an AI operation with tracing and metrics
// func (m *Metrics) TrackAIOperation(ctx context.Context, operation string, fn func(context.Context) error, om *ObservabilityManager) error {
// 	if m.AIProcessingTime == nil {
// 		// Metrics not initialized, just run the function
// 		return fn(ctx)
// 	}

// 	// Check if AI operations metrics are enabled
// 	aiMetricsEnabled := true
// 	if om.fullConfig != nil {
// 		aiMetricsEnabled = om.fullConfig.Observability.CustomMetrics.AIOperations.Enabled
// 	}

// 	tracer := otel.Tracer("resumatter.ai")
// 	ctx, span := tracer.Start(ctx, "ai."+operation)
// 	defer span.End()

// 	start := time.Now()
// 	err := fn(ctx)
// 	duration := time.Since(start).Seconds()

// 	// Record metrics only if AI operations metrics are enabled
// 	if aiMetricsEnabled {
// 		attrs := []attribute.KeyValue{
// 			attribute.String("operation", operation),
// 			attribute.Bool("success", err == nil),
// 		}

// 		// Track duration if enabled
// 		if om.fullConfig == nil || om.fullConfig.Observability.CustomMetrics.AIOperations.TrackDuration {
// 			m.AIProcessingTime.Record(ctx, duration, metric.WithAttributes(attrs...))
// 		}

// 		m.AIRequestCount.Add(ctx, 1, metric.WithAttributes(attrs...))

// 		if err != nil {
// 			m.AIErrorCount.Add(ctx, 1, metric.WithAttributes(attrs...))
// 		}

// 		span.SetAttributes(attrs...)
// 	}

// 	if err != nil {
// 		span.RecordError(err)
// 		span.SetAttributes(attribute.Bool("error", true))
// 	}

// 	return err
// }

// TrackAIOperationWithTokens instruments an AI operation with tracing, metrics, and token usage
func (m *Metrics) TrackAIOperationWithTokens(ctx context.Context, operation string, fn func(context.Context) *AIOperationResult, om *ObservabilityManager) error {
	if m.AIProcessingTime == nil {
		// Metrics not initialized, just run the function
		result := fn(ctx)
		if result != nil {
			return result.Error
		}
		return nil
	}

	// Check if AI operations metrics are enabled
	aiMetricsEnabled := m.isAIMetricsEnabled(om)

	tracer := otel.Tracer("resumatter.ai")
	ctx, span := tracer.Start(ctx, "ai."+operation)
	defer span.End()

	start := time.Now()
	result := fn(ctx)
	duration := time.Since(start).Seconds()

	var err error
	if result != nil {
		err = result.Error
	}

	// Record metrics only if AI operations metrics are enabled
	if aiMetricsEnabled {
		m.recordAIMetrics(ctx, operation, err, duration, result, om, span)
	}

	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("error", true))
	}

	return err
}

// isAIMetricsEnabled checks if AI metrics are enabled in the configuration
func (m *Metrics) isAIMetricsEnabled(om *ObservabilityManager) bool {
	if om.fullConfig == nil {
		return true
	}
	return om.fullConfig.Observability.CustomMetrics.AIOperations.Enabled
}

// recordAIMetrics records all AI-related metrics
func (m *Metrics) recordAIMetrics(ctx context.Context, operation string, err error, duration float64, result *AIOperationResult, om *ObservabilityManager, span oteltrace.Span) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.Bool("success", err == nil),
	}

	m.recordAIDuration(ctx, duration, attrs, om)
	m.recordAIRequestCount(ctx, attrs)
	m.recordTokenUsage(ctx, result, attrs, om, span)
	m.recordAIError(ctx, err, attrs)

	span.SetAttributes(attrs...)
}

// recordAIDuration records AI processing duration if enabled
func (m *Metrics) recordAIDuration(ctx context.Context, duration float64, attrs []attribute.KeyValue, om *ObservabilityManager) {
	if om.fullConfig == nil || om.fullConfig.Observability.CustomMetrics.AIOperations.TrackDuration {
		m.AIProcessingTime.Record(ctx, duration, metric.WithAttributes(attrs...))
	}
}

// recordAIRequestCount records AI request count
func (m *Metrics) recordAIRequestCount(ctx context.Context, attrs []attribute.KeyValue) {
	m.AIRequestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// recordAIError records AI error count if there was an error
func (m *Metrics) recordAIError(ctx context.Context, err error, attrs []attribute.KeyValue) {
	if err != nil {
		m.AIErrorCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// recordTokenUsage records token usage metrics and span attributes
func (m *Metrics) recordTokenUsage(ctx context.Context, result *AIOperationResult, attrs []attribute.KeyValue, om *ObservabilityManager, span oteltrace.Span) {
	if result == nil || result.TokenUsage == nil || m.AITokenUsage == nil {
		return
	}

	trackTokenUsage := om.fullConfig == nil || om.fullConfig.Observability.CustomMetrics.AIOperations.TrackTokenUsage
	if trackTokenUsage {
		m.recordTokenMetrics(ctx, result.TokenUsage, attrs)
	}

	// Add token usage to span attributes (always add to traces for debugging)
	span.SetAttributes(
		attribute.Int64("ai.tokens.input", result.TokenUsage.InputTokens),
		attribute.Int64("ai.tokens.output", result.TokenUsage.OutputTokens),
		attribute.Int64("ai.tokens.total", result.TokenUsage.TotalTokens),
	)
}

// recordTokenMetrics records individual token usage metrics
func (m *Metrics) recordTokenMetrics(ctx context.Context, tokenUsage *TokenUsage, attrs []attribute.KeyValue) {
	tokenTypes := []struct {
		tokenType string
		value     int64
	}{
		{"input", tokenUsage.InputTokens},
		{"output", tokenUsage.OutputTokens},
		{"total", tokenUsage.TotalTokens},
	}

	for _, tt := range tokenTypes {
		tokenAttrs := append(attrs[:len(attrs)-1], // Remove previous token_type
			attribute.String("token_type", tt.tokenType),
		)
		m.AITokenUsage.Record(ctx, tt.value, metric.WithAttributes(tokenAttrs...))
	}
}

// RecordBusinessMetric records business-specific metrics
func (m *Metrics) RecordBusinessMetric(ctx context.Context, metricType string, success bool, om *ObservabilityManager, attributes ...attribute.KeyValue) {
	// Check if business metrics are enabled
	if om.fullConfig != nil && !om.fullConfig.Observability.CustomMetrics.BusinessMetrics.Enabled {
		return
	}

	attrs := append([]attribute.KeyValue{
		attribute.Bool("success", success),
	}, attributes...)

	m.recordMetricByType(ctx, metricType, attrs, om)
}

// recordMetricByType records the appropriate metric based on the metric type
func (m *Metrics) recordMetricByType(ctx context.Context, metricType string, attrs []attribute.KeyValue, om *ObservabilityManager) {
	switch metricType {
	case "resume_tailored":
		m.recordResumeTailored(ctx, attrs)
	case "job_analyzed":
		m.recordJobAnalyzed(ctx, attrs)
	case "resume_evaluated":
		m.recordResumeEvaluated(ctx, attrs)
	case "rate_limit_hit":
		m.recordRateLimitHit(ctx, attrs, om)
	}
}

// recordResumeTailored records resume tailored metric
func (m *Metrics) recordResumeTailored(ctx context.Context, attrs []attribute.KeyValue) {
	if m.ResumesTailored != nil {
		m.ResumesTailored.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// recordJobAnalyzed records job analyzed metric
func (m *Metrics) recordJobAnalyzed(ctx context.Context, attrs []attribute.KeyValue) {
	if m.JobsAnalyzed != nil {
		m.JobsAnalyzed.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// recordResumeEvaluated records resume evaluated metric
func (m *Metrics) recordResumeEvaluated(ctx context.Context, attrs []attribute.KeyValue) {
	if m.ResumesEvaluated != nil {
		m.ResumesEvaluated.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// recordRateLimitHit records rate limit hit metric
func (m *Metrics) recordRateLimitHit(ctx context.Context, attrs []attribute.KeyValue, om *ObservabilityManager) {
	// Rate limiting is an infrastructure metric
	if om != nil && om.fullConfig != nil && !om.fullConfig.Observability.CustomMetrics.Infrastructure.TrackRateLimits {
		return
	}
	if m.RateLimitHits != nil {
		m.RateLimitHits.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// No-op exporters for when console output is disabled
type noOpSpanExporter struct{}

func (n *noOpSpanExporter) ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error {
	return nil
}

func (n *noOpSpanExporter) Shutdown(ctx context.Context) error {
	return nil
}

// createOTLPExporter creates an OTLP HTTP trace exporter
func (om *ObservabilityManager) createOTLPExporter() (trace.SpanExporter, error) {
	if om.fullConfig == nil {
		return nil, fmt.Errorf("config not available for OTLP configuration")
	}

	otlpConfig := om.fullConfig.Observability.OTLP

	// Prepare OTLP options
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(otlpConfig.Endpoint),
	}

	// Configure TLS
	if otlpConfig.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	// Add custom headers if provided
	if len(otlpConfig.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(otlpConfig.Headers))
	}

	// Create the OTLP exporter
	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	return exporter, nil
}

// createOTLPMetricsReader creates an OTLP HTTP metrics reader
func (om *ObservabilityManager) createOTLPMetricsReader() (sdkmetric.Reader, error) {
	if om.fullConfig == nil {
		return nil, fmt.Errorf("config not available for OTLP configuration")
	}

	otlpConfig := om.fullConfig.Observability.OTLP

	// Prepare OTLP options
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpointURL(otlpConfig.Endpoint),
	}

	// Configure TLS
	if otlpConfig.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	// Add custom headers if provided
	if len(otlpConfig.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(otlpConfig.Headers))
	}

	// Create the OTLP metrics exporter
	exporter, err := otlpmetrichttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP metrics exporter: %w", err)
	}

	// Use configurable collection interval for OTLP metrics
	interval := om.getMetricsCollectionInterval()
	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))

	return reader, nil
}

// getServiceInstanceID returns the service instance ID from config or generates one
func (om *ObservabilityManager) getServiceInstanceID() string {
	if om.fullConfig != nil && om.fullConfig.Observability.ServiceInstance != "" {
		return om.fullConfig.Observability.ServiceInstance
	}
	// Fallback to default if config not available
	return "resumatter-1"
}

// getMetricsCollectionInterval returns the configured metrics collection interval
func (om *ObservabilityManager) getMetricsCollectionInterval() time.Duration {
	if om.fullConfig != nil {
		return om.fullConfig.Observability.Metrics.CollectionInterval
	}
	// Fallback to default
	return 15 * time.Second
}
