package otel

import (
	"context"
	"errors"
	"fmt"
	"time"

	internallogger "github.com/grafana/flux-commit-tracker/internal/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

// ExporterType defines the type of exporter to use
type ExporterType string

const (
	// StdoutExporter outputs telemetry to stdout (for development)
	StdoutExporter ExporterType = "stdout"
	// OTLPExporter sends telemetry to an OTLP-compatible collector
	OTLPExporter ExporterType = "otlp"
)

// Config holds configuration for OpenTelemetry setup
type Config struct {
	// ServiceName is the name of the service in OpenTelemetry
	ServiceName string
	// ExporterType determines the format of telemetry output
	ExporterType ExporterType
	// OTLPEndpoint is the endpoint for OTLP exporters (e.g., "localhost:4317")
	OTLPEndpoint string
	// UseInsecure determines whether to use TLS with OTLP exporters
	UseInsecure bool
	// BatchTimeout is how frequently to send batches (lower for development)
	BatchTimeout time.Duration
	// MetricInterval is how often to collect metrics
	MetricInterval time.Duration
}

// SetupTelemetry initializes OpenTelemetry with the provided configuration
// It returns a logger, a shutdown function, and any error that occurred
func SetupTelemetry(ctx context.Context, config Config) (internallogger.Logger, func(context.Context) error, error) {
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 5 * time.Second
	}

	if config.MetricInterval == 0 {
		config.MetricInterval = 30 * time.Second
	}

	var shutdownFuncs []func(context.Context) error

	// Create a shutdown function that calls all registered shutdown functions
	shutdown := func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		return err
	}

	// Handle errors by attempting to clean up what's been set up so far
	handleErr := func(inErr error) (internallogger.Logger, func(context.Context) error, error) {
		shutdownErr := shutdown(ctx)
		if shutdownErr != nil {
			return internallogger.Logger{}, nil, errors.Join(inErr, fmt.Errorf("shutdown error: %v", shutdownErr))
		}
		return internallogger.Logger{}, nil, inErr
	}

	// Create resource with service attributes
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
		),
		resource.WithProcessRuntimeDescription(),
		resource.WithProcessRuntimeVersion(),
		resource.WithProcessExecutableName(),
		resource.WithProcessExecutablePath(),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create resource: %w", err))
	}

	// Set up propagator
	prop := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(prop)

	// Create logger
	logger := internallogger.NewLogger(config.ServiceName)

	// Set up logger provider
	loggerProvider, err := newLoggerProvider(ctx, config, res)
	if err != nil {
		return handleErr(err)
	}
	shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)
	global.SetLoggerProvider(loggerProvider)

	// Set up tracer provider
	tracerProvider, err := newTracerProvider(ctx, config, res)
	if err != nil {
		return handleErr(err)
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	// Set up meter provider
	meterReader, err := newMeterReader(ctx, config)
	if err != nil {
		return handleErr(err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(meterReader),
		sdkmetric.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	return logger, shutdown, nil
}

// Helper functions

func newTracerProvider(ctx context.Context, config Config, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	var traceExporter sdktrace.SpanExporter
	var sampler sdktrace.Sampler

	switch config.ExporterType {
	case OTLPExporter:
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(config.OTLPEndpoint),
		}

		if config.UseInsecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}

		exporter, err := otlptracegrpc.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}

		traceExporter = exporter
		sampler = sdktrace.TraceIDRatioBased(0.5)

	case StdoutExporter:
		exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout trace exporter: %w", err)
		}

		traceExporter = exporter
		sampler = sdktrace.AlwaysSample()

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(traceExporter, sdktrace.WithBatchTimeout(config.BatchTimeout)),
		sdktrace.WithResource(res),
	)

	return tracerProvider, nil
}

func newMeterReader(ctx context.Context, config Config) (sdkmetric.Reader, error) {
	switch config.ExporterType {
	case OTLPExporter:
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(config.OTLPEndpoint),
		}

		if config.UseInsecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}

		exporter, err := otlpmetricgrpc.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
		}

		return sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(config.MetricInterval)), nil

	case StdoutExporter:
		exporter, err := stdoutmetric.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout metric exporter: %w", err)
		}
		return sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(config.MetricInterval)), nil

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}
}

func newLoggerProvider(ctx context.Context, config Config, res *resource.Resource) (*sdklog.LoggerProvider, error) {
	var logProcessor sdklog.Processor

	switch config.ExporterType {
	case OTLPExporter:
		opts := []otlploggrpc.Option{
			otlploggrpc.WithEndpoint(config.OTLPEndpoint),
		}

		if config.UseInsecure {
			opts = append(opts, otlploggrpc.WithInsecure())
		}

		exporter, err := otlploggrpc.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
		}

		logProcessor = sdklog.NewBatchProcessor(exporter)

	case StdoutExporter:
		exporter, err := stdoutlog.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout log exporter: %w", err)
		}
		logProcessor = sdklog.NewBatchProcessor(exporter)

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(logProcessor),
		sdklog.WithResource(res),
	)

	return loggerProvider, nil
}
