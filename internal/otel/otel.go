package otel

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	"go.opentelemetry.io/otel/sdk/metric"
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
	// ServiceName is the name of the service in telemetry
	ServiceName string
	// ExporterType determines where to send telemetry
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

// DefaultConfig returns a configuration suitable for development
func DefaultConfig(serviceName string) Config {
	return Config{
		ServiceName:    serviceName,
		ExporterType:   StdoutExporter,
		OTLPEndpoint:   "localhost:4317",
		UseInsecure:    true,
		BatchTimeout:   1 * time.Second,
		MetricInterval: 15 * time.Second,
	}
}

// SetupOTelSDK bootstraps the OpenTelemetry pipeline based on the provided configuration.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func SetupOTelSDK(ctx context.Context, config Config) (shutdown func(context.Context) error, err error) {
	var shutdownFuncs []func(context.Context) error

	// shutdown calls cleanup functions registered via shutdownFuncs.
	// The errors from the calls are joined.
	// Each registered cleanup will be invoked once.
	shutdown = func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// handleErr calls shutdown for cleanup and makes sure that all errors are returned.
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	// Create a resource describing the service
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
		),
	)
	if err != nil {
		handleErr(fmt.Errorf("failed to create resource: %w", err))
		return shutdown, err
	}

	// Set up propagator.
	prop := newPropagator()
	otel.SetTextMapPropagator(prop)

	// Set up trace provider.
	tracerProvider, err := newTracerProvider(ctx, config, res)
	if err != nil {
		handleErr(err)
		return shutdown, err
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	// Set up meter provider.
	meterProvider, err := newMeterProvider(ctx, config, res)
	if err != nil {
		handleErr(err)
		return shutdown, err
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	// Set up logger provider.
	loggerProvider, err := newLoggerProvider(ctx, config)
	if err != nil {
		handleErr(err)
		return shutdown, err
	}
	shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)
	global.SetLoggerProvider(loggerProvider)

	return shutdown, nil
}

func newPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func newTracerProvider(ctx context.Context, config Config, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	var traceExporter sdktrace.SpanExporter

	switch config.ExporterType {
	case StdoutExporter:
		exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout trace exporter: %w", err)
		}

		traceExporter = exporter

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

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(traceExporter, sdktrace.WithBatchTimeout(config.BatchTimeout)),
		sdktrace.WithResource(res),
	)

	return tracerProvider, nil
}

func newMeterProvider(ctx context.Context, config Config, res *resource.Resource) (*metric.MeterProvider, error) {
	var reader metric.Reader

	switch config.ExporterType {
	case StdoutExporter:
		exporter, err := stdoutmetric.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout metric exporter: %w", err)
		}
		reader = metric.NewPeriodicReader(exporter, metric.WithInterval(config.MetricInterval))

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

		reader = metric.NewPeriodicReader(exporter, metric.WithInterval(config.MetricInterval))

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(reader),
		metric.WithResource(res),
	)

	return meterProvider, nil
}

func newLoggerProvider(ctx context.Context, config Config) (*sdklog.LoggerProvider, error) {
	var logProcessor sdklog.Processor

	switch config.ExporterType {
	case StdoutExporter:
		exporter, err := stdoutlog.New()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout log exporter: %w", err)
		}
		logProcessor = sdklog.NewBatchProcessor(exporter)

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

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", config.ExporterType)
	}

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(logProcessor),
	)

	return loggerProvider, nil
}
