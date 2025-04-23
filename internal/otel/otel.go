package otel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	otelslogtracehandler "github.com/go-slog/otelslog"
	"github.com/grafana/flux-commit-tracker/internal/buildinfo"
	"github.com/grafana/flux-commit-tracker/internal/logger"
	slogmulti "github.com/samber/slog-multi"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

type shutdownFunc = func(context.Context) error

// TelemetryMode defines the operational mode for telemetry.
type TelemetryMode string

const (
	// ModeStdoutLogs prints logs to stdout using tint (if TTY) or JSON (if not
	// TTY), discards metrics/traces.
	ModeStdoutLogs TelemetryMode = "stdout-logs"
	// ModeStdoutAll prints logs to stdout as per `ModeStdoutLogs`, but also
	// exports metrics/traces to stdout.
	ModeStdoutAll TelemetryMode = "stdout-all"
	// ModeOTLP exports all signals via OTLP.
	ModeOTLP TelemetryMode = "otlp"
	// ModeStdoutLogsOTLP prints logs to stdout as per `ModeStdoutLogs`, but
	// exports all signals via OTLP.
	ModeStdoutLogsOTLP TelemetryMode = "stdout-logs+otlp"
	// ModeStdoutAllOTLP prints logs/exports to stdout as per `ModeStdoutAll`, but
	// exports all signals via OTLP.
	ModeStdoutAllOTLP TelemetryMode = "stdout-all+otlp"
)

// IncludesOTLP returns true if signals should be exported via OTLP.
func (m TelemetryMode) IncludesOTLP() bool {
	return m == ModeOTLP || m == ModeStdoutLogsOTLP || m == ModeStdoutAllOTLP
}

// IncludesStdoutLogs returns true if logs should be printed to stdout.
func (m TelemetryMode) IncludesStdoutLogs() bool {
	return m == ModeStdoutLogs || m == ModeStdoutLogsOTLP || m == ModeStdoutAll || m == ModeStdoutAllOTLP
}

// IncludesVerbose returns true if signals should be printed to stdout.
func (m TelemetryMode) IncludesVerbose() bool {
	return m == ModeStdoutAll || m == ModeStdoutAllOTLP
}

// Config holds configuration for OpenTelemetry setup
type Config struct {
	// Mode determines how telemetry signals are processed and exported.
	Mode TelemetryMode
	// OTLPEndpoint is the endpoint for OTLP exporters (e.g., "localhost:4317")
	OTLPEndpoint string
	// UseInsecure determines whether to use TLS with OTLP exporters
	UseInsecure bool
	// BatchTimeout is how frequently to send batches (lower for development)
	BatchTimeout time.Duration
	// MetricInterval is how often to collect metrics
	MetricInterval time.Duration
}

func callShutdownFuncs(ctx context.Context, funcs []shutdownFunc) error {
	var err error
	for _, fn := range funcs {
		err = errors.Join(err, fn(ctx))
	}

	return err
}

// newTracerProvider creates a TracerProvider based on the mode.
// Returns the provider, its shutdown function, and any error.
// Returns nil provider if tracing is disabled for the mode.
func newTracerProvider(ctx context.Context, config Config, baseHandler slog.Handler, res *resource.Resource) (*sdktrace.TracerProvider, func(context.Context) error, error) {
	if config.Mode == ModeStdoutLogs {
		return nil, nil, nil
	}

	if !config.Mode.IncludesVerbose() && !config.Mode.IncludesOTLP() {
		return nil, nil, nil
	}

	var exporters []sdktrace.SpanExporter
	var exporterShutdownFuncs []shutdownFunc
	sampler := sdktrace.AlwaysSample()

	if config.Mode.IncludesOTLP() {
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(config.OTLPEndpoint),
		}
		if config.UseInsecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		exporter, err := otlptracegrpc.New(ctx, opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}

		exporters = append(exporters, exporter)
		exporterShutdownFuncs = append(exporterShutdownFuncs, exporter.Shutdown)
	}

	// In verbose mode, print traces to stdout.
	if config.Mode.IncludesVerbose() {
		slogWriter := logger.NewSlogWriter(ctx, baseHandler, "", logger.LevelTrace)
		exporter, err := stdouttrace.New(
			stdouttrace.WithWriter(slogWriter),
			stdouttrace.WithPrettyPrint(),
			stdouttrace.WithoutTimestamps(),
		)
		if err != nil {
			shutdownErr := callShutdownFuncs(ctx, exporterShutdownFuncs)
			return nil, nil, errors.Join(fmt.Errorf("failed to create stdout trace exporter: %w", err), shutdownErr)
		}

		exporters = append(exporters, exporter)
	}

	traceProviderOptions := make([]sdktrace.TracerProviderOption, 0, len(exporters)+2)
	traceProviderOptions = append(traceProviderOptions,
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	)

	batchSpanProcessorShutdownFuncs := make([]shutdownFunc, 0, len(exporters))
	for _, exporter := range exporters {
		bsp := sdktrace.NewBatchSpanProcessor(exporter, sdktrace.WithBatchTimeout(config.BatchTimeout))
		traceProviderOptions = append(traceProviderOptions, sdktrace.WithSpanProcessor(bsp))
		batchSpanProcessorShutdownFuncs = append(batchSpanProcessorShutdownFuncs, bsp.Shutdown)
	}

	tracerProvider := sdktrace.NewTracerProvider(traceProviderOptions...)

	shutdown := func(ctx context.Context) error {
		bspErr := callShutdownFuncs(ctx, batchSpanProcessorShutdownFuncs)
		exporterErr := callShutdownFuncs(ctx, exporterShutdownFuncs)
		return errors.Join(bspErr, exporterErr)
	}

	return tracerProvider, shutdown, nil
}

// newMeterProvider creates a MeterProvider based on the mode.
// Returns the provider, its shutdown function, and any error.
// Returns nil provider if metrics are disabled for the mode.
func newMeterProvider(ctx context.Context, config Config, baseHandler slog.Handler, res *resource.Resource) (*sdkmetric.MeterProvider, func(context.Context) error, error) {
	if config.Mode == ModeStdoutLogs {
		return nil, nil, nil
	}

	if !config.Mode.IncludesVerbose() && !config.Mode.IncludesOTLP() {
		return nil, nil, nil
	}

	view := sdkmetric.NewView(
		sdkmetric.Instrument{
			Kind: sdkmetric.InstrumentKindHistogram,
			Scope: instrumentation.Scope{
				Name: "tracker",
			},
		},
		sdkmetric.Stream{
			Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{
				MaxSize:  160,
				MaxScale: 20,
				NoMinMax: true,
			},
		},
	)

	meterProviderOptions := []sdkmetric.Option{sdkmetric.WithResource(res), sdkmetric.WithView(view)}
	exporterShutdownFuncs := []shutdownFunc{}

	if config.Mode.IncludesOTLP() {
		opts := []otlpmetricgrpc.Option{
			otlpmetricgrpc.WithEndpoint(config.OTLPEndpoint),
		}

		if config.UseInsecure {
			opts = append(opts, otlpmetricgrpc.WithInsecure())
		}

		exporter, err := otlpmetricgrpc.New(ctx, opts...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
		}

		reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(config.MetricInterval))
		meterProviderOptions = append(meterProviderOptions, sdkmetric.WithReader(reader))
		exporterShutdownFuncs = append(exporterShutdownFuncs, exporter.Shutdown)
	}

	// In verbose mode, print metrics to stdout.
	if config.Mode.IncludesVerbose() {
		slogWriter := logger.NewSlogWriter(ctx, baseHandler, "", logger.LevelTrace)
		exporter, err := stdoutmetric.New(
			stdoutmetric.WithWriter(slogWriter),
			stdoutmetric.WithPrettyPrint(),
			stdoutmetric.WithoutTimestamps(),
		)
		if err != nil {
			shutdownErr := callShutdownFuncs(ctx, exporterShutdownFuncs)
			return nil, nil, errors.Join(fmt.Errorf("failed to create stdout metric exporter: %w", err), shutdownErr)
		}
		reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(config.MetricInterval))
		meterProviderOptions = append(meterProviderOptions, sdkmetric.WithReader(reader))
	}

	meterProvider := sdkmetric.NewMeterProvider(meterProviderOptions...)

	shutdown := func(shutdownCtx context.Context) error {
		providerErr := meterProvider.Shutdown(shutdownCtx)
		exporterErr := callShutdownFuncs(shutdownCtx, exporterShutdownFuncs)
		return errors.Join(providerErr, exporterErr)
	}

	return meterProvider, shutdown, nil
}

// newOTLPLogProcessor creates an OTLP log processor if the mode requires it.
// Returns the processor, its shutdown function, and any error.
func newOTLPLogProcessor(ctx context.Context, config Config) (sdklog.Processor, func(context.Context) error, error) {
	if !config.Mode.IncludesOTLP() {
		return nil, nil, nil
	}

	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(config.OTLPEndpoint),
	}
	if config.UseInsecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}
	otlpExporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	processor := sdklog.NewBatchProcessor(otlpExporter)
	shutdown := otlpExporter.Shutdown

	return processor, shutdown, nil
}

// setupLoggingHandler configures the logging handler based on the telemetry mode.
// It determines if logs should go to OTLP, stdout, or both, and sets up the
// necessary providers and handlers.
// Returns the final slog.Handler, a slice of shutdown functions specific to logging,
// and any error that occurred.
func setupLoggingHandler(ctx context.Context, config Config, baseHandler slog.Handler, res *resource.Resource) (slog.Handler, []shutdownFunc, error) {
	finalHandler := baseHandler
	var loggingShutdownFuncs []shutdownFunc

	otlpLogProcessor, otlpLogShutdown, err := newOTLPLogProcessor(ctx, config)
	if err != nil {
		return nil, nil, err // Error already wrapped in newOTLPLogProcessor
	}

	if otlpLogProcessor != nil {
		loggerProvider := sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(otlpLogProcessor),
		)

		loggingShutdownFuncs = append(loggingShutdownFuncs, loggerProvider.Shutdown, otlpLogShutdown)
		global.SetLoggerProvider(loggerProvider)

		// Create a handler that sends logs to the global OTLP provider
		otelBridgeHandler := otelslog.NewHandler("github.com/grafana/flux-commit-tracker")

		if config.Mode.IncludesStdoutLogs() {
			// Combine base and OTLP handlers using slogmulti. This means that logs
			// written using `logger` will be sent to both the base handler (stdout) and
			// the OTLP handler.
			finalHandler = slogmulti.Fanout(baseHandler, otelBridgeHandler)
			// Automatically add trace and span IDs to log messages, if slog's
			// `*Context` methods are used
			finalHandler = otelslogtracehandler.NewHandler(finalHandler)
		} else {
			// If not logging to stdout, just use the OTLP bridge
			finalHandler = otelBridgeHandler
		}
	}

	return finalHandler, loggingShutdownFuncs, nil
}

// SetupTelemetry initializes OpenTelemetry with the provided configuration and base handler.
// It returns a configured slog Logger, a shutdown function, and any error that occurred.
func SetupTelemetry(ctx context.Context, config Config, baseHandler slog.Handler) (*slog.Logger, func(context.Context) error, error) {
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 5 * time.Second
	}

	if config.MetricInterval == 0 {
		config.MetricInterval = 30 * time.Second
	}

	var allShutdownFuncs []shutdownFunc
	shutdown := func(ctx context.Context) error {
		var err error
		for _, shutdownFunc := range allShutdownFuncs {
			err = errors.Join(err, shutdownFunc(ctx))
		}
		return err
	}

	logHandler := baseHandler
	handleErr := func(inErr error) (*slog.Logger, func(context.Context) error, error) {
		shutdownErr := shutdown(ctx)
		finalErr := errors.Join(inErr, shutdownErr)
		if finalErr != nil {
			// Use default logger here as our configured one might have failed
			slog.New(logHandler).Error("Telemetry setup failed", "error", finalErr)
		}
		return nil, shutdown, finalErr
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(

			semconv.ServiceName("flux-commit-tracker"),
			semconv.ServiceVersion(buildinfo.Version),
			semconv.VCSRefHeadRevision(buildinfo.Commit),
			semconv.VCSRefHeadName(buildinfo.Branch),
		),
		resource.WithContainer(),
		resource.WithHost(),
		resource.WithProcess(),
		resource.WithOS(),
	)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create initial resources: %w", err))
	}

	res, err = resource.Merge(
		resource.Default(),
		res,
	)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create merged resources: %w", err))
	}

	prop := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(prop)

	// Setup logging first
	finalHandler, loggingShutdownFuncs, err := setupLoggingHandler(ctx, config, baseHandler, res)
	if err != nil {
		return handleErr(err) // Error already wrapped in setupLoggingHandler
	}
	allShutdownFuncs = append(allShutdownFuncs, loggingShutdownFuncs...)

	// Create the primary logger instance using the potentially wrapped handler
	logHandler = finalHandler
	logger := slog.New(logHandler)

	// Pass the *original* baseHandler to tracer/meter providers for stdout export
	tracerProvider, traceShutdown, err := newTracerProvider(ctx, config, baseHandler, res)
	if err != nil {
		return handleErr(err)
	}

	if tracerProvider != nil {
		allShutdownFuncs = append(allShutdownFuncs, traceShutdown)
		otel.SetTracerProvider(tracerProvider)
	}

	meterProvider, meterShutdown, err := newMeterProvider(ctx, config, baseHandler, res)
	if err != nil {
		return handleErr(err)
	}

	if meterProvider != nil {
		allShutdownFuncs = append(allShutdownFuncs, meterShutdown)
		otel.SetMeterProvider(meterProvider)
	}

	return logger, shutdown, nil
}
