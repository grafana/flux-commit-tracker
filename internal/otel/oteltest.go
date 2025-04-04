package otel

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// TestTelemetry provides testing utilities for OpenTelemetry
type TestTelemetry struct {
	// Logger is the test logger
	Logger *slog.Logger

	// Tracer returns a tracer with the given name
	Tracer trace.Tracer
	//
	// TraceExporter captures spans
	TraceExporter *tracetest.InMemoryExporter

	// TraceProcessor processes spans
	TraceProcessor sdktrace.SpanProcessor

	// SpanRecorder captures recorded spans
	SpanRecorder *tracetest.SpanRecorder

	// MetricReader allows manual collection of metrics
	MetricReader *sdkmetric.ManualReader

	// LogExporter captures logs
	LogExporter *testLogExporter

	// Shutdown gracefully cleans up resources
	Shutdown func(context.Context) error
}

// SetupTestTelemetry creates a test environment for OpenTelemetry instrumentation
func SetupTestTelemetry(ctx context.Context, serviceName string) (*TestTelemetry, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
		resource.WithTelemetrySDK(),
	)
	if err != nil {
		return nil, err
	}

	prop := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(prop)

	var shutdownFuncs []func(context.Context) error

	spanRecorder := tracetest.NewSpanRecorder()
	traceExporter := tracetest.NewInMemoryExporter()
	bsp := sdktrace.NewSimpleSpanProcessor(traceExporter)
	shutdownFuncs = append(shutdownFuncs, bsp.Shutdown)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(traceExporter),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	metricReader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(metricReader),
		sdkmetric.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	logger := slog.New(slog.DiscardHandler)
	logExporter := newTestLogExporter()
	logProcessor := sdklog.NewSimpleProcessor(logExporter)
	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(logProcessor),
		sdklog.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)

	shutdownFuncs = append(shutdownFuncs, func(ctx context.Context) error {
		spanRecorder.Reset()
		traceExporter.Reset()
		logExporter.Clear()

		return nil
	})

	shutdown := func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		return err
	}

	return &TestTelemetry{
		Logger:         logger,
		Tracer:         tracerProvider.Tracer(serviceName),
		TraceExporter:  traceExporter,
		TraceProcessor: bsp,
		SpanRecorder:   spanRecorder,
		MetricReader:   metricReader,
		LogExporter:    logExporter,
		Shutdown:       shutdown,
	}, nil
}

// Spans returns all recorded spans
func (t *TestTelemetry) Spans() []sdktrace.ReadOnlySpan {
	return t.SpanRecorder.Ended()
}

// SpansByName returns spans with the given name
func (t *TestTelemetry) SpansByName(name string) []sdktrace.ReadOnlySpan {
	var result []sdktrace.ReadOnlySpan
	for _, span := range t.SpanRecorder.Ended() {
		if span.Name() == name {
			result = append(result, span)
		}
	}
	return result
}

// FindSpan returns the first span with the given name, or nil if not found
func (t *TestTelemetry) FindSpan(ctx context.Context, name string) sdktrace.ReadOnlySpan {
	t.TraceProcessor.ForceFlush(ctx)

	spans := t.TraceExporter.GetSpans()
	if len(spans) == 0 {
		return nil
	}

	return spans.Snapshots()[0]
}

// ClearSpans clears all recorded spans
func (t *TestTelemetry) ClearSpans() {
	t.SpanRecorder.Reset()
	t.TraceExporter.Reset()
}

// ForceMetricCollection forces metrics to be collected
func (t *TestTelemetry) ForceMetricCollection(ctx context.Context) (*metricdata.ResourceMetrics, error) {
	var metrics metricdata.ResourceMetrics

	return &metrics, t.MetricReader.Collect(ctx, &metrics)
}

// Clear clears all telemetry data
func (t *TestTelemetry) Clear() {
	t.ClearSpans()
	t.LogExporter.Clear()
}

// testLogExporter is a simple log exporter for testing
type testLogExporter struct {
	logs []sdklog.Record
}

func newTestLogExporter() *testLogExporter {
	return &testLogExporter{
		logs: make([]sdklog.Record, 0),
	}
}

func (e *testLogExporter) Export(ctx context.Context, logs []sdklog.Record) error {
	e.logs = append(e.logs, logs...)
	return nil
}

func (e *testLogExporter) ForceFlush(ctx context.Context) error {
	return nil
}

func (e *testLogExporter) Shutdown(ctx context.Context) error {
	e.Clear()
	return nil
}

func (e *testLogExporter) Clear() {
	e.logs = nil
}

// Helper functions for testing

// AssertSpanStatus checks that a span has the expected status code and description
func AssertSpanStatus(t *testing.T, span sdktrace.ReadOnlySpan, code codes.Code) {
	t.Helper()
	if span.Status().Code == code {
		return
	}

	t.Errorf("Expected span status code %v, got %v", code, span.Status().Code)
}

// AssertSpanAttributes verifies a span has the expected attributes
func AssertSpanAttributes(t *testing.T, span sdktrace.ReadOnlySpan, expectedAttrs []attribute.KeyValue) {
	t.Helper()
	spanAttrs := span.Attributes()

nextAttr:
	for _, expectedAttr := range expectedAttrs {
		for _, attr := range spanAttrs {
			if attr.Key == expectedAttr.Key && attr.Value.AsString() == expectedAttr.Value.AsString() {
				continue nextAttr
			}
		}

		t.Errorf("Expected attribute %s=%s not found in span", expectedAttr.Key, expectedAttr.Value.AsString())
	}
}
