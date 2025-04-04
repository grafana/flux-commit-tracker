package otel

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
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
func (tt *TestTelemetry) FindSpan(t *testing.T, ctx context.Context, name string) sdktrace.ReadOnlySpan {
	t.Helper()

	err := tt.TraceProcessor.ForceFlush(ctx)
	require.NoError(t, err)

	spans := tt.TraceExporter.GetSpans()
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

// FindMetric searches for a specific metric by name within ResourceMetrics
func FindMetric(rm *metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	if rm == nil {
		return nil
	}

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				// Return a pointer to a copy to avoid unintended modifications
				metricCopy := m
				return &metricCopy
			}
		}
	}
	return nil
}

// AssertMetricValueExists checks if a metric with the specified name exists.
func AssertMetricValueExists(t *testing.T, rm *metricdata.ResourceMetrics, name string) {
	t.Helper()

	metric := FindMetric(rm, name)
	require.NotNil(t, metric, "Expected metric '%s' not found", name)
}

// AssertHistogramValue checks if a histogram metric exists and its single data point
// matches the expected value (within a tolerance).
func AssertHistogramValue(t *testing.T, rm *metricdata.ResourceMetrics, name string, expectedValue float64) {
	t.Helper()
	metric := FindMetric(rm, name)
	require.NotNil(t, metric, "Metric '%s' not found", name)

	hist, ok := metric.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "Metric '%s' is not a float64 Histogram", name)

	require.Len(t, hist.DataPoints, 1, "Expected 1 data point for metric '%s', got %d", name, len(hist.DataPoints))
	dp := hist.DataPoints[0]

	require.Equal(t, uint64(1), dp.Count, "Expected count 1 for metric '%s', got %d", name, dp.Count)

	tolerance := 1e-9
	require.InDelta(t, expectedValue, dp.Sum, tolerance, "Expected sum %.6f for metric '%s', got %.6f", expectedValue, name, dp.Sum)

	min, ok := dp.Min.Value()
	require.True(t, ok, "Expected min for metric '%s', got none", name)
	require.InDelta(t, expectedValue, min, tolerance, "Expected min %.9f for metric '%s', got %.9f", expectedValue, name, dp.Min)

	max, ok := dp.Max.Value()
	require.True(t, ok, "Expected max for metric '%s', got none", name)
	require.InDelta(t, expectedValue, max, tolerance, "Expected max %.9f for metric '%s', got %.9f", expectedValue, name, dp.Max)
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
