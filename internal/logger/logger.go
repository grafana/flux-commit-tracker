package logger

import (
	"github.com/go-logr/logr"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/logtest"
)

type Logger struct {
	logr.Logger
}

func NewLogger(otelName string) Logger {
	otelHandler := otelslog.NewHandler(otelName)
	logger := logr.FromSlogHandler(otelHandler)
	otel.SetLogger(logger)

	return Logger{logger}
}

func NewTestLogger(otelName string) Logger {
	recorder := logtest.NewRecorder()
	otelLogger := otelslog.NewLogger(
		otelName,
		otelslog.WithLoggerProvider(recorder),
	)

	logger := logr.FromSlogHandler(otelLogger.Handler())
	otel.SetLogger(logger)

	return Logger{logger}
}

// These are based on https://github.com/kubernetes/community/blob/35444da79dff9a448e7ecf24b277e5f71373840a/contributors/devel/sig-instrumentation/logging.md#what-method-to-use

func (l Logger) Error(msg string, keysAndValues ...interface{}) {
	l.V(0).Info(msg, keysAndValues...)
}

func (l Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.V(1).Info(msg, keysAndValues...)
}

func (l Logger) Info(msg string, keysAndValues ...interface{}) {
	l.V(2).Info(msg, keysAndValues...)
}

func (l Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.V(4).Info(msg, keysAndValues...)
}

func (l Logger) Trace(msg string, keysAndValues ...interface{}) {
	l.V(5).Info(msg, keysAndValues...)
}
