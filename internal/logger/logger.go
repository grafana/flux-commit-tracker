package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-logr/logr"
)

var (
	// A log level that is just below the debug level. This is used to write
	// metric/trace logs to stdout if the trace log level is enabled.
	LevelTrace = slog.Level(slog.LevelDebug - 1)
)

// NewDefaultLogger creates a basic slog logger writing JSON to stderr.
func NewDefaultLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

type LogrSink = logr.LogSink

// FromSlog creates a logr.Logger from a slog.Logger.
// This is needed because controller-runtime uses logr.
func FromSlog(logger *slog.Logger) logr.Logger {
	return logr.FromSlogHandler(logger.Handler())
}

// SlogWriter wraps a slog.Handler and implements io.Writer, so that it can be
// used by APIs that expect an io.Writer.
type SlogWriter struct {
	slog.Handler

	level   slog.Level
	context context.Context
}

// NewSlogWriter creates a new SlogWriter with the given handler and optional group
func NewSlogWriter(ctx context.Context, handler slog.Handler, group string, level slog.Level) *SlogWriter {
	return &SlogWriter{
		Handler: handler.WithGroup(group),
		level:   level,
		context: ctx,
	}
}

// Write implements io.Writer by logging the data at debug level
func (w *SlogWriter) Write(p []byte) (n int, err error) {
	record := slog.Record{
		Time:    time.Now(),
		Level:   w.level,
		Message: string(p),
	}

	if err := w.Handle(w.context, record); err != nil {
		return 0, fmt.Errorf("failed to write log: %w", err)
	}

	return len(p), nil
}

type LogLevel slog.Level

func (l *LogLevel) UnmarshalText(text []byte) error {
	var level slog.Level
	if err := level.UnmarshalText(text); err != nil {
		return err
	}

	*l = LogLevel(level)
	return nil
}
