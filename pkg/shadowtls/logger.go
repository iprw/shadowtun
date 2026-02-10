package shadowtls

import (
	"context"

	"github.com/sirupsen/logrus"
)

// Logger implements the sing-shadowtls Logger interface
// and forwards logs to logrus at appropriate levels.
type Logger struct {
	L *logrus.Logger
}

// Trace is suppressed; library trace messages are noisy and redundant.
func (l *Logger) Trace(args ...any) {
}

// Debug forwards debug-level messages to logrus.
func (l *Logger) Debug(args ...any) {
	l.L.Debug(args...)
}

// Info forwards info-level messages to logrus.
func (l *Logger) Info(args ...any) {
	l.L.Info(args...)
}

// Warn forwards warn-level messages to logrus.
func (l *Logger) Warn(args ...any) {
	l.L.Warn(args...)
}

// Error forwards error-level messages to logrus.
func (l *Logger) Error(args ...any) {
	l.L.Error(args...)
}

// Fatal forwards fatal-level messages to logrus.
func (l *Logger) Fatal(args ...any) {
	l.L.Fatal(args...)
}

// Panic forwards panic-level messages to logrus.
func (l *Logger) Panic(args ...any) {
	l.L.Panic(args...)
}

// TraceContext is suppressed; see Trace.
func (l *Logger) TraceContext(ctx context.Context, args ...any) {
}

// DebugContext forwards debug-level messages with context to logrus.
func (l *Logger) DebugContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Debug(args...)
}

// InfoContext forwards info-level messages with context to logrus.
func (l *Logger) InfoContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Info(args...)
}

// WarnContext forwards warn-level messages with context to logrus.
func (l *Logger) WarnContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Warn(args...)
}

// ErrorContext forwards error-level messages with context to logrus.
func (l *Logger) ErrorContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Error(args...)
}

// FatalContext forwards fatal-level messages with context to logrus.
func (l *Logger) FatalContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Fatal(args...)
}

// PanicContext forwards panic-level messages with context to logrus.
func (l *Logger) PanicContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Panic(args...)
}
