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

func (l *Logger) Trace(args ...any) {
	// Suppressed — library trace messages ("handshake success") are noisy
	// and redundant with our own connection logging.
}

func (l *Logger) Debug(args ...any) {
	l.L.Debug(args...)
}

func (l *Logger) Info(args ...any) {
	l.L.Info(args...)
}

func (l *Logger) Warn(args ...any) {
	l.L.Warn(args...)
}

func (l *Logger) Error(args ...any) {
	l.L.Error(args...)
}

func (l *Logger) Fatal(args ...any) {
	l.L.Fatal(args...)
}

func (l *Logger) Panic(args ...any) {
	l.L.Panic(args...)
}

func (l *Logger) TraceContext(ctx context.Context, args ...any) {
	// Suppressed — see Trace()
}

func (l *Logger) DebugContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Debug(args...)
}

func (l *Logger) InfoContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Info(args...)
}

func (l *Logger) WarnContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Warn(args...)
}

func (l *Logger) ErrorContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Error(args...)
}

func (l *Logger) FatalContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Fatal(args...)
}

func (l *Logger) PanicContext(ctx context.Context, args ...any) {
	l.L.WithContext(ctx).Panic(args...)
}
