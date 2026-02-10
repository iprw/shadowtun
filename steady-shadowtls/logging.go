package main

import (
	"context"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// Log is the global logger
var Log = logrus.New()

// InitLogging sets up the logger with the specified verbosity level
// verbosity: 0=warn, 1=info, 2=debug, 3+=trace
func InitLogging(verbosity int) {
	Log.SetOutput(os.Stdout)
	Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006/01/02 15:04:05",
		DisableColors:   false,
	})

	switch {
	case verbosity <= 0:
		Log.SetLevel(logrus.WarnLevel)
	case verbosity == 1:
		Log.SetLevel(logrus.InfoLevel)
	case verbosity == 2:
		Log.SetLevel(logrus.DebugLevel)
	default:
		Log.SetLevel(logrus.TraceLevel)
	}

	Log.Debugf("Log level set to %s (verbosity=%d)", Log.GetLevel(), verbosity)
}

// ParseVerbosity counts the number of 'v' characters in the verbose flag
// Supports: -v, -vv, -vvv, -vvvv, etc.
// Returns verbosity level and filtered args (with -v* flags removed)
func ParseVerbosity(args []string) (int, []string) {
	verbosity := 0
	filtered := make([]string, 0, len(args))

	for _, arg := range args {
		if strings.HasPrefix(arg, "-v") && !strings.Contains(arg, "=") && !strings.HasPrefix(arg, "-verbose") {
			// Count 'v's in -v, -vv, -vvv, etc.
			// Only match pure -v flags, not -version or other -v* flags
			trimmed := strings.TrimLeft(arg, "-")
			if len(trimmed) > 0 && strings.Trim(trimmed, "v") == "" {
				verbosity = len(trimmed)
				continue // Don't add to filtered
			}
		}
		filtered = append(filtered, arg)
	}
	return verbosity, filtered
}

// ShadowTLSLogger implements the sing-shadowtls Logger interface
// and forwards logs to logrus at appropriate levels
type ShadowTLSLogger struct{}

func (l *ShadowTLSLogger) Trace(args ...any) {
	// Suppressed — library trace messages ("handshake success") are noisy
	// and redundant with our own connection logging.
}

func (l *ShadowTLSLogger) Debug(args ...any) {
	Log.Debug(args...)
}

func (l *ShadowTLSLogger) Info(args ...any) {
	Log.Info(args...)
}

func (l *ShadowTLSLogger) Warn(args ...any) {
	Log.Warn(args...)
}

func (l *ShadowTLSLogger) Error(args ...any) {
	Log.Error(args...)
}

func (l *ShadowTLSLogger) Fatal(args ...any) {
	Log.Fatal(args...)
}

func (l *ShadowTLSLogger) Panic(args ...any) {
	Log.Panic(args...)
}

func (l *ShadowTLSLogger) TraceContext(ctx context.Context, args ...any) {
	// Suppressed — see Trace()
}

func (l *ShadowTLSLogger) DebugContext(ctx context.Context, args ...any) {
	Log.WithContext(ctx).Debug(args...)
}

func (l *ShadowTLSLogger) InfoContext(ctx context.Context, args ...any) {
	Log.WithContext(ctx).Info(args...)
}

func (l *ShadowTLSLogger) WarnContext(ctx context.Context, args ...any) {
	Log.WithContext(ctx).Warn(args...)
}

func (l *ShadowTLSLogger) ErrorContext(ctx context.Context, args ...any) {
	Log.WithContext(ctx).Error(args...)
}

func (l *ShadowTLSLogger) FatalContext(ctx context.Context, args ...any) {
	Log.WithContext(ctx).Fatal(args...)
}

func (l *ShadowTLSLogger) PanicContext(ctx context.Context, args ...any) {
	Log.WithContext(ctx).Panic(args...)
}
