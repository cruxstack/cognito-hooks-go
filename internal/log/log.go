package log

import (
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

var (
	lv   = new(slog.LevelVar) // default info
	opts = &slog.HandlerOptions{Level: lv}
	base atomic.Value // *slog.Logger
)

func init() {
	l := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	base.Store(l)
}

// SetLevel changes the runtime log level: debug, info, warn, error.
func SetLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		lv.Set(slog.LevelDebug)
	case "warn", "warning":
		lv.Set(slog.LevelWarn)
	case "error":
		lv.Set(slog.LevelError)
	default:
		lv.Set(slog.LevelInfo)
	}
}

// MakeDefault sets slog.Default() to this package's logger.
func MakeDefault() {
	slog.SetDefault(From())
}

// With returns a child logger with default keyvals.
func With(args ...any) *slog.Logger {
	return From().With(args...)
}

// From returns the current base logger.
func From() *slog.Logger {
	if l, _ := base.Load().(*slog.Logger); l != nil {
		return l
	}
	l := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	base.Store(l)
	return l
}

// Debug logs at debug level.
func Debug(msg string, args ...any) {
	From().Debug(msg, args...)
}

// Info logs at info level.
func Info(msg string, args ...any) {
	From().Info(msg, args...)
}

// Warn logs at warn level.
func Warn(msg string, args ...any) {
	From().Warn(msg, args...)
}

// Error logs at error level.
func Error(msg string, args ...any) {
	From().Error(msg, args...)
}
