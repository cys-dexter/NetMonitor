package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// InitLogger initializes the global structured logger using Go 1.21's log/slog.
// Logs are written to a dedicated file to prevent corrupting the TUI terminal display.
func InitLogger(filePath string, levelStr string) (*slog.Logger, func(), error) {
	var level slog.Level
	switch strings.ToUpper(strings.TrimSpace(levelStr)) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}

	var writer io.Writer
	var cleanup func() = func() {}

	if filePath != "" && filePath != "stderr" && filePath != "stdout" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file '%s': %w", filePath, err)
		}
		writer = f
		cleanup = func() {
			_ = f.Sync()
			_ = f.Close()
		}
	} else if filePath == "stdout" {
		writer = os.Stdout
	} else {
		writer = os.Stderr
	}

	handler := slog.NewJSONHandler(writer, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, cleanup, nil
}
