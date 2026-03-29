package main

import (
	"log/slog"
	"os"
	"path/filepath"
)

func main() {
	// Init logging from environment first so any early errors are structured.
	initLogging(os.Getenv("LOG_LEVEL"))

	configPath := "config.toml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	// Re-init logging with level from config (overrides env).
	if cfg.LogLevel != "" {
		initLogging(cfg.LogLevel)
	}

	configDir := filepath.Dir(configPath)
	if configDir == "" {
		configDir = "."
	}

	srv, err := BuildServer(cfg, configDir)
	if err != nil {
		slog.Error("failed to build server", "err", err)
		os.Exit(1)
	}

	if err := RunServer(cfg, srv, os.Getenv("API_KEY")); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func initLogging(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}
