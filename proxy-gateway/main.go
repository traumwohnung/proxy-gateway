package main

import (
	"log/slog"
	"os"
	"path/filepath"

	"proxy-gateway/analytics"
)

func main() {
	initLogging(os.Getenv("LOG_LEVEL"))

	// `healthcheck [config]` self-probes the running proxy (used by the
	// distroless container HEALTHCHECK, which has no shell/curl).
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		hcConfig := "config.toml"
		if len(os.Args) > 2 {
			hcConfig = os.Args[2]
		}
		runHealthCheck(hcConfig)
		return
	}

	configPath := "config.toml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		slog.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	if os.Getenv("LOG_LEVEL") == "" && cfg.LogLevel != "" {
		initLogging(cfg.LogLevel)
	}

	configDir := filepath.Dir(configPath)
	if configDir == "" {
		configDir = "."
	}

	// --- Analytics (optional) ---
	var tracker *UsageTracker
	if addr := os.Getenv("ANALYTICS_GRPC_ADDR"); addr != "" {
		client, err := analytics.Dial(addr, os.Getenv("INGEST_TOKEN"))
		if err != nil {
			slog.Error("failed to dial analytics service", "err", err)
			os.Exit(1)
		}
		tracker = NewUsageTracker(client)
		slog.Info("usage tracking enabled", "analytics_addr", addr)
		defer client.Close() //nolint:errcheck
	} else {
		slog.Info("ANALYTICS_GRPC_ADDR not set, usage tracking disabled")
	}

	srv, err := BuildServer(cfg, configDir, os.Getenv("PROXY_PASSWORD"), tracker)
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
