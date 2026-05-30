package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// healthPath is served on the main proxy listener for liveness/readiness.
// Plain origin-form GET requests (Host in the request line, empty URL.Host)
// never collide with real proxy traffic, which is either CONNECT or an
// absolute-form URI — so intercepting this one path is safe.
const healthPath = "/health"

// withHealth wraps the proxy handler so a direct `GET /health` returns 200
// without being forwarded upstream. Everything else passes through untouched.
func withHealth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Host == "" && r.URL.Path == healthPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// runHealthCheck is the `healthcheck` subcommand invoked by the container
// HEALTHCHECK. The image is built FROM scratch (no shell, curl or wget), so the
// binary probes itself: read the configured bind address and GET /health on the
// loopback. Exits 0 when the proxy answers 200, non-zero otherwise.
func runHealthCheck(configPath string) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: load config: %v\n", err)
		os.Exit(1)
	}
	_, port, err := net.SplitHostPort(cfg.BindAddr)
	if err != nil || port == "" {
		fmt.Fprintf(os.Stderr, "healthcheck: invalid bind_addr %q: %v\n", cfg.BindAddr, err)
		os.Exit(1)
	}
	url := fmt.Sprintf("http://127.0.0.1:%s%s", port, healthPath)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: GET %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		os.Exit(1)
	}
}
