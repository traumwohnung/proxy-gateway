package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"

	"proxy-gateway/core"
)

// RunServer starts the proxy and, optionally, the admin API and SOCKS5 listener.
// It blocks until a shutdown signal is received (SIGINT/SIGTERM), then drains.
func RunServer(cfg *Config, srv *Server, apiKey string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Admin API (separate listener, optional) ---
	if apiKey != "" && cfg.AdminAddr != "" {
		adminSrv := buildAdminServer(cfg.AdminAddr, srv.Sessions, apiKey)
		go func() {
			slog.Info("admin API listening", "addr", cfg.AdminAddr)
			if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("admin server error", "err", err)
			}
		}()
		defer adminSrv.Shutdown(context.Background())
	} else if apiKey != "" {
		slog.Warn("API_KEY set but admin_addr not configured — admin API disabled")
	}

	// --- SOCKS5 listener (background, no graceful drain needed for raw TCP) ---
	if cfg.Socks5Addr != "" {
		go func() {
			slog.Info("SOCKS5 proxy listening", "addr", cfg.Socks5Addr)
			if err := core.ListenSOCKS5(cfg.Socks5Addr, srv.Pipeline); err != nil {
				slog.Error("SOCKS5 server error", "err", err)
			}
		}()
	}

	// --- HTTP proxy (main listener) ---
	// The proxy handler is registered as middleware so it catches everything
	// that doesn't match an explicit route — no brittle /* catch-all.
	r := chi.NewRouter()
	r.Use(chiware.Recoverer)
	// Mount the proxy handler as chi middleware so it catches all requests
	// that don't match an explicit route — no fragile /* catch-all needed.
	proxyHandler := core.HTTPProxyHandler(srv.Pipeline)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxyHandler.ServeHTTP(w, r)
			// proxy handler fully handles the request; next is not called
		})
	})

	httpSrv := &http.Server{
		Addr:    cfg.BindAddr,
		Handler: r,
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutdown signal received, draining connections")
		httpSrv.Shutdown(context.Background())
	}()

	slog.Info("HTTP proxy listening", "addr", cfg.BindAddr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// buildAdminServer constructs the management REST API on a dedicated listener.
func buildAdminServer(addr string, sessions *core.SessionHandler, apiKey string) *http.Server {
	r := chi.NewRouter()
	r.Use(chiware.Recoverer)
	r.Route("/api", func(r chi.Router) {
		r.Get("/sessions", bearerAuth(apiKey, handleListSessions(sessions)))
		r.Get("/sessions/{key}", bearerAuth(apiKey, handleGetSession(sessions)))
		r.Post("/sessions/{key}/rotate", bearerAuth(apiKey, handleForceRotate(sessions)))
	})
	return &http.Server{Addr: addr, Handler: r}
}
