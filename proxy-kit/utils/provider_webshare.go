package utils

import (
	"context"
	"fmt"
	"os"

	"proxy-kit"
)

const (
	webshareDefaultHost = "p.webshare.io"
	webshareDefaultPort = uint16(80)
)

// WebshareConfig is the configuration for the webshare proxy source.
type WebshareConfig struct {
	Username    string `toml:"username"     yaml:"username"     json:"username"`
	Amount      int    `toml:"amount"       yaml:"amount"       json:"amount"`
	PasswordEnv string `toml:"password_env" yaml:"password_env" json:"password_env"`
}

// WebshareSource is a proxy source backed by a generated fixed Webshare pool.
type WebshareSource struct {
	username string
	pool     *CountingPool[proxykit.Proxy]
}

// NewWebshareSource creates a WebshareSource from config.
func NewWebshareSource(cfg *WebshareConfig) (*WebshareSource, error) {
	if cfg.Username == "" {
		return nil, fmt.Errorf("webshare: username is required")
	}
	if cfg.Amount <= 0 {
		return nil, fmt.Errorf("webshare: amount must be > 0")
	}
	if cfg.PasswordEnv == "" {
		return nil, fmt.Errorf("webshare: password_env is required")
	}

	password := os.Getenv(cfg.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("webshare: env var %q not set or empty", cfg.PasswordEnv)
	}

	proxies := make([]proxykit.Proxy, 0, cfg.Amount)
	for i := 1; i <= cfg.Amount; i++ {
		proxies = append(proxies, proxykit.Proxy{
			Host:     webshareDefaultHost,
			Port:     webshareDefaultPort,
			Username: fmt.Sprintf("%s-%d", cfg.Username, i),
			Password: password,
			Protocol: proxykit.ProtocolHTTP,
		})
	}

	return &WebshareSource{
		username: cfg.Username,
		pool:     NewCountingPool(proxies),
	}, nil
}

// Resolve implements proxykit.Handler.
func (s *WebshareSource) Resolve(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
	p := s.pool.NextWithSeed(proxykit.GetSessionSeed(ctx))
	if p == nil {
		return nil, fmt.Errorf("webshare: empty proxy pool")
	}
	cp := *p
	return proxykit.Resolved(&cp), nil
}

// Describe returns a human-readable description.
func (s *WebshareSource) Describe() string {
	return fmt.Sprintf("webshare %s x%d @ %s:%d", s.username, s.pool.Len(), webshareDefaultHost, webshareDefaultPort)
}
