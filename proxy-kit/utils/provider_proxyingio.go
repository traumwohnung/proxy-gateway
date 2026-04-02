package utils

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"proxy-kit"
)

const (
	proxyingioDefaultHost     = "proxy.proxying.io"
	proxyingioDefaultLifetime = 60
	proxyingioSessionCharset  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	proxyingioSessionLength   = 6
)

// ProxyingIOProtocol is the upstream proxy protocol.
type ProxyingIOProtocol string

const (
	ProxyingIOProtocolHTTP   ProxyingIOProtocol = "http"
	ProxyingIOProtocolSocks5 ProxyingIOProtocol = "socks5"
)

// ProxyingIOConfig is the configuration for the proxying.io proxy source.
type ProxyingIOConfig struct {
	Username        string             `toml:"username"         yaml:"username"         json:"username"`
	PasswordEnv     string             `toml:"password_env"     yaml:"password_env"     json:"password_env"`
	Host            string             `toml:"host"             yaml:"host"             json:"host"`
	Protocol        ProxyingIOProtocol `toml:"protocol"         yaml:"protocol"         json:"protocol"`
	Port            uint16             `toml:"port"             yaml:"port"             json:"port"`
	Countries       []Country          `toml:"countries"        yaml:"countries"        json:"countries"`
	HighQuality     *bool              `toml:"high_quality"     yaml:"high_quality"     json:"high_quality"`
	DefaultLifetime int                `toml:"default_lifetime" yaml:"default_lifetime" json:"default_lifetime"`
}

// ProxyingIOSource is a proxy source backed by proxying.io.
type ProxyingIOSource struct {
	config       ProxyingIOConfig
	basePassword string
}

// NewProxyingIOSource creates a ProxyingIOSource from config.
func NewProxyingIOSource(cfg *ProxyingIOConfig) (*ProxyingIOSource, error) {
	if cfg.Username == "" {
		return nil, fmt.Errorf("proxyingio: username is required")
	}
	if cfg.PasswordEnv == "" {
		return nil, fmt.Errorf("proxyingio: password_env is required")
	}
	basePassword := os.Getenv(cfg.PasswordEnv)
	if basePassword == "" {
		return nil, fmt.Errorf("proxyingio: env var %q not set or empty", cfg.PasswordEnv)
	}

	normalized := *cfg
	if normalized.Host == "" {
		normalized.Host = proxyingioDefaultHost
	}
	if normalized.Protocol == "" {
		normalized.Protocol = ProxyingIOProtocolHTTP
	}
	if normalized.Port == 0 {
		normalized.Port = normalized.defaultPort()
	}
	if normalized.DefaultLifetime < 0 {
		return nil, fmt.Errorf("proxyingio: default_lifetime must be >= 0")
	}
	if normalized.DefaultLifetime == 0 {
		normalized.DefaultLifetime = proxyingioDefaultLifetime
	}
	if normalized.Protocol != ProxyingIOProtocolHTTP && normalized.Protocol != ProxyingIOProtocolSocks5 {
		return nil, fmt.Errorf("proxyingio: unsupported protocol %q (expected: http, socks5)", normalized.Protocol)
	}

	return &ProxyingIOSource{config: normalized, basePassword: basePassword}, nil
}

// Resolve implements proxykit.Handler.
func (s *ProxyingIOSource) Resolve(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
	seed := proxykit.GetSessionSeed(ctx)
	proto := proxykit.ProtocolHTTP
	if s.config.Protocol == ProxyingIOProtocolSocks5 {
		proto = proxykit.ProtocolSOCKS5
	}
	return proxykit.Resolved(&proxykit.Proxy{
		Host:     s.config.Host,
		Port:     s.config.Port,
		Username: s.config.Username,
		Password: pioBuildPassword(s.basePassword, &s.config, GetMeta(ctx), GetSeedTTL(ctx), seed),
		Protocol: proto,
	}), nil
}

// Describe returns a human-readable description.
func (s *ProxyingIOSource) Describe() string {
	parts := []string{"proxyingio"}
	if len(s.config.Countries) > 0 {
		codes := make([]string, len(s.config.Countries))
		for i, c := range s.config.Countries {
			codes[i] = strings.ToUpper(c.AsParamStr())
		}
		parts = append(parts, fmt.Sprintf("countries=[%s]", strings.Join(codes, ",")))
	}
	parts = append(parts, fmt.Sprintf("%s@%s:%d", s.config.Username, s.config.Host, s.config.Port))
	return strings.Join(parts, " ")
}

func (c ProxyingIOConfig) defaultPort() uint16 {
	if c.Protocol == ProxyingIOProtocolSocks5 {
		return 1080
	}
	return 8080
}

func pioBuildPassword(basePassword string, cfg *ProxyingIOConfig, meta Meta, ttl time.Duration, seed *proxykit.SessionSeed) string {
	parts := []string{basePassword}
	if seed != nil {
		parts = append(parts, fmt.Sprintf("session-%s", pioSessionID(seed)))
		if lifetime := pioLifetimeStr(meta, ttl, cfg.DefaultLifetime); lifetime != "" {
			parts = append(parts, fmt.Sprintf("lifetime-%s", lifetime))
		}
	}
	if countries := pioCountriesStr(cfg.Countries); countries != "" {
		parts = append(parts, fmt.Sprintf("country-%s", countries))
	}
	if cfg.HighQuality != nil && *cfg.HighQuality {
		parts = append(parts, "quality-high")
	}
	return strings.Join(parts, "_")
}

func pioSessionID(seed *proxykit.SessionSeed) string {
	if seed != nil {
		return seed.DeriveStringKey(proxyingioSessionCharset, proxyingioSessionLength)
	}

	var b strings.Builder
	b.Grow(proxyingioSessionLength)
	for range proxyingioSessionLength {
		b.WriteByte(proxyingioSessionCharset[CheapRandom()%uint64(len(proxyingioSessionCharset))])
	}
	return b.String()
}

func pioLifetimeStr(meta Meta, ttl time.Duration, defaultLifetime int) string {
	v := meta["lifetime"]
	if v == nil {
		if ttl > 0 {
			return fmt.Sprintf("%d", int(ttl/time.Minute))
		}
		if defaultLifetime > 0 {
			return fmt.Sprintf("%d", defaultLifetime)
		}
		return ""
	}
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return fmt.Sprintf("%g", vv)
	default:
		return fmt.Sprintf("%v", vv)
	}
}

func pioCountriesStr(countries []Country) string {
	if len(countries) == 0 {
		return ""
	}
	values := make([]string, 0, len(countries))
	for _, country := range countries {
		if country == "" {
			continue
		}
		values = append(values, strings.ToUpper(country.AsParamStr()))
	}
	return strings.Join(values, ",")
}
