package utils

import (
	"context"
	"fmt"
	"os"
	"strings"

	"proxy-gateway/core"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// GeonodeConfig is the configuration for the geonode proxy source.
type GeonodeConfig struct {
	Username    string               `toml:"username"     yaml:"username"     json:"username"`
	PasswordEnv string               `toml:"password_env" yaml:"password_env" json:"password_env"`
	Gateway     GeonodeGateway       `toml:"gateway"      yaml:"gateway"      json:"gateway"`
	Protocol    GeonodeProtocol      `toml:"protocol"     yaml:"protocol"     json:"protocol"`
	Countries   []Country            `toml:"countries"    yaml:"countries"    json:"countries"`
	Session     GeonodeSessionConfig `toml:"session" yaml:"session"      json:"session"`
}

// Host returns the upstream proxy host for the configured gateway.
func (c *GeonodeConfig) Host() string {
	return c.Gateway.Host()
}

// Port returns the upstream proxy port based on protocol and session type.
func (c *GeonodeConfig) Port() uint16 {
	switch {
	case c.Protocol == GeonodeProtocolHTTP && c.Session.Type == GeonodeSessionRotating:
		return 9000
	case c.Protocol == GeonodeProtocolHTTP && c.Session.Type == GeonodeSessionSticky:
		return 10000
	case c.Protocol == GeonodeProtocolSocks5 && c.Session.Type == GeonodeSessionRotating:
		return 11000
	case c.Protocol == GeonodeProtocolSocks5 && c.Session.Type == GeonodeSessionSticky:
		return 12000
	}
	return 9000
}

// GeonodeGateway is the gateway location.
type GeonodeGateway string

const (
	GeonodeGatewayFR GeonodeGateway = "fr"
	GeonodeGatewayUS GeonodeGateway = "us"
	GeonodeGatewaySG GeonodeGateway = "sg"
)

// Host returns the proxy hostname for this gateway.
func (g GeonodeGateway) Host() string {
	switch g {
	case GeonodeGatewayFR:
		return "proxy.geonode.io"
	case GeonodeGatewaySG:
		return "sg.premium-residential.geonode.com"
	default:
		return "us.premium-residential.geonode.com"
	}
}

// GeonodeProtocol is the proxy protocol.
type GeonodeProtocol string

const (
	GeonodeProtocolHTTP   GeonodeProtocol = "http"
	GeonodeProtocolSocks5 GeonodeProtocol = "socks5"
)

// GeonodeSessionType differentiates rotating vs sticky sessions.
type GeonodeSessionType string

const (
	GeonodeSessionRotating GeonodeSessionType = "rotating"
	GeonodeSessionSticky   GeonodeSessionType = "sticky"
)

// GeonodeSessionConfig holds session-type configuration.
type GeonodeSessionConfig struct {
	Type     GeonodeSessionType `toml:"type"      yaml:"type"      json:"type"`
	SessTime uint32             `toml:"sess_time" yaml:"sess_time" json:"sess_time"`
}

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

// GeonodeSource is a proxy source backed by geonode.
type GeonodeSource struct {
	config   GeonodeConfig
	password string
}

// NewGeonodeSource creates a GeonodeSource from config.
func NewGeonodeSource(cfg *GeonodeConfig) (*GeonodeSource, error) {
	password := os.Getenv(cfg.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("geonode: env var %q not set or empty", cfg.PasswordEnv)
	}
	return &GeonodeSource{config: *cfg, password: password}, nil
}

// Resolve implements core.Handler.
func (s *GeonodeSource) Resolve(_ context.Context, _ *core.Request) (*core.Result, error) {
	proto := core.ProtocolHTTP
	if s.config.Protocol == GeonodeProtocolSocks5 {
		proto = core.ProtocolSOCKS5
	}
	return core.Resolved(&core.Proxy{
		Host:     s.config.Host(),
		Port:     s.config.Port(),
		Username: gnBuildUsername(&s.config),
		Password: s.password,
		Protocol: proto,
	}), nil
}

// Describe returns a human-readable description.
func (s *GeonodeSource) Describe() string {
	parts := []string{"geonode"}
	if len(s.config.Countries) > 0 {
		codes := make([]string, len(s.config.Countries))
		for i, c := range s.config.Countries {
			codes[i] = strings.ToUpper(c.AsParamStr())
		}
		parts = append(parts, strings.Join(codes, ","))
	}
	parts = append(parts, fmt.Sprintf("%s@%s:%d", s.config.Username, s.config.Host(), s.config.Port()))
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------
// Username building
// ---------------------------------------------------------------------------

func gnBuildUsername(cfg *GeonodeConfig) string {
	country := gnPickCountry(cfg.Countries)
	if cfg.Session.Type == GeonodeSessionSticky {
		return gnBuildSticky(cfg.Username, cfg.Session.SessTime, gnRandomSessionID(), country)
	}
	return gnBuildRotating(cfg.Username, country)
}

// GeonodeRotateUsername rebuilds the username with a new session ID.
func GeonodeRotateUsername(cfg *GeonodeConfig) string {
	return gnBuildUsername(cfg)
}

func gnBuildRotating(username string, country Country) string {
	if country == "" {
		return username
	}
	return fmt.Sprintf("%s-country-%s", username, strings.ToUpper(country.AsParamStr()))
}

func gnBuildSticky(username string, sessTime uint32, sessionID string, country Country) string {
	parts := []string{
		username,
		fmt.Sprintf("session-%s", sessionID),
		fmt.Sprintf("sessTime-%d", sessTime),
	}
	if country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", strings.ToUpper(country.AsParamStr())))
	}
	return strings.Join(parts, "-")
}

func gnPickCountry(countries []Country) Country {
	if len(countries) == 0 {
		return ""
	}
	return countries[int(CheapRandom())%len(countries)]
}

func gnRandomSessionID() string {
	a := CheapRandom()
	b := CheapRandom()
	return fmt.Sprintf("%016x", a^(b<<32))
}
