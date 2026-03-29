package geonode

import "proxy-gateway/utils"

// Config is the configuration for the geonode proxy source.
type Config struct {
	Username    string          `toml:"username"     yaml:"username"     json:"username"`
	PasswordEnv string          `toml:"password_env" yaml:"password_env" json:"password_env"`
	Gateway     GeonodeGateway  `toml:"gateway"      yaml:"gateway"      json:"gateway"`
	Protocol    GeonodeProtocol `toml:"protocol"     yaml:"protocol"     json:"protocol"`
	Countries   []utils.Country `toml:"countries"    yaml:"countries"    json:"countries"`
	Session     SessionConfig   `toml:"session"      yaml:"session"      json:"session"`
}

// Host returns the upstream proxy host for the configured gateway.
func (c *Config) Host() string {
	return c.Gateway.Host()
}

// Port returns the upstream proxy port based on protocol and session type.
func (c *Config) Port() uint16 {
	switch {
	case c.Protocol == GeonodeProtocolHTTP && c.Session.Type == SessionTypeRotating:
		return 9000
	case c.Protocol == GeonodeProtocolHTTP && c.Session.Type == SessionTypeSticky:
		return 10000
	case c.Protocol == GeonodeProtocolSocks5 && c.Session.Type == SessionTypeRotating:
		return 11000
	case c.Protocol == GeonodeProtocolSocks5 && c.Session.Type == SessionTypeSticky:
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
	default: // us
		return "us.premium-residential.geonode.com"
	}
}

// GeonodeProtocol is the proxy protocol.
type GeonodeProtocol string

const (
	GeonodeProtocolHTTP   GeonodeProtocol = "http"
	GeonodeProtocolSocks5 GeonodeProtocol = "socks5"
)

// SessionType differentiates rotating vs sticky sessions.
type SessionType string

const (
	SessionTypeRotating SessionType = "rotating"
	SessionTypeSticky   SessionType = "sticky"
)

// SessionConfig holds session-type configuration.
type SessionConfig struct {
	Type     SessionType `toml:"type"      yaml:"type"      json:"type"`
	SessTime uint32      `toml:"sess_time" yaml:"sess_time" json:"sess_time"`
}
