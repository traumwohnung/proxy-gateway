package core

// Protocol is the proxy protocol used to connect to the upstream.
type Protocol string

const (
	ProtocolHTTP   Protocol = "http"
	ProtocolSOCKS5 Protocol = "socks5"
)

// Proxy is a resolved upstream proxy endpoint.
type Proxy struct {
	Host     string
	Port     uint16
	Username string
	Password string
	Protocol Protocol
}

// Proto returns the protocol, defaulting to HTTP if empty.
func (p *Proxy) Proto() Protocol {
	if p.Protocol == "" {
		return ProtocolHTTP
	}
	return p.Protocol
}
