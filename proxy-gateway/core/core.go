// Package core defines the fundamental types for the proxy gateway pipeline.
//
// The entire system is built around one interface: Handler. Everything —
// credential parsing, authentication, rate limiting, session affinity, proxy
// source selection — is a Handler that either enriches the Request context
// and delegates to the next handler, or terminates the chain by returning
// a Proxy.
//
// The gateway transport layer (HTTP, SOCKS5) only populates RawUsername and
// RawPassword from the protocol. All semantic parsing (extracting sub, set,
// meta, session TTL) is done by middleware — there is no hardcoded username
// format in core or gateway.
package core

import (
	"context"
)

// Handler resolves an inbound proxy request to an upstream Proxy.
type Handler interface {
	Resolve(ctx context.Context, req *Request) (*Proxy, error)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *Request) (*Proxy, error)

func (f HandlerFunc) Resolve(ctx context.Context, req *Request) (*Proxy, error) {
	return f(ctx, req)
}

// Request carries all information about an inbound proxy request.
// The gateway populates only the Raw* fields from the transport protocol.
// Middleware enriches the structured fields as the request flows through
// the pipeline.
type Request struct {
	// --- Raw fields, set by the transport (gateway) ---

	// RawUsername is the raw username from the transport protocol
	// (e.g. Basic auth username, SOCKS5 username). Not interpreted by gateway.
	RawUsername string

	// RawPassword is the raw password from the transport protocol.
	RawPassword string

	// Target is the destination the client wants to reach (e.g. "example.com:443").
	// Set by the gateway from the CONNECT target or request URI.
	Target string

	// --- Structured fields, set by middleware ---

	// Sub is the subscriber/user identity, parsed from RawUsername by middleware.
	Sub string

	// Password is the credential, may be copied from RawPassword or parsed.
	Password string

	// Set is the proxy set name to route through.
	Set string

	// Meta is flat key-value metadata.
	Meta Meta

	// SessionKey is the stable key for sticky-session affinity.
	// If empty, no affinity is applied.
	SessionKey string

	// SessionTTL is how long a sticky session should last (minutes).
	// Zero means no affinity (new proxy every request).
	SessionTTL int
}

// Meta is a flat map of string/number metadata values.
type Meta map[string]interface{}

// GetString returns the string value for key, or "" if absent/not-a-string.
func (m Meta) GetString(key string) string {
	v, _ := m[key].(string)
	return v
}

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

// GetProtocol returns the protocol, defaulting to HTTP if empty.
func (p *Proxy) GetProtocol() Protocol {
	if p.Protocol == "" {
		return ProtocolHTTP
	}
	return p.Protocol
}

// ConnHandle tracks a single active proxied connection.
type ConnHandle interface {
	RecordTraffic(upstream bool, delta int64, cancel func())
	Close(sentTotal, receivedTotal int64)
}

// ConnectionTracker is an optional interface that Handlers can implement
// to observe and control individual proxied connections.
type ConnectionTracker interface {
	OpenConnection(sub string) (ConnHandle, error)
}
