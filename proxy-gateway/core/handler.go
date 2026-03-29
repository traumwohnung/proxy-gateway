package core

import (
	"context"
	"net"
	"net/http"
)

// Handler resolves an inbound proxy request to a Result.
type Handler interface {
	Resolve(ctx context.Context, req *Request) (*Result, error)
}

// HandlerFunc adapts a function to the Handler interface.
type HandlerFunc func(ctx context.Context, req *Request) (*Result, error)

func (f HandlerFunc) Resolve(ctx context.Context, req *Request) (*Result, error) {
	return f(ctx, req)
}

// Request carries the transport-level facts about an inbound proxy request.
type Request struct {
	// RawUsername is the raw username from the transport (Basic auth / SOCKS5).
	RawUsername string

	// RawPassword is the raw password from the transport.
	RawPassword string

	// Target is the destination host:port (from CONNECT or request URI).
	Target string

	// Conn is the raw client connection (CONNECT/SOCKS5 only, nil for plain HTTP).
	Conn net.Conn

	// HTTPRequest is the decoded HTTP request (plain HTTP or MITM-decrypted).
	HTTPRequest *http.Request
}

// Result carries everything the gateway needs after pipeline resolution.
type Result struct {
	// Proxy is the upstream proxy to connect through (nil = handled/rejected).
	Proxy *Proxy

	// ConnTracker tracks connection lifecycle (may be nil).
	ConnTracker ConnTracker

	// ResponseHook modifies the response before sending to client.
	ResponseHook func(resp *http.Response) *http.Response

	// HTTPResponse is a synthetic response from middleware (blocking, caching).
	HTTPResponse *http.Response

	// UpstreamConn is a pre-dialed upstream connection (used by MITM).
	UpstreamConn net.Conn
}

// Resolved is a convenience for returning a Result with just a Proxy.
func Resolved(p *Proxy) *Result {
	return &Result{Proxy: p}
}
