package core

import (
	"context"
	"net"
)

// Downstream is a listener that accepts client connections and dispatches
// them through a Handler pipeline.
type Downstream interface {
	Serve(addr string, handler Handler) error
}

// Upstream dials a target through an upstream proxy.
type Upstream interface {
	Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)
}

// UpstreamFunc adapts a function to the Upstream interface.
type UpstreamFunc func(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)

func (f UpstreamFunc) Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error) {
	return f(ctx, proxy, target)
}
