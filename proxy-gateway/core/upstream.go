package core

import (
	"context"
	"net"
)

// DefaultUpstream returns an Upstream that dispatches to HTTPUpstream
// or SOCKS5Upstream based on the proxy's Protocol field.
func DefaultUpstream() Upstream {
	h := HTTPUpstream{}
	s := SOCKS5Upstream{}
	return UpstreamFunc(func(ctx context.Context, proxy *Proxy, target string) (net.Conn, error) {
		switch proxy.GetProtocol() {
		case ProtocolSOCKS5:
			return s.Dial(ctx, proxy, target)
		default:
			return h.Dial(ctx, proxy, target)
		}
	})
}
