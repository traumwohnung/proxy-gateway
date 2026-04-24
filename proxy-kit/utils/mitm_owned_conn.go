package utils

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/sardanioss/httpcloak"
	httpcloaktransport "github.com/sardanioss/httpcloak/transport"
	utls "github.com/sardanioss/utls"

	proxykit "proxy-kit"
)

// ownedConn is one upstream TLS connection bound to a (tunnel, target
// host:port, preset, upstream proxy) tuple. Created lazily on the first
// MITM request for a host within a tunnel, torn down when the tunnel ends.
//
// Per-tunnel ownership makes sticky-IP affinity at the upstream proxy
// structurally safe: a tunnel performs exactly one CONNECT to the upstream
// and holds it for every subsequent request to that host. There is no pool
// slot that can die and cause a silent fresh-CONNECT with a different
// sticky-session lookup — a behavior that previously corrupted IP-bound
// flow state.
type ownedConn struct {
	tlsConn   *utls.UConn
	proto     string // "h2" or "http/1.1"
	h2        *httpcloaktransport.H2ClientConn
	transport *httpcloaktransport.Transport // shared: owns preset/header application
	// h1Mu serializes inflight H1 requests on this conn. HTTP/1.1 is not
	// multiplexed; concurrent RoundTripOnConn calls would interleave
	// response framing. H2 has native multiplexing and does not need this.
	h1Mu sync.Mutex
}

func (oc *ownedConn) close() {
	if oc.h2 != nil {
		_ = oc.h2.Close()
		oc.h2 = nil
	}
	if oc.tlsConn != nil {
		_ = oc.tlsConn.Close()
		oc.tlsConn = nil
	}
	if oc.transport != nil {
		oc.transport.Close()
		oc.transport = nil
	}
}

// tunnelOwnedConnKey scopes owned connections to a (target, preset,
// upstream proxy, TLS cert verification) tuple within a tunnel. All four
// components contribute to routing identity: two requests that differ in
// any of them cannot share a single upstream TLS connection.
type tunnelOwnedConnKey struct {
	hostPort string
	preset   string
	proxyURL string
	insecure bool
}

// ownedConnOrErr lets us store either a working conn or the error that
// happened when trying to build it in the TunnelScope slot, so we don't
// re-dial on every request for a tunnel where the upstream refused us.
// Subsequent requests in the same tunnel for the same target key will see
// the same error without triggering another CONNECT.
type ownedConnOrErr struct {
	oc  *ownedConn
	err error
}

// acquireOwnedConn returns an ownedConn for (scope, target, proxy) from the
// TunnelScope cache. On cache miss it dials + handshakes + ALPN-inspects
// and stores the result. On cache hit the existing conn is reused.
//
// scope must be the proxykit.TunnelScope retrieved via
// proxykit.GetTunnelScope(ctx). Callers must ensure it is non-nil.
func (f *tlsFingerprintInterceptor) acquireOwnedConn(
	ctx context.Context,
	scope *proxykit.TunnelScope,
	hostPort string,
	proxy *proxykit.Proxy,
	proxyURL string,
) (*ownedConn, error) {
	key := tunnelOwnedConnKey{
		hostPort: hostPort,
		preset:   f.spec.Preset,
		proxyURL: proxyURL,
		insecure: f.insecure,
	}

	v := scope.GetOrSet(key, func() (any, func()) {
		oc, err := f.buildOwnedConn(ctx, hostPort, proxy, proxyURL)
		if err != nil {
			// Cache the error so subsequent requests for this key in the
			// same tunnel don't repeatedly re-dial a known-bad upstream.
			// No cleanup callback — nothing was allocated.
			return &ownedConnOrErr{err: err}, nil
		}
		return &ownedConnOrErr{oc: oc}, func() { oc.close() }
	})
	res := v.(*ownedConnOrErr)
	if res.err != nil {
		return nil, res.err
	}
	return res.oc, nil
}

// buildOwnedConn dials, handshakes, inspects ALPN, and returns an
// ownedConn ready to receive requests.
func (f *tlsFingerprintInterceptor) buildOwnedConn(
	ctx context.Context,
	hostPort string,
	proxy *proxykit.Proxy,
	proxyURL string,
) (*ownedConn, error) {
	tlsConn, err := f.dialUpstreamTLS(ctx, hostPort, proxy)
	if err != nil {
		return nil, err
	}

	proto := tlsConn.ConnectionState().NegotiatedProtocol
	if proto == "" {
		// Some servers don't negotiate ALPN at all — fall back to H1.
		proto = "http/1.1"
	}

	// Build a transport for preset/header application. We will NEVER call
	// tr.Do on this transport — only DoOnH2Conn / DoOnTLSConn, which
	// bypass the transport's own pool and ignore its proxy config. Pass
	// proxyURL so tr carries the same proxy auth config, though it's
	// unused in the roundtrip path we actually take.
	tOpts := f.spec.transportOptions(proxyURL, f.insecure)
	tr, err := httpcloak.NewTransport(f.spec.Preset, tOpts...)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("building transport for owned conn: %w", err)
	}

	oc := &ownedConn{
		tlsConn:   tlsConn,
		proto:     proto,
		transport: tr,
	}
	if proto == "h2" {
		h2c, err := tr.NewH2ClientConn(ctx, tlsConn)
		if err != nil {
			tlsConn.Close()
			tr.Close()
			return nil, fmt.Errorf("building H2 client conn for owned conn: %w", err)
		}
		oc.h2 = h2c
	}

	slog.Debug("owned conn established",
		"host_port", hostPort,
		"proto", proto,
		"preset", f.spec.Preset,
		"upstream_proxy", redactProxyURL(proxyURL))
	return oc, nil
}

// doOwnedConnRoundTrip dispatches a request onto the ownedConn's H1 or H2
// framer. H1 requests are serialized on h1Mu; H2 requests multiplex
// natively.
func (f *tlsFingerprintInterceptor) doOwnedConnRoundTrip(
	ctx context.Context,
	oc *ownedConn,
	treq *httpcloaktransport.Request,
) (*httpcloaktransport.Response, error) {
	switch oc.proto {
	case "h2":
		return oc.transport.DoOnH2Conn(ctx, treq, oc.h2)
	case "http/1.1":
		oc.h1Mu.Lock()
		defer oc.h1Mu.Unlock()
		return oc.transport.DoOnTLSConn(ctx, treq, oc.tlsConn)
	default:
		return nil, fmt.Errorf("owned conn: unsupported protocol %q", oc.proto)
	}
}
