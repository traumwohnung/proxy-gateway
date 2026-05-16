package proxykit

// ConnTracker tracks a single active proxied connection's lifecycle.
//
// reason on Close describes why the connection ended. The canonical set used
// by the analytics ingest is: "ok" (relay completed normally), "upstream_err"
// (dial or transport failure on the upstream side), "client_close" (client
// disconnected before relay started), "timeout", "auth_fail". Implementations
// that don't care about the reason should ignore it.
type ConnTracker interface {
	RecordTraffic(upstream bool, delta int64, cancel func())
	Close(sentTotal, receivedTotal int64, reason string)
}

// ChainTrackers returns a ConnTracker that delegates to both a and b.
// Either may be nil (the non-nil one is returned as-is).
func ChainTrackers(a, b ConnTracker) ConnTracker {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return &chainedTracker{a, b}
}

type chainedTracker struct{ a, b ConnTracker }

func (c *chainedTracker) RecordTraffic(upstream bool, delta int64, cancel func()) {
	c.a.RecordTraffic(upstream, delta, cancel)
	c.b.RecordTraffic(upstream, delta, cancel)
}

func (c *chainedTracker) Close(sent, received int64, reason string) {
	c.a.Close(sent, received, reason)
	c.b.Close(sent, received, reason)
}
