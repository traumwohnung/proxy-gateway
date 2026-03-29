package core

// ConnTracker tracks a single active proxied connection's lifecycle.
type ConnTracker interface {
	RecordTraffic(upstream bool, delta int64, cancel func())
	Close(sentTotal, receivedTotal int64)
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

func (c *chainedTracker) Close(sent, received int64) {
	c.a.Close(sent, received)
	c.b.Close(sent, received)
}
