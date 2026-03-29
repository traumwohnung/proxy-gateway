package core

import (
	"context"
	"testing"
	"time"
)

// testKeyFn returns a SessionParams using identity as key with a fixed TTL.
func testKeyFn(ttl time.Duration) KeyFunc {
	return func(ctx context.Context) SessionParams {
		return SessionParams{Key: Identity(ctx), TTL: ttl}
	}
}

func TestStickyAffinityPins(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		counter++
		return Resolved(&Proxy{Host: "host", Port: uint16(counter)}), nil
	})
	s := Session(testKeyFn(5*time.Minute), source)
	ctx := WithIdentity(context.Background(), "alice")
	r1, _ := s.Resolve(ctx, &Request{})
	r2, _ := s.Resolve(ctx, &Request{})
	if r1.Proxy.Port != r2.Proxy.Port {
		t.Fatalf("sticky should pin: got %d and %d", r1.Proxy.Port, r2.Proxy.Port)
	}
}

func TestStickyZeroTTLPassesThrough(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		counter++
		return Resolved(&Proxy{Host: "host", Port: uint16(counter)}), nil
	})
	// Zero TTL = no affinity.
	s := Session(func(_ context.Context) SessionParams { return SessionParams{} }, source)
	ctx := WithIdentity(context.Background(), "alice")
	r1, _ := s.Resolve(ctx, &Request{})
	r2, _ := s.Resolve(ctx, &Request{})
	if r1.Proxy.Port == r2.Proxy.Port {
		t.Fatal("0 TTL should not pin")
	}
}

func TestStickyListSessions(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	s := Session(testKeyFn(5*time.Minute), source)
	s.Resolve(WithIdentity(context.Background(), "a"), &Request{})
	s.Resolve(WithIdentity(context.Background(), "b"), &Request{})
	// No key = no affinity.
	s.Resolve(context.Background(), &Request{})
	if len(s.ListSessions()) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(s.ListSessions()))
	}
}

func TestStickyForceRotate(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		counter++
		return Resolved(&Proxy{Host: "host", Port: uint16(counter)}), nil
	})
	s := Session(testKeyFn(60*time.Minute), source)
	ctx := WithIdentity(context.Background(), "alice")
	s.Resolve(ctx, &Request{})
	before := s.GetSession("alice")
	info, _ := s.ForceRotate(context.Background(), "alice")
	if info == nil {
		t.Fatal("expected session info")
	}
	if info.SessionID != before.SessionID {
		t.Fatal("session ID should be preserved after rotate")
	}
}

func TestDirectLibraryUsage(t *testing.T) {
	source := HandlerFunc(func(ctx context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "proxy-" + Identity(ctx), Port: 8080}), nil
	})
	ctx := WithIdentity(context.Background(), "residential")
	r, err := source.Resolve(ctx, &Request{})
	if err != nil || r.Proxy.Host != "proxy-residential" {
		t.Fatalf("unexpected: err=%v proxy=%+v", err, r)
	}
}
