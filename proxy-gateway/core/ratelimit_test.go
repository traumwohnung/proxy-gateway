package core

import (
	"context"
	"testing"
)

func resolveWithIdentity(t *testing.T, h Handler, identity string) *Result {
	t.Helper()
	ctx := WithIdentity(context.Background(), identity)
	result, err := h.Resolve(ctx, &Request{})
	if err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}
	return result
}

func TestRateLimitConcurrentConnections(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(Identity, source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 2},
	}))

	r1 := resolveWithIdentity(t, rl, "alice")
	r2 := resolveWithIdentity(t, rl, "alice")

	ctx := WithIdentity(context.Background(), "alice")
	if _, err := rl.Resolve(ctx, &Request{}); err == nil {
		t.Fatal("expected connection limit error on third resolve")
	}

	r1.ConnTracker.Close(0, 0)
	resolveWithIdentity(t, rl, "alice").ConnTracker.Close(0, 0)
	r2.ConnTracker.Close(0, 0)
}

func TestRateLimitBandwidthMidConnection(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(Identity, source, StaticLimits([]RateLimitRule{
		{Type: LimitUploadBytes, Timeframe: Hourly, Window: 1, Max: 100},
	}))

	r := resolveWithIdentity(t, rl, "alice")
	cancelled := false
	r.ConnTracker.RecordTraffic(true, 80, func() { cancelled = true })
	if cancelled {
		t.Fatal("should not cancel yet at 80 bytes")
	}
	r.ConnTracker.RecordTraffic(true, 30, func() { cancelled = true })
	if !cancelled {
		t.Fatal("expected cancel when upload limit exceeded (80+30 > 100)")
	}
	r.ConnTracker.Close(110, 0)
}

func TestRateLimitWrapsResultConnTracker(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(Identity, source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 10},
	}))

	result := resolveWithIdentity(t, rl, "alice")
	if result.ConnTracker == nil {
		t.Fatal("expected ConnTracker in result")
	}
	result.ConnTracker.Close(0, 0)
}

func TestRateLimitEmptyIdentityFallback(t *testing.T) {
	// When no identity is in context, all traffic shares the "" bucket.
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(Identity, source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 1},
	}))

	r, err := rl.Resolve(context.Background(), &Request{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rl.Resolve(context.Background(), &Request{}); err == nil {
		t.Fatal("expected limit exceeded for shared anonymous bucket")
	}
	r.ConnTracker.Close(0, 0)
}

func TestRateLimitCustomKeyFn(t *testing.T) {
	// Custom key function — rate limit by a different context value.
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})

	type customKey struct{}
	keyFn := func(ctx context.Context) string {
		v, _ := ctx.Value(customKey{}).(string)
		return v
	}

	rl := RateLimit(keyFn, source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 1},
	}))

	ctx := context.WithValue(context.Background(), customKey{}, "tenant-A")
	r, err := rl.Resolve(ctx, &Request{})
	if err != nil {
		t.Fatal(err)
	}

	// Same tenant: blocked.
	if _, err := rl.Resolve(ctx, &Request{}); err == nil {
		t.Fatal("expected limit for tenant-A")
	}

	// Different tenant: not blocked.
	ctx2 := context.WithValue(context.Background(), customKey{}, "tenant-B")
	r2, err := rl.Resolve(ctx2, &Request{})
	if err != nil {
		t.Fatalf("tenant-B should not be rate limited: %v", err)
	}

	r.ConnTracker.Close(0, 0)
	r2.ConnTracker.Close(0, 0)
}
