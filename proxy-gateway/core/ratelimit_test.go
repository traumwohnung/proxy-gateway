package core

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// RateLimiting
// ---------------------------------------------------------------------------

func TestRateLimitConcurrentConnections(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 2},
	}))
	h1, err := rl.OpenConnection("alice")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := rl.OpenConnection("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rl.OpenConnection("alice"); err == nil {
		t.Fatal("expected connection limit error")
	}
	h1.Close(0, 0)
	if _, err := rl.OpenConnection("alice"); err != nil {
		t.Fatalf("should succeed after close: %v", err)
	}
	h2.Close(0, 0)
}

func TestRateLimitBandwidthMidConnection(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitUploadBytes, Timeframe: Hourly, Window: 1, Max: 100},
	}))
	h, err := rl.OpenConnection("alice")
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	h.RecordTraffic(true, 80, func() { cancelled = true })
	if cancelled {
		t.Fatal("should not cancel yet")
	}
	h.RecordTraffic(true, 30, func() { cancelled = true })
	if !cancelled {
		t.Fatal("expected cancel when upload limit exceeded")
	}
	h.Close(110, 0)
}

func TestRateLimitWrapsResultConnTracker(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 10},
	}))

	ctx := WithSub(context.Background(), "alice")
	result, err := rl.Resolve(ctx, &Request{})
	if err != nil {
		t.Fatal(err)
	}
	if result.ConnTracker == nil {
		t.Fatal("expected ConnTracker in result")
	}
	// Close it to decrement concurrent counter.
	result.ConnTracker.Close(0, 0)
}
