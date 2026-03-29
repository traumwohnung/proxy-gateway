package middleware

import (
	"context"
	"testing"

	"proxy-gateway/core"
)

// testSource always returns the same proxy.
var testProxy = &core.Proxy{Host: "upstream", Port: 8080}

var testSource = core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
	return testProxy, nil
})

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func TestAuthPassesOnValidCredentials(t *testing.T) {
	h := Auth(NewSimpleAuth("alice", "pw"), testSource)
	p, err := h.Resolve(context.Background(), &core.Request{Sub: "alice", Password: "pw"})
	if err != nil || p == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}
}

func TestAuthRejectsInvalidCredentials(t *testing.T) {
	h := Auth(NewSimpleAuth("alice", "pw"), testSource)
	_, err := h.Resolve(context.Background(), &core.Request{Sub: "alice", Password: "wrong"})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestMultiAuthWorks(t *testing.T) {
	auth := NewMultiAuth(map[string]string{"alice": "pw1", "bob": "pw2"})
	h := Auth(auth, testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{Sub: "alice", Password: "pw1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Resolve(context.Background(), &core.Request{Sub: "bob", Password: "pw2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Resolve(context.Background(), &core.Request{Sub: "charlie", Password: "pw"}); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

// ---------------------------------------------------------------------------
// Sticky
// ---------------------------------------------------------------------------

func TestStickyAffinityPins(t *testing.T) {
	// Source that returns different proxies each time.
	counter := 0
	source := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		counter++
		return &core.Proxy{Host: "host", Port: uint16(counter)}, nil
	})

	s := Sticky(source)
	req := &core.Request{SessionKey: "key1", SessionTTL: 5}

	p1, _ := s.Resolve(context.Background(), req)
	p2, _ := s.Resolve(context.Background(), req)
	if p1.Port != p2.Port {
		t.Fatalf("sticky should pin: got %d and %d", p1.Port, p2.Port)
	}
}

func TestStickyZeroTTLPassesThrough(t *testing.T) {
	counter := 0
	source := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		counter++
		return &core.Proxy{Host: "host", Port: uint16(counter)}, nil
	})

	s := Sticky(source)
	req := &core.Request{SessionKey: "key1", SessionTTL: 0}

	p1, _ := s.Resolve(context.Background(), req)
	p2, _ := s.Resolve(context.Background(), req)
	if p1.Port == p2.Port {
		t.Fatal("0 TTL should not pin")
	}
}

func TestStickyListSessions(t *testing.T) {
	s := Sticky(testSource)
	s.Resolve(context.Background(), &core.Request{SessionKey: "a", SessionTTL: 5})
	s.Resolve(context.Background(), &core.Request{SessionKey: "b", SessionTTL: 5})
	s.Resolve(context.Background(), &core.Request{SessionKey: "c", SessionTTL: 0}) // no affinity
	sessions := s.ListSessions()
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
}

func TestStickyForceRotate(t *testing.T) {
	counter := 0
	source := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		counter++
		return &core.Proxy{Host: "host", Port: uint16(counter)}, nil
	})
	s := Sticky(source)
	s.Resolve(context.Background(), &core.Request{SessionKey: "k", SessionTTL: 60})
	before := s.GetSession("k")

	info, _ := s.ForceRotate(context.Background(), "k")
	if info == nil {
		t.Fatal("expected session info")
	}
	if info.SessionID != before.SessionID {
		t.Fatal("session ID should be preserved")
	}
}

// ---------------------------------------------------------------------------
// RateLimiting
// ---------------------------------------------------------------------------

func TestRateLimitConcurrentConnections(t *testing.T) {
	rl := RateLimiting(testSource, StaticLimits([]RateLimit{
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
	rl := RateLimiting(testSource, StaticLimits([]RateLimit{
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

// ---------------------------------------------------------------------------
// ParseJSONCreds
// ---------------------------------------------------------------------------

func TestParseJSONCredsPopulatesFields(t *testing.T) {
	h := ParseJSONCreds(core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Proxy, error) {
		if req.Sub != "alice" || req.Set != "res" || req.SessionTTL != 5 {
			t.Fatalf("unexpected parsed fields: sub=%q set=%q ttl=%d", req.Sub, req.Set, req.SessionTTL)
		}
		if req.Password != "s3cret" {
			t.Fatalf("expected password=s3cret, got %q", req.Password)
		}
		if req.Meta.GetString("app") != "test" {
			t.Fatalf("expected meta.app=test")
		}
		return &core.Proxy{Host: "ok"}, nil
	}))

	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":5,"meta":{"app":"test"}}`,
		RawPassword: "s3cret",
	}
	p, err := h.Resolve(context.Background(), req)
	if err != nil || p.Host != "ok" {
		t.Fatalf("unexpected: err=%v proxy=%+v", err, p)
	}
}

func TestParseJSONCredsRejectsEmptyUsername(t *testing.T) {
	h := ParseJSONCreds(testSource)
	_, err := h.Resolve(context.Background(), &core.Request{})
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestParseJSONCredsRejectsInvalidJSON(t *testing.T) {
	h := ParseJSONCreds(testSource)
	_, err := h.Resolve(context.Background(), &core.Request{RawUsername: "notjson"})
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseJSONCredsRejectsMissingSub(t *testing.T) {
	h := ParseJSONCreds(testSource)
	_, err := h.Resolve(context.Background(), &core.Request{RawUsername: `{"set":"res","minutes":0,"meta":{}}`})
	if err == nil {
		t.Fatal("expected error for missing sub")
	}
}

// ---------------------------------------------------------------------------
// Pipeline composition with ParseJSONCreds
// ---------------------------------------------------------------------------

func TestFullPipeline(t *testing.T) {
	source := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})

	// ParseJSONCreds → Auth → Sticky → Source
	pipeline := ParseJSONCreds(
		Auth(
			NewSimpleAuth("alice", "pw"),
			Sticky(source),
		),
	)

	// Valid request as the gateway would send it.
	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	}
	p, err := pipeline.Resolve(context.Background(), req)
	if err != nil || p == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}

	// Same raw username → same sticky session.
	p2, _ := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	})
	if p2.Port != p.Port {
		t.Fatal("sticky should return same proxy")
	}

	// Bad password.
	_, err = pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "wrong",
	})
	if err == nil {
		t.Fatal("expected auth error")
	}
}

// ---------------------------------------------------------------------------
// Library usage (no HTTP, no Basic auth)
// ---------------------------------------------------------------------------

func TestDirectLibraryUsage(t *testing.T) {
	source := core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Proxy, error) {
		return &core.Proxy{Host: "proxy-" + req.Set, Port: 8080}, nil
	})

	p, err := source.Resolve(context.Background(), &core.Request{Set: "residential"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "proxy-residential" {
		t.Fatalf("expected proxy-residential, got %s", p.Host)
	}
}
