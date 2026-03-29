package main

import (
	"context"
	"testing"
	"time"

	"proxy-gateway/core"
	"proxy-gateway/utils"
)

var testProxy = &core.Proxy{Host: "upstream", Port: 8080}
var testSource = core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Result, error) {
	return core.Resolved(testProxy), nil
})

// ---------------------------------------------------------------------------
// ParseJSONCreds
// ---------------------------------------------------------------------------

func TestParseJSONCredsPopulatesContext(t *testing.T) {
	h := ParseJSONCreds(core.HandlerFunc(func(ctx context.Context, _ *core.Request) (*core.Result, error) {
		if core.Identity(ctx) != "alice" {
			t.Fatalf("expected identity=alice, got %q", core.Identity(ctx))
		}
		if getSet(ctx) != "res" {
			t.Fatalf("expected set=res, got %q", getSet(ctx))
		}
		if getSessionTTL(ctx) != 5*time.Minute {
			t.Fatalf("expected ttl=5m, got %v", getSessionTTL(ctx))
		}
		if core.Credential(ctx) != "s3cret" {
			t.Fatalf("expected credential=s3cret, got %q", core.Credential(ctx))
		}
		if utils.GetMeta(ctx).GetString("app") != "test" {
			t.Fatal("expected meta.app=test")
		}
		return core.Resolved(testProxy), nil
	}))
	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":5,"meta":{"app":"test"}}`,
		RawPassword: "s3cret",
	}
	r, err := h.Resolve(context.Background(), req)
	if err != nil || r.Proxy.Host != "upstream" {
		t.Fatalf("unexpected: err=%v result=%+v", err, r)
	}
}

func TestParseJSONCredsSessionKeyIsIdentityPlusSet(t *testing.T) {
	var gotKey string
	h := ParseJSONCreds(core.HandlerFunc(func(ctx context.Context, _ *core.Request) (*core.Result, error) {
		gotKey = getSessionKey(ctx)
		return core.Resolved(testProxy), nil
	}))
	h.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	})

	var gotKey2 string
	h2 := ParseJSONCreds(core.HandlerFunc(func(ctx context.Context, _ *core.Request) (*core.Result, error) {
		gotKey2 = getSessionKey(ctx)
		return core.Resolved(testProxy), nil
	}))
	// Different minutes — key must be the same.
	h2.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":99,"meta":{}}`,
		RawPassword: "pw",
	})
	if gotKey != gotKey2 {
		t.Fatalf("session key changed when only minutes changed: %q vs %q", gotKey, gotKey2)
	}
}

func TestParseJSONCredsRejectsEmptyUsername(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSONCredsRejectsInvalidJSON(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{RawUsername: "notjson"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSONCredsRejectsMissingSub(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{
		RawUsername: `{"set":"res","minutes":0,"meta":{}}`,
	}); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Config auth resolution
// ---------------------------------------------------------------------------

func TestConfigAuthUsersMapTakesPrecedence(t *testing.T) {
	cfg := &Config{
		AuthSub:      "ignored",
		AuthPassword: "ignored",
		Users:        map[string]string{"alice": "pw1", "bob": "pw2"},
	}
	users, err := cfg.authUsers()
	if err != nil {
		t.Fatal(err)
	}
	if users["alice"] != "pw1" || users["bob"] != "pw2" {
		t.Fatal("expected users map")
	}
	if _, ok := users["ignored"]; ok {
		t.Fatal("auth_sub should be ignored when users is set")
	}
}

func TestConfigAuthFallsBackToSubPassword(t *testing.T) {
	cfg := &Config{AuthSub: "alice", AuthPassword: "pw"}
	users, err := cfg.authUsers()
	if err != nil {
		t.Fatal(err)
	}
	if users["alice"] != "pw" {
		t.Fatal("expected single-user map from auth_sub/auth_password")
	}
}

func TestConfigAuthRequiresCredentials(t *testing.T) {
	if _, err := (&Config{}).authUsers(); err == nil {
		t.Fatal("expected error when no auth configured")
	}
}

// ---------------------------------------------------------------------------
// Full pipeline
// ---------------------------------------------------------------------------

func TestFullPipeline(t *testing.T) {
	sessionKeyFn := func(ctx context.Context) core.SessionParams {
		return core.SessionParams{
			Key: getSessionKey(ctx),
			TTL: getSessionTTL(ctx),
		}
	}

	pipeline := ParseJSONCreds(
		core.Auth(
			utils.NewMapAuth(map[string]string{"alice": "pw"}),
			core.Session(sessionKeyFn, testSource),
		),
	)

	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	}
	r, err := pipeline.Resolve(context.Background(), req)
	if err != nil || r == nil || r.Proxy == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}

	// Same sub+set, different minutes → same sticky session.
	r2, _ := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":99,"meta":{}}`,
		RawPassword: "pw",
	})
	if r2.Proxy.Port != r.Proxy.Port {
		t.Fatal("sticky should return same proxy regardless of minutes")
	}

	// Wrong credential.
	if _, err := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "wrong",
	}); err == nil {
		t.Fatal("expected auth error")
	}
}
