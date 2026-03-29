package main

import (
	"context"
	"testing"

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
		if core.Sub(ctx) != "alice" || core.Set(ctx) != "res" || core.SessionTTL(ctx) != 5 {
			t.Fatalf("unexpected: sub=%q set=%q ttl=%d", core.Sub(ctx), core.Set(ctx), core.SessionTTL(ctx))
		}
		if core.Password(ctx) != "s3cret" {
			t.Fatalf("expected password=s3cret, got %q", core.Password(ctx))
		}
		if core.GetMeta(ctx).GetString("app") != "test" {
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

func TestParseJSONCredsSessionKeyIsSubPlusSet(t *testing.T) {
	var gotKey string
	h := ParseJSONCreds(core.HandlerFunc(func(ctx context.Context, _ *core.Request) (*core.Result, error) {
		gotKey = core.SessionKey(ctx)
		return core.Resolved(testProxy), nil
	}))
	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	}
	h.Resolve(context.Background(), req)
	// Key must be stable: changing minutes should not change the key.
	req2 := &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":99,"meta":{}}`,
		RawPassword: "pw",
	}
	var gotKey2 string
	h2 := ParseJSONCreds(core.HandlerFunc(func(ctx context.Context, _ *core.Request) (*core.Result, error) {
		gotKey2 = core.SessionKey(ctx)
		return core.Resolved(testProxy), nil
	}))
	h2.Resolve(context.Background(), req2)
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
	cfg := &Config{}
	if _, err := cfg.authUsers(); err == nil {
		t.Fatal("expected error when no auth configured")
	}
}

// ---------------------------------------------------------------------------
// Full pipeline
// ---------------------------------------------------------------------------

func TestFullPipeline(t *testing.T) {
	pipeline := ParseJSONCreds(
		core.Auth(
			utils.NewMapAuth(map[string]string{"alice": "pw"}),
			core.Session(testSource),
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

	// Same sub+set → same sticky session.
	r2, _ := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":99,"meta":{}}`,
		RawPassword: "pw",
	})
	if r2.Proxy.Port != r.Proxy.Port {
		t.Fatal("sticky should return same proxy regardless of minutes")
	}

	// Wrong password.
	if _, err := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "wrong",
	}); err == nil {
		t.Fatal("expected auth error")
	}
}
