package core

import (
	"context"
	"testing"
)

func TestMetaGetString(t *testing.T) {
	m := Meta{"k": "v", "n": float64(42)}
	if m.GetString("k") != "v" {
		t.Fatal("expected v")
	}
	if m.GetString("n") != "" {
		t.Fatal("expected empty for non-string")
	}
	if m.GetString("missing") != "" {
		t.Fatal("expected empty for missing")
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	ctx = WithSub(ctx, "alice")
	ctx = WithPassword(ctx, "secret")
	ctx = WithSet(ctx, "residential")
	ctx = WithSessionKey(ctx, "key123")
	ctx = WithSessionTTL(ctx, 5)
	ctx = WithMeta(ctx, Meta{"app": "test"})
	ctx = WithTLSState(ctx, TLSState{Broken: true, ServerName: "example.com"})

	if Sub(ctx) != "alice" {
		t.Fatal("Sub")
	}
	if Password(ctx) != "secret" {
		t.Fatal("Password")
	}
	if Set(ctx) != "residential" {
		t.Fatal("Set")
	}
	if SessionKey(ctx) != "key123" {
		t.Fatal("SessionKey")
	}
	if SessionTTL(ctx) != 5 {
		t.Fatal("SessionTTL")
	}
	if GetMeta(ctx).GetString("app") != "test" {
		t.Fatal("Meta")
	}
	ts := GetTLSState(ctx)
	if !ts.Broken || ts.ServerName != "example.com" {
		t.Fatal("TLSState")
	}
}
