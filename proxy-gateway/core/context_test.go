package core

import (
	"context"
	"testing"
)

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	ctx = WithIdentity(ctx, "alice")
	ctx = WithCredential(ctx, "secret")
	ctx = WithTLSState(ctx, TLSState{Broken: true, ServerName: "example.com"})

	if Identity(ctx) != "alice" {
		t.Fatal("Identity")
	}
	if Credential(ctx) != "secret" {
		t.Fatal("Credential")
	}
	ts := GetTLSState(ctx)
	if !ts.Broken || ts.ServerName != "example.com" {
		t.Fatal("TLSState")
	}
}
