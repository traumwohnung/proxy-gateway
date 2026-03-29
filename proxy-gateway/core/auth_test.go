package core

import (
	"context"
	"fmt"
	"testing"
)

type stubAuth struct{ identity, credential string }

func (a *stubAuth) Authenticate(identity, credential string) error {
	if identity != a.identity || credential != a.credential {
		return fmt.Errorf("invalid")
	}
	return nil
}

func TestAuthPassesOnValidCredentials(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	h := Auth(&stubAuth{"alice", "pw"}, source)
	ctx := WithIdentity(context.Background(), "alice")
	ctx = WithCredential(ctx, "pw")
	r, err := h.Resolve(ctx, &Request{})
	if err != nil || r == nil || r.Proxy == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}
}

func TestAuthRejectsInvalidCredentials(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	h := Auth(&stubAuth{"alice", "pw"}, source)
	ctx := WithIdentity(context.Background(), "alice")
	ctx = WithCredential(ctx, "wrong")
	_, err := h.Resolve(ctx, &Request{})
	if err == nil {
		t.Fatal("expected error for wrong credential")
	}
}
