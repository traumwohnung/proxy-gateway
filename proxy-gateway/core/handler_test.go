package core

import (
	"context"
	"testing"
)

func TestHandlerFunc(t *testing.T) {
	h := HandlerFunc(func(ctx context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "test", Port: 8080, Username: Sub(ctx)}), nil
	})
	ctx := WithSub(context.Background(), "alice")
	r, err := h.Resolve(ctx, &Request{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Proxy.Username != "alice" {
		t.Fatalf("expected alice, got %s", r.Proxy.Username)
	}
}

func TestResolved(t *testing.T) {
	p := &Proxy{Host: "test", Port: 8080}
	r := Resolved(p)
	if r.Proxy != p {
		t.Fatal("Resolved should wrap the proxy")
	}
	if r.ConnTracker != nil || r.ResponseHook != nil || r.HTTPResponse != nil {
		t.Fatal("other fields should be nil")
	}
}
