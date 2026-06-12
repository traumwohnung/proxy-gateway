package main

import (
	"context"
	"testing"

	proxykit "proxy-kit"
)

func TestDestinationAllowlist_Allows(t *testing.T) {
	al := NewDestinationAllowlist([]string{
		".immobilienscout24.de",
		".immowelt.de",
		"api.immowelt.com",
		"*.example.org",
	})
	if al == nil {
		t.Fatal("expected non-nil allowlist")
	}

	cases := []struct {
		target string
		want   bool
	}{
		{"www.immobilienscout24.de:443", true},
		{"sso.immobilienscout24.de:443", true},
		{"api.mobile.immobilienscout24.de", true},
		{"immobilienscout24.de", true}, // bare domain matches suffix entry
		{"www.immowelt.de:443", true},
		{"api.immowelt.com:443", true},      // exact host
		{"WWW.IMMOWELT.DE", true},           // case-insensitive
		{"www.immobilienscout24.de.", true}, // trailing dot stripped
		{"foo.example.org:80", true},        // *. form
		{"example.org", true},               // *. matches bare too
		{"www.immowelt.com", false},         // only api.immowelt.com is exact
		{"evil.com:443", false},
		{"169.254.169.254:80", false}, // metadata endpoint blocked
		{"localhost:9000", false},
		{"notimmobilienscout24.de", false}, // suffix must be on a dot boundary
		{"", false},
	}
	for _, c := range cases {
		if got := al.Allows(c.target); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestNewDestinationAllowlist_EmptyDisables(t *testing.T) {
	if al := NewDestinationAllowlist(nil); al != nil {
		t.Fatal("nil entries should yield nil (disabled) allowlist")
	}
	if al := NewDestinationAllowlist([]string{"", "  "}); al != nil {
		t.Fatal("blank entries should yield nil (disabled) allowlist")
	}
}

func TestAllowDestinations_NilIsPassthrough(t *testing.T) {
	called := false
	next := proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		called = true
		return &proxykit.Result{}, nil
	})
	h := AllowDestinations(nil, next)
	if _, err := h.Resolve(context.Background(), &proxykit.Request{Target: "anything:443"}); err != nil {
		t.Fatalf("passthrough resolve: %v", err)
	}
	if !called {
		t.Fatal("expected next handler to be called when allowlist is nil")
	}
}

func TestAllowDestinations_RejectsNonAllowlisted(t *testing.T) {
	al := NewDestinationAllowlist([]string{".immowelt.de"})
	next := proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		return &proxykit.Result{}, nil
	})
	h := AllowDestinations(al, next)

	if _, err := h.Resolve(context.Background(), &proxykit.Request{Target: "evil.com:443"}); err == nil {
		t.Fatal("expected rejection of non-allowlisted destination")
	}
	if _, err := h.Resolve(context.Background(), &proxykit.Request{Target: "www.immowelt.de:443"}); err != nil {
		t.Fatalf("expected allow of allowlisted destination, got %v", err)
	}
}
