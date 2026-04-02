package utils

import (
	"context"
	"testing"

	proxykit "proxy-kit"
)

func TestNewWebshareSourceBuildsGeneratedPool(t *testing.T) {
	t.Setenv("WEBSHARE_TEST_PASSWORD", "pw")

	src, err := NewWebshareSource(&WebshareConfig{
		Username:    "trlvvxfs",
		Amount:      3,
		PasswordEnv: "WEBSHARE_TEST_PASSWORD",
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	got1, err := src.Resolve(context.Background(), &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve 1: %v", err)
	}
	got2, err := src.Resolve(context.Background(), &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve 2: %v", err)
	}

	if got1.Proxy.Host != "p.webshare.io" || got1.Proxy.Port != 80 {
		t.Fatalf("unexpected proxy endpoint: %+v", got1.Proxy)
	}
	if got1.Proxy.Password != "pw" {
		t.Fatalf("unexpected password: %q", got1.Proxy.Password)
	}
	if got1.Proxy.Proto() != proxykit.ProtocolHTTP {
		t.Fatalf("expected http protocol, got %q", got1.Proxy.Proto())
	}
	if got1.Proxy.Username == got2.Proxy.Username {
		t.Fatalf("expected least-used rotation across generated pool, got duplicate %q", got1.Proxy.Username)
	}
}

func TestWebshareResolveUsesSeedForDeterministicTieBreak(t *testing.T) {
	t.Setenv("WEBSHARE_TEST_PASSWORD", "pw")

	src, err := NewWebshareSource(&WebshareConfig{
		Username:    "trlvvxfs",
		Amount:      20,
		PasswordEnv: "WEBSHARE_TEST_PASSWORD",
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	ctx1 := proxykit.WithSessionSeed(context.Background(), proxykit.NewSessionSeed(42, 0))
	ctx2 := proxykit.WithSessionSeed(context.Background(), proxykit.NewSessionSeed(42, 0))

	got1, err := src.Resolve(ctx1, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve 1: %v", err)
	}

	src2, err := NewWebshareSource(&WebshareConfig{
		Username:    "trlvvxfs",
		Amount:      20,
		PasswordEnv: "WEBSHARE_TEST_PASSWORD",
	})
	if err != nil {
		t.Fatalf("new source 2: %v", err)
	}
	got2, err := src2.Resolve(ctx2, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve 2: %v", err)
	}

	if got1.Proxy.Username != got2.Proxy.Username {
		t.Fatalf("same seed should pick same generated username, got %q vs %q", got1.Proxy.Username, got2.Proxy.Username)
	}
}
