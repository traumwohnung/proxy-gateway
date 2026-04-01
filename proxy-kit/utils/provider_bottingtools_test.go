package utils

import (
	"context"
	"strings"
	"testing"
	"time"

	proxykit "proxy-kit"
)

func TestBottingtoolsResolveUsesSeedTTLAsSesstime(t *testing.T) {
	t.Setenv("BT_TEST_PASSWORD", "pw")

	src, err := NewBottingtoolsSource(&BottingtoolsConfig{
		Username:    "account",
		PasswordEnv: "BT_TEST_PASSWORD",
		Host:        "proxy.bottingtools.com",
		Product: BottingtoolsRawProductConfig{
			Type:      "residential",
			Quality:   "high",
			Countries: []Country{Country("DE")},
		},
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	ctx := context.Background()
	ctx = WithSeedTTL(ctx, 12*time.Hour)
	ctx = proxykit.WithSessionSeed(ctx, proxykit.NewSessionSeed(1, 0))

	result, err := src.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Username; !strings.Contains(got, "_sesstime-720") {
		t.Fatalf("expected sesstime in username, got %q", got)
	}
}

func TestBottingtoolsResolvePrefersExplicitSesstimeMeta(t *testing.T) {
	t.Setenv("BT_TEST_PASSWORD", "pw")

	src, err := NewBottingtoolsSource(&BottingtoolsConfig{
		Username:    "account",
		PasswordEnv: "BT_TEST_PASSWORD",
		Host:        "proxy.bottingtools.com",
		Product: BottingtoolsRawProductConfig{
			Type:      "isp",
			Countries: []Country{Country("DE")},
		},
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	ctx := context.Background()
	ctx = WithMeta(ctx, Meta{"sesstime": "10"})
	ctx = WithSeedTTL(ctx, 12*time.Hour)
	ctx = proxykit.WithSessionSeed(ctx, proxykit.NewSessionSeed(1, 0))

	result, err := src.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Username; !strings.Contains(got, "_sesstime-10") {
		t.Fatalf("expected explicit sesstime in username, got %q", got)
	}
}
