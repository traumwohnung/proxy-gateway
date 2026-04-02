package utils

import (
	"context"
	"strings"
	"testing"
	"time"

	proxykit "proxy-kit"
)

func boolPtr(v bool) *bool { return &v }

func TestProxyingIOResolveUsesSeedTTLAsLifetime(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:    "account",
		PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
		Countries:   []Country{Country("DE"), Country("FR")},
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
	if got := result.Proxy.Username; got != "account" {
		t.Fatalf("expected upstream username to stay static, got %q", got)
	}
	if got := result.Proxy.Password; !strings.Contains(got, "_lifetime-720") {
		t.Fatalf("expected lifetime in password, got %q", got)
	}
	if got := result.Proxy.Password; !strings.Contains(got, "_country-DE,FR") {
		t.Fatalf("expected country in password, got %q", got)
	}
	if result.Proxy.Proto() != proxykit.ProtocolHTTP {
		t.Fatalf("expected default protocol http, got %q", result.Proxy.Proto())
	}
}

func TestProxyingIOResolveAppendsHighQualityWhenEnabled(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:    "account",
		PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
		HighQuality: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	result, err := src.Resolve(context.Background(), &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Password; !strings.Contains(got, "_quality-high") {
		t.Fatalf("expected quality-high in password, got %q", got)
	}
	if got := result.Proxy.Password; strings.Contains(got, "_country-") {
		t.Fatalf("did not expect country in password, got %q", got)
	}
	if got := result.Proxy.Password; strings.Contains(got, "_session-") || strings.Contains(got, "_lifetime-") {
		t.Fatalf("did not expect sticky session fields in password, got %q", got)
	}
}

func TestProxyingIOResolveOmitsHighQualityWhenUnset(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:    "account",
		PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	result, err := src.Resolve(context.Background(), &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Password; strings.Contains(got, "_quality-high") {
		t.Fatalf("did not expect quality-high in password, got %q", got)
	}
}

func TestProxyingIOResolvePrefersExplicitLifetimeMeta(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:    "account",
		PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	ctx := context.Background()
	ctx = WithMeta(ctx, Meta{"lifetime": "10"})
	ctx = WithSeedTTL(ctx, 12*time.Hour)
	ctx = proxykit.WithSessionSeed(ctx, proxykit.NewSessionSeed(1, 0))

	result, err := src.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Password; !strings.Contains(got, "_lifetime-10") {
		t.Fatalf("expected explicit lifetime in password, got %q", got)
	}
}

func TestProxyingIOResolveOmitsStickyFieldsWithoutSessionAffinity(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:        "account",
		PasswordEnv:     "PROXYINGIO_TEST_PASSWORD",
		DefaultLifetime: 60,
		Countries:       []Country{Country("AQ"), Country("AD")},
		HighQuality:     boolPtr(true),
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	result, err := src.Resolve(context.Background(), &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Password; got != "basepw_country-AQ,AD_quality-high" {
		t.Fatalf("expected non-sticky password without session/lifetime, got %q", got)
	}
}

func TestProxyingIOResolveUsesDefaultLifetimeWithSeedWithoutExplicitTTL(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:        "account",
		PasswordEnv:     "PROXYINGIO_TEST_PASSWORD",
		DefaultLifetime: 60,
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	ctx := proxykit.WithSessionSeed(context.Background(), proxykit.NewSessionSeed(1, 0))
	result, err := src.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := result.Proxy.Password; !strings.Contains(got, "_lifetime-60") {
		t.Fatalf("expected default lifetime in password, got %q", got)
	}
}

func TestProxyingIOResolveSupportsSocks5Protocol(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	src, err := NewProxyingIOSource(&ProxyingIOConfig{
		Username:    "account",
		PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
		Protocol:    ProxyingIOProtocolSocks5,
		Countries:   []Country{Country("AQ"), Country("AD")},
		HighQuality: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}

	result, err := src.Resolve(context.Background(), &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.Proxy.Proto() != proxykit.ProtocolSOCKS5 {
		t.Fatalf("expected socks5 protocol, got %q", result.Proxy.Proto())
	}
	if result.Proxy.Port != 1080 {
		t.Fatalf("expected default socks5 port 1080, got %d", result.Proxy.Port)
	}
	if got := result.Proxy.Password; got != "basepw_country-AQ,AD_quality-high" {
		t.Fatalf("expected socks5 password to match non-sticky format, got %q", got)
	}
}
