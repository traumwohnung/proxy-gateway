package proxygatewayclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyConfiguration_Deterministic(t *testing.T) {
	c1 := NewProxyConfiguration("residential").
		Minutes(60).
		Affinity("platform", "myapp").
		Affinity("user", "alice")
	c2 := NewProxyConfiguration("residential").
		Minutes(60).
		Affinity("user", "alice").
		Affinity("platform", "myapp")

	u1, err := c1.BuildUsername()
	if err != nil {
		t.Fatalf("c1: %v", err)
	}
	u2, err := c2.BuildUsername()
	if err != nil {
		t.Fatalf("c2: %v", err)
	}

	p1, err := ParseUsername(u1)
	if err != nil {
		t.Fatalf("parse u1: %v", err)
	}
	p2, err := ParseUsername(u2)
	if err != nil {
		t.Fatalf("parse u2: %v", err)
	}
	if p1.Set != p2.Set || p1.Minutes != p2.Minutes {
		t.Fatalf("set/minutes differ: %+v vs %+v", p1, p2)
	}
}

func TestProxyConfiguration_BuildURLRequiresProxyClient(t *testing.T) {
	c := NewProxyConfiguration("set").Minutes(60)
	if _, err := c.BuildURL(); err == nil {
		t.Fatal("expected error without WithProxyClient")
	}
}

func TestProxyConfiguration_BuildURL(t *testing.T) {
	pc := NewProxyClient().Proxy("127.0.0.1", 8100)
	c := NewProxyConfiguration("residential").
		Minutes(60).
		Affinity("user", "alice").
		WithProxyClient(pc)

	url, err := c.BuildURL()
	if err != nil {
		t.Fatalf("BuildURL: %v", err)
	}
	if !strings.HasPrefix(url, "http://") || !strings.Contains(url, "@127.0.0.1:8100") {
		t.Fatalf("unexpected URL: %q", url)
	}
}

func TestProxyConfiguration_BuildHTTPClient(t *testing.T) {
	pc := NewProxyClient().Proxy("127.0.0.1", 8100)
	c := NewProxyConfiguration("residential").Minutes(60).WithProxyClient(pc)

	hc, err := c.BuildHTTPClient()
	if err != nil {
		t.Fatalf("BuildHTTPClient: %v", err)
	}
	if hc.Transport == nil {
		t.Fatal("expected non-nil Transport")
	}
}

func TestProxyConfiguration_RotateRequiresAdmin(t *testing.T) {
	pc := NewProxyClient().Proxy("127.0.0.1", 8100) // no admin
	c := NewProxyConfiguration("set").Minutes(60).WithProxyClient(pc)
	if _, err := c.Rotate(context.Background()); err == nil {
		t.Fatal("expected error without admin endpoint")
	}
}

func TestProxyConfiguration_Rotate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rotate-now") {
			_ = json.NewEncoder(w).Encode(SessionInfo{SessionID: 42, Upstream: "host:1"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	pc := NewProxyClient().Proxy("127.0.0.1", 8100).Admin(srv.URL, "")
	c := NewProxyConfiguration("set").Minutes(60).WithProxyClient(pc)

	info, err := c.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if info == nil || info.SessionID != 42 {
		t.Fatalf("unexpected info: %+v", info)
	}
}
