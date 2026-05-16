package proxygatewayclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRetry_StopsOnOk(t *testing.T) {
	b := NewProxyConfiguration("set").Minutes(60)
	calls := 0
	v, err := Retry(context.Background(), b, func(attempt int) (string, bool) {
		calls++
		return "done", true
	})
	if err != nil {
		t.Fatalf("Retry: %v", err)
	}
	if v != "done" || calls != 1 {
		t.Fatalf("unexpected v=%q calls=%d", v, calls)
	}
}

func TestRetry_RotatesBetweenFailingAttempts(t *testing.T) {
	rotates := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rotate-now") {
			rotates++
			info := SessionInfo{SessionID: uint64(rotates), Upstream: "127.0.0.1:9000"}
			_ = json.NewEncoder(w).Encode(info)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	pc := NewProxyClient().Admin(srv.URL, "")
	b := NewProxyConfiguration("set").Minutes(60).WithProxyClient(pc)

	maxAttempts := 3
	v, err := Retry(context.Background(), b, func(attempt int) (int, bool) {
		if attempt+1 >= maxAttempts {
			return attempt, true
		}
		return 0, false
	})
	if err != nil {
		t.Fatalf("Retry: %v", err)
	}
	if v != maxAttempts-1 {
		t.Fatalf("expected final attempt=%d, got %d", maxAttempts-1, v)
	}
	if rotates != maxAttempts-1 {
		t.Fatalf("expected %d rotations, got %d", maxAttempts-1, rotates)
	}
}

func TestRetry_PropagatesRotateError(t *testing.T) {
	b := NewProxyConfiguration("set").Minutes(60) // no client → Rotate errors
	_, err := Retry(context.Background(), b, func(attempt int) (int, bool) {
		return 0, false
	})
	if err == nil {
		t.Fatal("expected error when configuration has no proxy client")
	}
}

func TestRetryN_StopsAtMax(t *testing.T) {
	rotates := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rotate-now") {
			rotates++
			_ = json.NewEncoder(w).Encode(SessionInfo{SessionID: uint64(rotates)})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	pc := NewProxyClient().Admin(srv.URL, "")
	b := NewProxyConfiguration("set").Minutes(60).WithProxyClient(pc)

	calls := 0
	v, err := RetryN(context.Background(), b, 3, func(i int) (int, bool) {
		calls++
		return i, false
	})
	if err != nil {
		t.Fatalf("RetryN: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
	if rotates != 2 {
		t.Fatalf("expected 2 rotations, got %d", rotates)
	}
	if v != 2 {
		t.Fatalf("expected last value 2, got %d", v)
	}
}

func TestRetryN_EarlyExit(t *testing.T) {
	b := NewProxyConfiguration("set").Minutes(60) // no client; first false will error
	calls := 0
	v, err := RetryN(context.Background(), b, 10, func(i int) (string, bool) {
		calls++
		if i == 2 {
			return "early", true
		}
		return "", false
	})
	if err == nil {
		t.Fatalf("expected error from Rotate without client; got v=%q", v)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call before rotate-error, got %d", calls)
	}
}

func TestProxyConfiguration_Clone(t *testing.T) {
	pc := NewProxyClient().Proxy("127.0.0.1", 8100)
	a := NewProxyConfiguration("set").Minutes(60).SessionParams("user", "alice").WithProxyClient(pc)
	b := a.Clone().SessionParams("user", "bob")

	ua, _ := a.BuildUsername()
	ub, _ := b.BuildUsername()
	if ua == ub {
		t.Fatal("expected clone mutation to produce a different username")
	}
	if a.params.SessionParams["user"] != "alice" {
		t.Fatalf("original affinity was mutated: %v", a.params.SessionParams)
	}
}
