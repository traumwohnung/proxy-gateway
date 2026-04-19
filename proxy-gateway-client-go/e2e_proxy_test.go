package proxygatewayclient_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
)

func ctx() context.Context { return context.Background() }

func TestE2E_BuildAndParseUsername(t *testing.T) {
	params := proxygatewayclient.UsernameParams{
		Set:     "residential",
		Minutes: 60,
		Affinity:    map[string]any{"platform": "myapp", "user": "alice"},
	}
	u, err := proxygatewayclient.BuildUsername(params)
	if err != nil {
		t.Fatalf("BuildUsername: %v", err)
	}

	got, err := proxygatewayclient.ParseUsername(u)
	if err != nil {
		t.Fatalf("ParseUsername: %v", err)
	}
	if got.Set != "residential" || got.Minutes != 60 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestE2E_HTTPConnect_ThroughGatewayAndUpstreamProxy(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	body := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")
	if body["method"] != "GET" {
		t.Fatalf("unexpected echo body: %v", body)
	}
}

func TestE2E_SOCKS5_ThroughGatewayAndUpstreamProxy(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	body := doSOCKS5ToEcho(t, env.gatewaySOCKS5Addr, env.echoAddr, username, "x")
	if body["method"] != "GET" {
		t.Fatalf("unexpected echo body: %v", body)
	}
}

func TestE2E_PlainHTTP_ThroughGateway(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	status, body := doPlainHTTP(t, env.gatewayHTTPAddr, "http://"+env.echoAddr+"/hello", username, "x")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if body["path"] != "/hello" {
		t.Fatalf("unexpected path in echo: %v", body)
	}
}

func TestE2E_SessionAffinity_SameUsernamePinsSameUpstream(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 60, map[string]any{"user": "alice"})

	var upstreamHosts []string
	for i := 0; i < 5; i++ {
		body := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")
		remote, _ := body["remote_addr"].(string)
		host, _, _ := net.SplitHostPort(remote)
		upstreamHosts = append(upstreamHosts, host)
	}

	for i, u := range upstreamHosts {
		if u != upstreamHosts[0] {
			t.Fatalf("request %d went through different upstream host: %v (expected %v)\nall: %v", i, u, upstreamHosts[0], upstreamHosts)
		}
	}
}

func TestE2E_NoAffinity_RotatesAcrossUpstreams(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		username := mustBuildUsername(t, "test", 0, map[string]any{"req": fmt.Sprintf("%d", i)})
		_, body := doPlainHTTP(t, env.gatewayHTTPAddr, "http://"+env.echoAddr+"/", username, "x")
		via, _ := body["x-forwarded-via"].(string)
		seen[via] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected requests to spread across multiple upstreams, only saw: %v", seen)
	}
}

func TestE2E_ProxyPassword_WrongPasswordRejected(t *testing.T) {
	env := startTestEnv(t, 1, "s3cret")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	if err := tryHTTPConnect(t, env.gatewayHTTPAddr, env.echoAddr, username, "wrongpassword"); err == nil {
		t.Fatal("expected failure with wrong proxy password, got success")
	}
}

func TestE2E_ProxyPassword_CorrectPasswordAccepted(t *testing.T) {
	env := startTestEnv(t, 1, "s3cret")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	body := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "s3cret")
	if body["method"] != "GET" {
		t.Fatalf("unexpected echo body: %v", body)
	}
}

func TestE2E_ConcurrentStickyRequests_AllPinnedToSameUpstream(t *testing.T) {
	env := startTestEnv(t, 5, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 60, map[string]any{"user": "frank"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	info, err := env.client.GetSession(ctx(), username)
	if err != nil || info == nil {
		t.Fatalf("GetSession: err=%v info=%v", err, info)
	}
	expectedUpstream := info.Upstream

	const concurrency = 10
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")
		}()
	}
	wg.Wait()

	info2, err := env.client.GetSession(ctx(), username)
	if err != nil || info2 == nil {
		t.Fatalf("GetSession after concurrent: err=%v info=%v", err, info2)
	}
	if info2.Upstream != expectedUpstream {
		t.Errorf("upstream changed during concurrent requests: before=%v after=%v", expectedUpstream, info2.Upstream)
	}
}

func TestE2E_MultipleDistinctSessions(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	users := []string{"user-a", "user-b", "user-c"}
	usernames := make([]string, len(users))
	for i, u := range users {
		usernames[i] = mustBuildUsername(t, "test", 60, map[string]any{"user": u})
		doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, usernames[i], "x")
	}

	sessions, err := env.client.ListSessions(ctx())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions for 3 distinct users, got %d", len(sessions))
	}

	for _, u := range usernames {
		body1 := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, u, "x")
		body2 := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, u, "x")
		if body1["x-forwarded-via"] != body2["x-forwarded-via"] {
			t.Errorf("user %q changed upstream between requests", u)
		}
	}
}

func TestE2E_LeastUsedRotation_SpreadAcrossUpstreams(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		username := mustBuildUsername(t, "test", 0, map[string]any{"req": fmt.Sprintf("%d", i)})
		_, body := doPlainHTTP(t, env.gatewayHTTPAddr, "http://"+env.echoAddr+"/", username, "x")
		via, _ := body["x-forwarded-via"].(string)
		if via != "" {
			seen[via]++
		}
	}

	if len(seen) != 3 {
		t.Fatalf("expected all 3 upstreams to be used, only saw %d: %v", len(seen), seen)
	}
	for addr, count := range seen {
		if count < 2 || count > 4 {
			t.Errorf("upstream %v handled %d requests, expected ~3 (least-used)", addr, count)
		}
	}
}
