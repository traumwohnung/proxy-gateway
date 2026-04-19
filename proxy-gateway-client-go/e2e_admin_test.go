package proxygatewayclient_test

import (
	"testing"
	"time"
)

func TestE2E_AdminAPI_ListSessions_EmptyInitially(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	sessions, err := env.client.ListSessions(ctx())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions initially, got %d", len(sessions))
	}
}

func TestE2E_AdminAPI_SessionAppearsAfterStickyRequest(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 30, map[string]any{"user": "bob"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	sessions, err := env.client.ListSessions(ctx())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	s := sessions[0]
	if s.ProxySet != "test" {
		t.Errorf("proxy_set: got %q, want %q", s.ProxySet, "test")
	}
	if s.Upstream == "" {
		t.Error("upstream should not be empty")
	}
	if s.NextRotationAt.Before(time.Now()) {
		t.Errorf("next_rotation_at should be in the future, got %v", s.NextRotationAt)
	}
}

func TestE2E_AdminAPI_GetSession(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 30, map[string]any{"user": "carol"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	info, err := env.client.GetSession(ctx(), username)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if info == nil {
		t.Fatal("expected session info, got nil")
	}
	if info.ProxySet != "test" {
		t.Errorf("proxy_set: got %q, want %q", info.ProxySet, "test")
	}

	nonexistent := mustBuildUsername(t, "test", 30, map[string]any{"user": "nobody"})
	missing, err := env.client.GetSession(ctx(), nonexistent)
	if err != nil {
		t.Fatalf("GetSession (missing): %v", err)
	}
	if missing != nil {
		t.Fatal("expected nil for unknown username")
	}
}

func TestE2E_AdminAPI_NoSessionForZeroMinutes(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, map[string]any{"user": "dave"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	sessions, err := env.client.ListSessions(ctx())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("minutes=0 requests should not create sessions, got %d", len(sessions))
	}
}

func TestE2E_AdminAPI_ForceRotate_ChangesUpstream(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 60, map[string]any{"user": "eve"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	info, err := env.client.GetSession(ctx(), username)
	if err != nil || info == nil {
		t.Fatalf("GetSession before rotate: err=%v info=%v", err, info)
	}
	upstreamBefore := info.Upstream

	rotated, err := env.client.ForceRotate(ctx(), username)
	if err != nil {
		t.Fatalf("ForceRotate: %v", err)
	}
	if rotated == nil {
		t.Fatal("expected non-nil response from ForceRotate")
	}
	if rotated.LastRotationAt.IsZero() {
		t.Error("last_rotation_at should be set after force rotate")
	}
	if rotated.ProxySet != "test" {
		t.Errorf("proxy_set should be preserved after rotate, got %q", rotated.ProxySet)
	}
	t.Logf("upstream before=%s after=%s", upstreamBefore, rotated.Upstream)
}

func TestE2E_AdminAPI_ForceRotate_NonExistentReturnsNil(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	nonexistent := mustBuildUsername(t, "test", 30, map[string]any{"user": "ghost"})
	result, err := env.client.ForceRotate(ctx(), nonexistent)
	if err != nil {
		t.Fatalf("ForceRotate on non-existent: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil for non-existent session")
	}
}
