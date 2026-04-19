package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"proxy-kit"
	"proxy-kit/utils"
)

func ptrBool(v bool) *bool { return &v }

var testProxy = &proxykit.Proxy{Host: "upstream", Port: 8080}
var testSource = proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
	return proxykit.Resolved(testProxy), nil
})

// ---------------------------------------------------------------------------
// ParseJSONCreds
// ---------------------------------------------------------------------------

func TestParseJSONCredsPopulatesContext(t *testing.T) {
	h := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		if getSet(ctx) != "res" {
			t.Fatalf("expected set=res, got %q", getSet(ctx))
		}
		if utils.GetSeedTTL(ctx) != 5*time.Minute {
			t.Fatalf("expected ttl=5m, got %v", utils.GetSeedTTL(ctx))
		}
		if utils.GetTopLevelSeed(ctx) == 0 {
			t.Fatal("expected non-zero top-level seed")
		}
		return proxykit.Resolved(testProxy), nil
	}))
	req := &proxykit.Request{
		RawUsername: `{"set":"res","minutes":5}`,
	}
	r, err := h.Resolve(context.Background(), req)
	if err != nil || r.Proxy.Host != "upstream" {
		t.Fatalf("unexpected: err=%v result=%+v", err, r)
	}
}

func TestParseJSONCredsTopLevelSeedStableForSameUsername(t *testing.T) {
	var gotSeed1, gotSeed2 uint64
	h := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		gotSeed1 = utils.GetTopLevelSeed(ctx)
		return proxykit.Resolved(testProxy), nil
	}))
	h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":5,"affinity":{"app":"x"}}`,
	})

	h2 := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		gotSeed2 = utils.GetTopLevelSeed(ctx)
		return proxykit.Resolved(testProxy), nil
	}))
	h2.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":5,"affinity":{"app":"x"}}`,
	})
	if gotSeed1 != gotSeed2 {
		t.Fatalf("same username should produce same seed: %d vs %d", gotSeed1, gotSeed2)
	}
}

func TestParseJSONCredsDifferentMetaDifferentSeed(t *testing.T) {
	var gotSeed1, gotSeed2 uint64
	h := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		gotSeed1 = utils.GetTopLevelSeed(ctx)
		return proxykit.Resolved(testProxy), nil
	}))
	h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":5,"affinity":{"user":"alice"}}`,
	})

	h2 := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		gotSeed2 = utils.GetTopLevelSeed(ctx)
		return proxykit.Resolved(testProxy), nil
	}))
	h2.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":5,"affinity":{"user":"bob"}}`,
	})
	if gotSeed1 == gotSeed2 {
		t.Fatal("different affinity should produce different seeds")
	}
}

func TestParseJSONCredsRejectsEmptyUsername(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &proxykit.Request{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSONCredsRejectsInvalidJSON(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &proxykit.Request{RawUsername: "notjson"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSONCredsRejectsMissingSet(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"minutes":0,"affinity":{}}`,
	}); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// PasswordAuth
// ---------------------------------------------------------------------------

func TestPasswordAuthRejectsWrong(t *testing.T) {
	h := PasswordAuth("s3cret", testSource)
	_, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":0,"affinity":{}}`,
		RawPassword: "wrong",
	})
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestPasswordAuthAcceptsCorrect(t *testing.T) {
	h := PasswordAuth("s3cret", testSource)
	_, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":0,"affinity":{}}`,
		RawPassword: "s3cret",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestPasswordAuthDisabledWhenEmpty(t *testing.T) {
	h := PasswordAuth("", testSource)
	_, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":0,"affinity":{}}`,
		RawPassword: "anything",
	})
	if err != nil {
		t.Fatalf("expected pass-through when no password, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Full pipeline with SessionManager
// ---------------------------------------------------------------------------

func TestFullPipeline(t *testing.T) {
	sm := utils.NewSessionManager(testSource)
	pipeline := PasswordAuth("pw", ParseJSONCreds(sm))

	req := &proxykit.Request{
		RawUsername: `{"set":"test","minutes":5,"affinity":{}}`,
		RawPassword: "pw",
	}
	r, err := pipeline.Resolve(context.Background(), req)
	if err != nil || r == nil || r.Proxy == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}

	// Same username → same sticky session
	r2, _ := pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"test","minutes":5,"affinity":{}}`,
		RawPassword: "pw",
	})
	if r2.Proxy.Port != r.Proxy.Port {
		t.Fatal("sticky should return same proxy for same username")
	}

	// Wrong password
	if _, err := pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"test","minutes":5,"affinity":{}}`,
		RawPassword: "wrong",
	}); err == nil {
		t.Fatal("expected auth error")
	}
}

func TestFullPipelineZeroTTLNoAffinity(t *testing.T) {
	counter := 0
	source := proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		counter++
		return proxykit.Resolved(&proxykit.Proxy{Host: "host", Port: uint16(counter)}), nil
	})

	pipeline := ParseJSONCreds(utils.NewSessionManager(source))

	r1, _ := pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"test","minutes":0,"affinity":{}}`,
	})
	r2, _ := pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"test","minutes":0,"affinity":{}}`,
	})
	if r1.Proxy.Port == r2.Proxy.Port {
		t.Fatal("0 minutes should not pin")
	}
}

func TestFullPipelineSeedFlowsToSource(t *testing.T) {
	var gotSeed *proxykit.SessionSeed
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		gotSeed = proxykit.GetSessionSeed(ctx)
		return proxykit.Resolved(testProxy), nil
	})

	pipeline := ParseJSONCreds(utils.NewSessionManager(source))
	pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"test","minutes":5,"affinity":{}}`,
	})

	if gotSeed == nil {
		t.Fatal("source should receive a non-nil SessionSeed when minutes > 0")
	}
}

func TestFullPipelineNilSeedWithoutAffinity(t *testing.T) {
	var gotSeed *proxykit.SessionSeed
	called := false
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		gotSeed = proxykit.GetSessionSeed(ctx)
		called = true
		return proxykit.Resolved(testProxy), nil
	})

	pipeline := ParseJSONCreds(utils.NewSessionManager(source))
	pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"test","minutes":0,"affinity":{}}`,
	})

	if !called {
		t.Fatal("source should have been called")
	}
	if gotSeed != nil {
		t.Fatal("minutes=0 should result in nil seed")
	}
}

func TestBuildProxysetRouterSupportsProxyingIO(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	router, err := buildProxysetRouter(&Config{
		ProxySets: []ProxySetConfig{{
			Name:       "proxying",
			SourceType: "proxyingio",
			ProxyingIO: &utils.ProxyingIOConfig{
				Username:    "account",
				PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
				Countries:   []utils.Country{"DE"},
				HighQuality: ptrBool(true),
			},
		}},
	}, ".")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	ctx := withSet(context.Background(), "proxying")
	ctx = utils.WithSeedTTL(ctx, 5*time.Minute)
	ctx = proxykit.WithSessionSeed(ctx, proxykit.NewSessionSeed(1, 0))

	result, err := router.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.Proxy.Username != "account" {
		t.Fatalf("expected proxyingio username, got %q", result.Proxy.Username)
	}
	if result.Proxy.Port != 8080 {
		t.Fatalf("expected proxyingio default port, got %d", result.Proxy.Port)
	}
	if result.Proxy.Password == "" || !strings.Contains(result.Proxy.Password, "_quality-high") {
		t.Fatalf("expected quality-high password suffix, got %q", result.Proxy.Password)
	}
}

func TestBuildProxysetRouterSupportsProxyingIOSocks5(t *testing.T) {
	t.Setenv("PROXYINGIO_TEST_PASSWORD", "basepw")

	router, err := buildProxysetRouter(&Config{
		ProxySets: []ProxySetConfig{{
			Name:       "proxying-socks5",
			SourceType: "proxyingio",
			ProxyingIO: &utils.ProxyingIOConfig{
				Username:    "account",
				PasswordEnv: "PROXYINGIO_TEST_PASSWORD",
				Protocol:    utils.ProxyingIOProtocolSocks5,
				Countries:   []utils.Country{"AQ"},
				HighQuality: ptrBool(true),
			},
		}},
	}, ".")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	ctx := withSet(context.Background(), "proxying-socks5")
	result, err := router.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.Proxy.Proto() != proxykit.ProtocolSOCKS5 {
		t.Fatalf("expected socks5 protocol, got %q", result.Proxy.Proto())
	}
	if result.Proxy.Port != 1080 {
		t.Fatalf("expected socks5 port, got %d", result.Proxy.Port)
	}
}

func TestBuildProxysetRouterSupportsWebshare(t *testing.T) {
	t.Setenv("WEBSHARE_TEST_PASSWORD", "pw")

	router, err := buildProxysetRouter(&Config{
		ProxySets: []ProxySetConfig{{
			Name:       "webshare",
			SourceType: "webshare",
			Webshare: &utils.WebshareConfig{
				Username:    "trlvvxfs",
				Amount:      20,
				PasswordEnv: "WEBSHARE_TEST_PASSWORD",
			},
		}},
	}, ".")
	if err != nil {
		t.Fatalf("build router: %v", err)
	}

	ctx := withSet(context.Background(), "webshare")
	result, err := router.Resolve(ctx, &proxykit.Request{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.Proxy.Host != "p.webshare.io" || result.Proxy.Port != 80 {
		t.Fatalf("unexpected webshare proxy: %+v", result.Proxy)
	}
	if result.Proxy.Password != "pw" {
		t.Fatalf("unexpected webshare password: %q", result.Proxy.Password)
	}
}

func TestForceRotateChangesSeed(t *testing.T) {
	var seeds []*proxykit.SessionSeed
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seeds = append(seeds, proxykit.GetSessionSeed(ctx))
		return proxykit.Resolved(&proxykit.Proxy{Host: "host", Port: uint16(len(seeds))}), nil
	})

	sm := utils.NewSessionManager(source)
	pipeline := ParseJSONCreds(sm)

	username := `{"set":"test","minutes":60,"affinity":{}}`
	pipeline.Resolve(context.Background(), &proxykit.Request{RawUsername: username})

	u, _ := ParseUsername(username)
	seed := u.Affinity.Seed()
	info := sm.GetSession(seed)
	if info == nil {
		t.Fatal("expected session")
	}
	seedBefore := info.Seed

	info2, err := sm.ForceRotate(seed)
	if err != nil {
		t.Fatal(err)
	}
	if info2 == nil {
		t.Fatal("expected rotated session")
	}
	if info2.Seed == seedBefore {
		t.Fatal("force rotate should produce a different seed")
	}
	if info2.Rotation != 1 {
		t.Fatalf("expected rotation=1, got %d", info2.Rotation)
	}
}
