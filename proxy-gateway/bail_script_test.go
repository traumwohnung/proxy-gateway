package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proxykit "proxy-kit"
	"proxy-kit/utils"
)

// ── ParseUsername: bail_script field ───────────────────────────────────────

const validBail = `def bail(r): return None`

func TestParseUsername_BailScriptCompiled(t *testing.T) {
	raw := `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"},"bail_script":"def bail(r): return 'datadome'"}`
	u, err := ParseUsername(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.BailScript == nil {
		t.Fatal("expected compiled script, got nil")
	}
}

func TestParseUsername_BailScriptRequiresHttpcloak(t *testing.T) {
	raw := `{"set":"res","bail_script":"def bail(r): return None"}`
	_, err := ParseUsername(raw)
	if err == nil || !strings.Contains(err.Error(), "requires httpcloak") {
		t.Fatalf("want httpcloak-required error, got %v", err)
	}
}

func TestParseUsername_BailScriptCompileErrorSurfaces(t *testing.T) {
	raw := `{"set":"res","httpcloak":{"preset":"chrome-latest"},"bail_script":"this is not starlark"}`
	_, err := ParseUsername(raw)
	if err == nil || !strings.Contains(err.Error(), "bail_script") {
		t.Fatalf("want script-compile error, got %v", err)
	}
}

func TestParseUsername_NoBailScriptIsOK(t *testing.T) {
	raw := `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"}}`
	u, err := ParseUsername(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.BailScript != nil {
		t.Fatal("want nil script when field absent")
	}
}

// ── ParseJSONCreds: context propagation ────────────────────────────────────

func TestParseJSONCreds_PutsBailScriptOnContext(t *testing.T) {
	var seen *utils.BailScript
	h := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seen = getBailScript(ctx)
		return &proxykit.Result{Proxy: &proxykit.Proxy{Host: "x", Port: 1}}, nil
	}))
	_, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","httpcloak":{"preset":"chrome-latest"},"bail_script":"` + validBail + `"}`,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if seen == nil {
		t.Fatal("expected script on context")
	}
}

// ── Per-set router: installs ResponseHook ──────────────────────────────────

func writeConfig(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir, path
}

func TestLoadConfig_CompilesPerSetBail(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
bail_script = "def bail(r): return None"
`
	_, path := writeConfig(t, body)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ProxySets[0].CompiledBail() == nil {
		t.Fatal("want compiled script")
	}
}

func TestLoadConfig_BadBailFailsBoot(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
bail_script = "this is not starlark"
`
	_, path := writeConfig(t, body)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("want compile error at boot")
	}
}

func TestBuildServer_PerSetBailInstallsHook(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
bail_script = """
def bail(r):
    if r.scan(b'BLOCK') >= 0:
        return 'blocked'
    return None
"""
`
	dir, path := writeConfig(t, body)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := BuildServer(cfg, dir, "", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	result, err := srv.Pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"}}`,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result == nil || result.ResponseHook == nil {
		t.Fatalf("expected ResponseHook from per-set default; result=%+v", result)
	}

	// Bail path: body contains the marker → hook returns same status with
	// X-Bail-Reason header; body preserved up to bail point.
	blocked := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("xxBLOCKxx"))),
	}
	hooked := result.ResponseHook(blocked)
	if hooked.StatusCode != 200 {
		t.Fatalf("status must be preserved, got %d", hooked.StatusCode)
	}
	if hooked.Header.Get(utils.HeaderBailReason) != "blocked" {
		t.Fatalf("X-Bail-Reason=%q", hooked.Header.Get(utils.HeaderBailReason))
	}

	// Passthrough path: no marker → original status + body intact.
	ok := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("clean payload"))),
	}
	hooked2 := result.ResponseHook(ok)
	if hooked2.StatusCode != 200 {
		t.Fatalf("want 200, got %d", hooked2.StatusCode)
	}
	if hooked2.Header.Get(utils.HeaderBailReason) != "" {
		t.Fatalf("unexpected bail header on passthrough")
	}
	body2, _ := io.ReadAll(hooked2.Body)
	if string(body2) != "clean payload" {
		t.Fatalf("body=%q", body2)
	}
}

func TestBuildServer_PerCallBailOverridesPerSet(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
bail_script = "def bail(r): return None"
`
	dir, path := writeConfig(t, body)
	cfg, _ := LoadConfig(path)
	srv, _ := BuildServer(cfg, dir, "", nil)

	override := `def bail(r): return 'override-fires'`
	raw := `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"},"bail_script":` +
		jsonString(override) + `}`

	result, err := srv.Pipeline.Resolve(context.Background(), &proxykit.Request{RawUsername: raw})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ResponseHook == nil {
		t.Fatal("expected ResponseHook")
	}
	hooked := result.ResponseHook(&http.Response{
		StatusCode: 200, Header: http.Header{},
		Body: io.NopCloser(bytes.NewReader([]byte("anything"))),
	})
	if hooked.Header.Get(utils.HeaderBailReason) != "override-fires" {
		t.Fatalf("override did not fire: header=%q", hooked.Header.Get(utils.HeaderBailReason))
	}
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
