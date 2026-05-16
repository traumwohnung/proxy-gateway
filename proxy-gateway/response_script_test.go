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

// ── ParseUsername: response_script field ───────────────────────────────────

const validResponseScript = `def on_response(r): return r.passthrough()`

func TestParseUsername_ResponseScriptCompiled(t *testing.T) {
	raw := `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"},"response_script":"def on_response(r): return r.abort('x')"}`
	u, err := ParseUsername(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.ResponseScript == nil {
		t.Fatal("expected compiled script, got nil")
	}
}

func TestParseUsername_ResponseScriptRequiresHttpcloak(t *testing.T) {
	raw := `{"set":"res","response_script":"def on_response(r): return r.passthrough()"}`
	_, err := ParseUsername(raw)
	if err == nil || !strings.Contains(err.Error(), "requires httpcloak") {
		t.Fatalf("want httpcloak-required error, got %v", err)
	}
}

func TestParseUsername_ResponseScriptCompileErrorSurfaces(t *testing.T) {
	raw := `{"set":"res","httpcloak":{"preset":"chrome-latest"},"response_script":"this is not starlark"}`
	_, err := ParseUsername(raw)
	if err == nil || !strings.Contains(err.Error(), "response_script") {
		t.Fatalf("want script-compile error, got %v", err)
	}
}

func TestParseUsername_NoResponseScriptIsOK(t *testing.T) {
	raw := `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"}}`
	u, err := ParseUsername(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.ResponseScript != nil {
		t.Fatal("want nil script when field absent")
	}
}

// ── ParseJSONCreds: context propagation ────────────────────────────────────

func TestParseJSONCreds_PutsScriptOnContext(t *testing.T) {
	var seen *utils.Script
	h := ParseJSONCreds(proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seen = getResponseScript(ctx)
		return &proxykit.Result{Proxy: &proxykit.Proxy{Host: "x", Port: 1}}, nil
	}))
	_, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","httpcloak":{"preset":"chrome-latest"},"response_script":"` + validResponseScript + `"}`,
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

func TestLoadConfig_CompilesPerSetScript(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
response_script = "def on_response(r): return r.passthrough()"
`
	_, path := writeConfig(t, body)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ProxySets[0].CompiledScript() == nil {
		t.Fatal("want compiled script")
	}
}

func TestLoadConfig_BadScriptFailsBoot(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
response_script = "this is not starlark"
`
	_, path := writeConfig(t, body)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("want compile error at boot")
	}
}

func TestBuildServer_PerSetScriptInstallsResponseHook(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
response_script = """
def on_response(r):
    if r.scan(b'BLOCK') >= 0:
        return r.abort('blocked')
    return r.passthrough()
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

	// Simulate a request landing on the per-set source: invoke the
	// pipeline with a valid username (no per-call override), then exercise
	// the ResponseHook on a synthetic response.
	result, err := srv.Pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"}}`,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result == nil || result.ResponseHook == nil {
		t.Fatalf("expected ResponseHook from per-set default; result=%+v", result)
	}

	// Block path: body contains the marker → hook returns 499.
	blocked := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("xxBLOCKxx"))),
	}
	hooked := result.ResponseHook(blocked)
	if hooked.StatusCode != 499 {
		t.Fatalf("want 499, got %d", hooked.StatusCode)
	}
	if hooked.Header.Get("X-Gateway-Abort") != "blocked" {
		t.Fatalf("missing X-Gateway-Abort=blocked, got %q", hooked.Header.Get("X-Gateway-Abort"))
	}

	// Passthrough path: no marker → original status preserved, body intact.
	ok := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("clean payload"))),
	}
	hooked2 := result.ResponseHook(ok)
	if hooked2.StatusCode != 200 {
		t.Fatalf("want 200, got %d", hooked2.StatusCode)
	}
	body2, _ := io.ReadAll(hooked2.Body)
	if string(body2) != "clean payload" {
		t.Fatalf("body=%q", body2)
	}
}

func TestBuildServer_PerCallScriptOverridesPerSet(t *testing.T) {
	// Per-set default would passthrough; per-call override aborts.
	body := `
[[proxy_set]]
name = "res"
provider = "none"
response_script = "def on_response(r): return r.passthrough()"
`
	dir, path := writeConfig(t, body)
	cfg, _ := LoadConfig(path)
	srv, _ := BuildServer(cfg, dir, "", nil)

	override := `def on_response(r): return r.abort('override-fires')`
	raw := `{"set":"res","minutes":0,"httpcloak":{"preset":"chrome-latest"},"response_script":` +
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
	if hooked.StatusCode != 499 || hooked.Header.Get("X-Gateway-Abort") != "override-fires" {
		t.Fatalf("override did not fire: status=%d abort=%q", hooked.StatusCode, hooked.Header.Get("X-Gateway-Abort"))
	}
}

// jsonString is the smallest possible json.Marshal for a string.
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
