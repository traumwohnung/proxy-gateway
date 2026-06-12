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
)

// ── ParseUsername: mitm scoping ────────────────────────────────────────────

const validInline = `{"kind":"source","source":"def response_bailing(r): return None"}`

func TestParseUsername_NoMITM_TunnelMode(t *testing.T) {
	u, err := ParseUsername(`{"set":"res"}`, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Httpcloak != nil {
		t.Fatalf("want nil Httpcloak in tunnel mode, got %+v", u.Httpcloak)
	}
	if len(u.Scripts) != 0 {
		t.Fatalf("want no scripts in tunnel mode")
	}
}

func TestParseUsername_EmptyMITM_DefaultsToChromeLatest(t *testing.T) {
	u, err := ParseUsername(`{"set":"res","mitm":{}}`, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Httpcloak == nil || u.Httpcloak.Preset != "chrome-latest" {
		t.Fatalf("want chrome-latest default, got %+v", u.Httpcloak)
	}
}

func TestParseUsername_InlineScriptCompiled(t *testing.T) {
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":[` + validInline + `]}}`
	u, err := ParseUsername(raw, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(u.Scripts) != 1 || !u.Scripts[0].HasResponseBailing() {
		t.Fatalf("want 1 script with bail, got %+v", u.Scripts)
	}
}

func TestParseUsername_ScriptsWithoutHTTPCloak_GetsDefault(t *testing.T) {
	raw := `{"set":"res","mitm":{"scripts":[` + validInline + `]}}`
	u, err := ParseUsername(raw, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Httpcloak == nil || u.Httpcloak.Preset != "chrome-latest" {
		t.Fatalf("want chrome-latest default, got %+v", u.Httpcloak)
	}
	if len(u.Scripts) != 1 {
		t.Fatalf("want 1 script, got %d", len(u.Scripts))
	}
}

func TestParseUsername_TopLevelHTTPCloak_Rejected(t *testing.T) {
	raw := `{"set":"res","httpcloak":"chrome-latest"}`
	_, err := ParseUsername(raw, nil)
	if err == nil || !strings.Contains(err.Error(), "top-level 'httpcloak'") {
		t.Fatalf("want top-level httpcloak rejection, got %v", err)
	}
}

func TestParseUsername_TopLevelScripts_Rejected(t *testing.T) {
	raw := `{"set":"res","scripts":[` + validInline + `]}`
	_, err := ParseUsername(raw, nil)
	if err == nil || !strings.Contains(err.Error(), "top-level 'scripts'") {
		t.Fatalf("want top-level scripts rejection, got %v", err)
	}
}

func TestParseUsername_RefWithoutRegistryErrors(t *testing.T) {
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":["antibot"]}}`
	_, err := ParseUsername(raw, nil)
	if err == nil || !strings.Contains(err.Error(), "no script registry") {
		t.Fatalf("want no-registry error, got %v", err)
	}
}

func TestParseUsername_RefResolvesViaRegistry(t *testing.T) {
	s, _ := Compile("antibot", `def response_bailing(r): return None`)
	reg := scriptMap{"antibot": s}
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":["antibot"]}}`
	u, err := ParseUsername(raw, reg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(u.Scripts) != 1 || u.Scripts[0] != s {
		t.Fatalf("ref did not resolve to registry entry")
	}
}

func TestParseUsername_UnknownRefErrors(t *testing.T) {
	reg := scriptMap{}
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":["missing"]}}`
	_, err := ParseUsername(raw, reg)
	if err == nil || !strings.Contains(err.Error(), `unknown script reference "missing"`) {
		t.Fatalf("want unknown-ref error, got %v", err)
	}
}

func TestParseUsername_MixedRefAndInline(t *testing.T) {
	s, _ := Compile("a", `def response_bailing(r): return None`)
	reg := scriptMap{"a": s}
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":["a",` + validInline + `,{"kind":"ref","name":"a"}]}}`
	u, err := ParseUsername(raw, reg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(u.Scripts) != 3 {
		t.Fatalf("want 3 scripts, got %d", len(u.Scripts))
	}
}

func TestParseUsername_UnknownKindErrors(t *testing.T) {
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":[{"kind":"nonsense"}]}}`
	_, err := ParseUsername(raw, scriptMap{})
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("want unknown-kind error, got %v", err)
	}
}

func TestParseUsername_EmptyScriptsArrayIsOK(t *testing.T) {
	raw := `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":[]}}`
	u, err := ParseUsername(raw, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(u.Scripts) != 0 {
		t.Fatalf("want empty, got %d", len(u.Scripts))
	}
}

// ── ParseJSONCreds: context propagation ────────────────────────────────────

func TestParseJSONCreds_PutsScriptsOnContext(t *testing.T) {
	s, _ := Compile("antibot", `def response_bailing(r): return None`)
	reg := scriptMap{"antibot": s}
	var seen []*Script
	h := ParseJSONCreds(reg, proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seen = getScripts(ctx)
		return &proxykit.Result{Proxy: &proxykit.Proxy{Host: "x", Port: 1}}, nil
	}))
	_, err := h.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":["antibot"]}}`,
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("expected 1 script on context, got %d", len(seen))
	}
}

// ── LoadConfig: named script registry ─────────────────────────────────────

func writeConfig(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return dir, path
}

func TestLoadConfig_CompilesNamedScripts(t *testing.T) {
	body := `
[[script]]
name = "antibot"
source = "def response_bailing(r): return None"

[[proxy_set]]
name = "res"
provider = "none"
`
	_, path := writeConfig(t, body)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Registry() == nil {
		t.Fatal("want registry populated")
	}
	if _, ok := cfg.Registry().Lookup("antibot"); !ok {
		t.Fatal("registry missing antibot")
	}
}

func TestLoadConfig_BadScriptSourceFailsBoot(t *testing.T) {
	body := `
[[script]]
name = "bad"
source = "this is not starlark"
`
	_, path := writeConfig(t, body)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("want compile error at boot")
	}
}

func TestLoadConfig_DuplicateNameFails(t *testing.T) {
	body := `
[[script]]
name = "dup"
source = "def response_bailing(r): return None"

[[script]]
name = "dup"
source = "def response_bailing(r): return None"
`
	_, path := writeConfig(t, body)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("want duplicate-name error, got %v", err)
	}
}

// ── End-to-end: per-call script chain installs hook ───────────────────────

func TestBuildServer_PerCallChainInstallsHook(t *testing.T) {
	body := `
[[script]]
name = "antibot"
source = """
def response_bailing(r):
    if r.scan(b'BLOCK') >= 0:
        return 'blocked'
    return None
"""

[[proxy_set]]
name = "res"
provider = "none"
`
	dir, path := writeConfig(t, body)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	srv, err := BuildServer(cfg, dir, "pw", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	result, err := srv.Pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","mitm":{"httpcloak":"chrome-latest","scripts":["antibot"]}}`,
		RawPassword: "pw",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result == nil || result.ResponseHook == nil {
		t.Fatalf("want ResponseHook from per-call chain")
	}
	hooked := result.ResponseHook(&http.Response{
		StatusCode: 200, Header: http.Header{},
		Body: io.NopCloser(bytes.NewReader([]byte("xxBLOCKxx"))),
	})
	if hooked.Header.Get(HeaderResponseBailingOutput) != "blocked" {
		t.Fatalf("header=%q", hooked.Header.Get(HeaderResponseBailingOutput))
	}
}

func TestBuildServer_NoScriptsNoHook(t *testing.T) {
	body := `
[[proxy_set]]
name = "res"
provider = "none"
`
	dir, path := writeConfig(t, body)
	cfg, _ := LoadConfig(path)
	srv, _ := BuildServer(cfg, dir, "pw", nil)
	result, err := srv.Pipeline.Resolve(context.Background(), &proxykit.Request{
		RawUsername: `{"set":"res","mitm":{}}`,
		RawPassword: "pw",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result != nil && result.ResponseHook != nil {
		t.Fatalf("want no ResponseHook when mitm has no scripts")
	}
}

// ── Chain ordering: first bail wins ───────────────────────────────────────

func TestApply_ChainFirstBailWins(t *testing.T) {
	first, _ := Compile("first", `def response_bailing(r): return 'first'`)
	second, _ := Compile("second", `def response_bailing(r): return 'second'`)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte("body")))}
	got := ApplyResponseBailing(context.Background(), []*Script{first, second}, resp, 0, 0)
	if got.Header.Get(HeaderResponseBailingOutput) != "first" {
		t.Fatalf("want first, got %q", got.Header.Get(HeaderResponseBailingOutput))
	}
	if got.Header.Get("X-Script-Response-Bailing-Name") != "first" {
		t.Fatalf("want bailed-by=first, got %q", got.Header.Get("X-Script-Response-Bailing-Name"))
	}
}

func TestApply_ChainSkipsNoneReturners(t *testing.T) {
	noop, _ := Compile("noop", `def response_bailing(r): return None`)
	hit, _ := Compile("hit", `def response_bailing(r): return 'hit'`)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte("body")))}
	got := ApplyResponseBailing(context.Background(), []*Script{noop, hit}, resp, 0, 0)
	if got.Header.Get(HeaderResponseBailingOutput) != "hit" {
		t.Fatalf("want hit, got %q", got.Header.Get(HeaderResponseBailingOutput))
	}
}

func TestApply_ChainErroringScriptDisabledLaterScriptStillRuns(t *testing.T) {
	bad, _ := Compile("bad", `def response_bailing(r): fail("boom")`)
	hit, _ := Compile("hit", `def response_bailing(r): return 'hit'`)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte("body")))}
	got := ApplyResponseBailing(context.Background(), []*Script{bad, hit}, resp, 0, 0)
	if got.Header.Get(HeaderResponseBailingOutput) != "hit" {
		t.Fatalf("want hit, got %q", got.Header.Get(HeaderResponseBailingOutput))
	}
	if !strings.Contains(got.Header.Get(HeaderResponseBailingError), "bad:") {
		t.Fatalf("want error header with bad: prefix, got %q", got.Header.Get(HeaderResponseBailingError))
	}
}

func TestCompile_NoRecognisedEntryPointFails(t *testing.T) {
	_, err := Compile("empty", `x = 1`)
	if err == nil || !strings.Contains(err.Error(), "no recognised entry point") {
		t.Fatalf("want no-entry-point error, got %v", err)
	}
}
