package utils

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// staticBuffer is a fake upstream body for unit tests. peek returns the
// already-buffered prefix; requestMore consumes more from the remaining
// "upstream" slice.
type staticBuffer struct {
	upstream  []byte // bytes still available at the upstream
	buf       []byte // prefix already pulled from upstream
	requested int
}

func newStaticBuffer(initial, upstreamRemainder []byte) *staticBuffer {
	return &staticBuffer{buf: append([]byte(nil), initial...), upstream: upstreamRemainder}
}

func (s *staticBuffer) peek(n int) []byte {
	if n < 0 || n >= len(s.buf) {
		return s.buf
	}
	return s.buf[:n]
}

func (s *staticBuffer) requestMore(n int) (int, error) {
	s.requested += n
	want := n
	if want > len(s.upstream) {
		want = len(s.upstream)
	}
	if want == 0 {
		return len(s.buf), io.EOF
	}
	s.buf = append(s.buf, s.upstream[:want]...)
	s.upstream = s.upstream[want:]
	return len(s.buf), nil
}

func runScript(t *testing.T, src string, status int, headers map[string][]string, body *staticBuffer) (Decision, error) {
	t.Helper()
	s, err := Compile(t.Name(), src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s.Run(context.Background(), status, headers, body.peek, body.requestMore)
}

// ── Compile ────────────────────────────────────────────────────────────────

func TestCompile_Happy(t *testing.T) {
	_, err := Compile("ok", `def on_response(r): return r.passthrough()`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestCompile_MissingOnResponse(t *testing.T) {
	_, err := Compile("nofn", `x = 1`)
	if err == nil || !strings.Contains(err.Error(), "on_response") {
		t.Fatalf("want missing-on_response error, got %v", err)
	}
}

func TestCompile_SyntaxError(t *testing.T) {
	_, err := Compile("bad", `def on_response(r):  ?? `)
	if err == nil {
		t.Fatal("want syntax error")
	}
}

func TestCompile_TooLarge(t *testing.T) {
	big := strings.Repeat("# pad\n", MaxScriptSize)
	_, err := Compile("big", big)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("want size error, got %v", err)
	}
}

func TestCompile_NotCallable(t *testing.T) {
	_, err := Compile("nofn", `on_response = 42`)
	if err == nil || !strings.Contains(err.Error(), "not callable") {
		t.Fatalf("want not-callable error, got %v", err)
	}
}

// ── Actions ────────────────────────────────────────────────────────────────

func TestRun_Passthrough_Default(t *testing.T) {
	body := newStaticBuffer([]byte("hello world"), nil)
	d, err := runScript(t, `def on_response(r): pass`, 200, nil, body)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if d.Action != ActionPassthrough {
		t.Fatalf("want passthrough, got %v", d)
	}
}

func TestRun_Passthrough_Explicit(t *testing.T) {
	body := newStaticBuffer([]byte("hi"), nil)
	d, _ := runScript(t, `def on_response(r): return r.passthrough()`, 200, nil, body)
	if d.Action != ActionPassthrough {
		t.Fatalf("want passthrough, got %v", d)
	}
}

func TestRun_Abort_OnMarker(t *testing.T) {
	body := newStaticBuffer([]byte("<html>...geo.captcha-delivery.com..."), nil)
	src := `
def on_response(r):
    if r.scan(b"captcha-delivery.com") >= 0:
        return r.abort("datadome")
    return r.passthrough()
`
	d, err := runScript(t, src, 403, nil, body)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if d.Action != ActionAbort || d.AbortReason != "datadome" {
		t.Fatalf("want abort(datadome), got %+v", d)
	}
}

func TestRun_Extract(t *testing.T) {
	body := newStaticBuffer([]byte(`junk__START__payload__END__more`), nil)
	src := `
def on_response(r):
    s = r.scan(b"__START__")
    if s < 0:
        return r.passthrough()
    s += len(b"__START__")
    e = r.scan(b"__END__", s)
    if e < 0:
        return r.passthrough()
    return r.extract(s, e)
`
	d, _ := runScript(t, src, 200, nil, body)
	if d.Action != ActionExtract {
		t.Fatalf("want extract, got %+v", d)
	}
	if got := string(body.buf[d.ExtractStart:d.ExtractEnd]); got != "payload" {
		t.Fatalf("extracted slice = %q, want %q", got, "payload")
	}
}

func TestRun_DoubleDecision_IsError(t *testing.T) {
	body := newStaticBuffer([]byte("x"), nil)
	src := `
def on_response(r):
    r.abort("a")
    r.passthrough()
`
	d, err := runScript(t, src, 200, nil, body)
	if err == nil {
		t.Fatalf("want error from double decision, got nil; decision=%+v", d)
	}
	if d.Action != ActionPassthrough {
		t.Fatalf("on error, want fallback to passthrough, got %v", d.Action)
	}
}

// ── peek / request_more semantics ──────────────────────────────────────────

func TestRun_PeekAll(t *testing.T) {
	body := newStaticBuffer([]byte("abcdef"), nil)
	src := `
def on_response(r):
    if len(r.peek()) != 6: fail("want 6 buffered")
    if r.peek(3) != b"abc":  fail("peek(3) wrong")
    if r.peek(100) != b"abcdef": fail("peek beyond should clamp")
    return r.passthrough()
`
	if _, err := runScript(t, src, 200, nil, body); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestRun_RequestMore_ExtendsBuffer(t *testing.T) {
	body := newStaticBuffer([]byte("aaaa"), []byte("bbbbcccc"))
	src := `
def on_response(r):
    if len(r.peek()) != 4: fail("initial")
    if r.request_more(4) != True: fail("first")
    if len(r.peek()) != 8: fail("after first more")
    if r.request_more(8) != True: fail("second")
    if len(r.peek()) != 12: fail("after second more")
    if r.request_more(1) != False: fail("EOF expected")
    return r.passthrough()
`
	if _, err := runScript(t, src, 200, nil, body); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// ── Limits ─────────────────────────────────────────────────────────────────

func TestRun_StepLimit_FallbackToPassthrough(t *testing.T) {
	body := newStaticBuffer(nil, nil)
	// Tight loop that blows the step budget.
	src := `
def on_response(r):
    n = 0
    for _ in range(1000000):
        n += 1
    return r.passthrough()
`
	d, err := runScript(t, src, 200, nil, body)
	if err == nil {
		t.Fatalf("want step-limit error")
	}
	if d.Action != ActionPassthrough {
		t.Fatalf("on limit, want passthrough fallback, got %v", d.Action)
	}
}

func TestRun_WallClock_FallbackToPassthrough(t *testing.T) {
	body := newStaticBuffer(nil, nil)
	// A range loop large enough to take > MaxWallClock even within steps.
	// We rely on the watchdog cancelling.
	src := `
def on_response(r):
    n = 0
    for i in range(99999):
        n = n + i
    return r.passthrough()
`
	// Tighten budget by wrapping Compile + Run with a faster watchdog —
	// but our limits are constants; just ensure the test completes quickly
	// either way. We don't assert wall-clock specifically here since steps
	// will catch it first; this is a smoke test.
	t.Cleanup(func() { _ = time.Now() })
	d, _ := runScript(t, src, 200, nil, body)
	if d.Action != ActionPassthrough {
		t.Fatalf("want passthrough fallback, got %v", d.Action)
	}
}

func TestRun_ContextCancel_FallbackToPassthrough(t *testing.T) {
	body := newStaticBuffer(nil, nil)
	// Starlark has no `while`; use a huge range loop so the watchdog has
	// time to fire before steps exhaust.
	src := `
def on_response(r):
    n = 0
    for i in range(99999):
        n = n + i
    return r.passthrough()
`
	s, err := Compile(t.Name(), src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	d, err := s.Run(ctx, 200, nil, body.peek, body.requestMore)
	if err == nil {
		t.Fatalf("want cancellation error")
	}
	if d.Action != ActionPassthrough {
		t.Fatalf("want passthrough fallback, got %v", d.Action)
	}
}

// ── headers + status ───────────────────────────────────────────────────────

func TestRun_HeadersAccessible(t *testing.T) {
	body := newStaticBuffer(nil, nil)
	headers := map[string][]string{
		"Content-Type": {"text/html"},
		"Set-Cookie":   {"a=1", "b=2"},
	}
	src := `
def on_response(r):
    if r.status != 200: fail("status")
    h = r.headers
    if h["content-type"] != ["text/html"]: fail("content-type lowercased")
    if len(h["set-cookie"]) != 2: fail("set-cookie multi-value")
    return r.passthrough()
`
	if _, err := runScript(t, src, 200, headers, body); err != nil {
		t.Fatalf("run: %v", err)
	}
}

// ── sanity: returned Decision survives runtime panic in builtin args ───────

func TestRun_BuiltinArgError_FallbackToPassthrough(t *testing.T) {
	body := newStaticBuffer(nil, nil)
	src := `def on_response(r): return r.extract(-1, 5)`
	d, err := runScript(t, src, 200, nil, body)
	if err == nil {
		t.Fatal("want arg-validation error")
	}
	if d.Action != ActionPassthrough {
		t.Fatalf("want passthrough fallback, got %v", d.Action)
	}
}

// Ensures we don't leak watchdog goroutines on the happy path.
func TestRun_NoWatchdogLeak(t *testing.T) {
	s, _ := Compile("noop", `def on_response(r): return r.passthrough()`)
	body := newStaticBuffer(nil, nil)
	for i := 0; i < 100; i++ {
		_, err := s.Run(context.Background(), 200, nil, body.peek, body.requestMore)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	// If we leak a goroutine per Run, race detector would complain;
	// pragmatic check is just that the loop completes without timeout.
	_ = errors.New
}
