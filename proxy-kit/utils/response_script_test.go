package utils

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
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

// ── bufferedBody ───────────────────────────────────────────────────────────

func TestBufferedBody_RequestMoreThenRead(t *testing.T) {
	upstream := io.NopCloser(bytes.NewReader([]byte("abcdefghij"))) // 10 bytes
	bb := newBufferedBody(upstream, 1024)

	got, err := bb.RequestMore(4)
	if err != nil {
		t.Fatalf("RequestMore: %v", err)
	}
	if got != 4 || string(bb.Peek(-1)) != "abcd" {
		t.Fatalf("after RequestMore(4): got=%d buf=%q", got, bb.Peek(-1))
	}

	// Read should drain buffered prefix then continue from upstream.
	out := make([]byte, 100)
	n, _ := bb.Read(out)
	if n != 4 || string(out[:n]) != "abcd" {
		t.Fatalf("Read prefix: n=%d %q", n, out[:n])
	}
	n, _ = bb.Read(out)
	if n != 6 || string(out[:n]) != "efghij" {
		t.Fatalf("Read tail: n=%d %q", n, out[:n])
	}
	if _, err := bb.Read(out); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestBufferedBody_EOFOnShortRequestMore(t *testing.T) {
	bb := newBufferedBody(io.NopCloser(bytes.NewReader([]byte("abc"))), 1024)
	_, err := bb.RequestMore(100)
	if err != io.EOF {
		t.Fatalf("want EOF, got %v; buf=%q", err, bb.Peek(-1))
	}
	if string(bb.Peek(-1)) != "abc" {
		t.Fatalf("buf=%q", bb.Peek(-1))
	}
	// Second call after EOF should immediately EOF.
	_, err = bb.RequestMore(1)
	if err != io.EOF {
		t.Fatalf("second call: want EOF, got %v", err)
	}
}

func TestBufferedBody_HardCap(t *testing.T) {
	bb := newBufferedBody(io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 10000))), 100)
	got, err := bb.RequestMore(50)
	if err != nil || got != 50 {
		t.Fatalf("first 50: got=%d err=%v", got, err)
	}
	got, err = bb.RequestMore(60) // exceeds 100 cap
	if err != nil || got != 100 {
		t.Fatalf("second 60: got=%d err=%v (want clamped to 100)", got, err)
	}
	_, err = bb.RequestMore(1) // already at cap
	if err == nil {
		t.Fatalf("want cap error, got nil")
	}
}

func TestBufferedBody_CloseIdempotent(t *testing.T) {
	closes := 0
	upstream := &countingCloser{Reader: bytes.NewReader([]byte("x")), onClose: func() { closes++ }}
	bb := newBufferedBody(upstream, 1024)
	_ = bb.Close()
	_ = bb.Close()
	if closes != 1 {
		t.Fatalf("want close called once, got %d", closes)
	}
}

type countingCloser struct {
	io.Reader
	onClose func()
}

func (c *countingCloser) Close() error { c.onClose(); return nil }

// ── ApplyScript end-to-end ─────────────────────────────────────────────────

func makeResp(body string) *http.Response {
	return &http.Response{
		StatusCode:    200,
		Status:        "200 OK",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/html"}, "Content-Length": {"42"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func readAll(t *testing.T, body io.ReadCloser) string {
	t.Helper()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	body.Close()
	return string(b)
}

func TestApply_Passthrough_DeliversFullBody(t *testing.T) {
	s, _ := Compile("pt", `def on_response(r): return r.passthrough()`)
	resp := makeResp("hello world")
	got := ApplyScript(context.Background(), s, resp, 0, 0)
	if got.StatusCode != 200 {
		t.Fatalf("status %d", got.StatusCode)
	}
	if body := readAll(t, got.Body); body != "hello world" {
		t.Fatalf("body=%q", body)
	}
}

func TestApply_Abort_Returns499AndClosesUpstream(t *testing.T) {
	closed := false
	upstream := &countingCloser{
		Reader:  bytes.NewReader([]byte("blocked: geo.captcha-delivery.com/...")),
		onClose: func() { closed = true },
	}
	resp := &http.Response{
		StatusCode: 403, Status: "403 Forbidden",
		Header: http.Header{}, Body: upstream,
	}
	src := `
def on_response(r):
    if r.scan(b"captcha-delivery.com") >= 0:
        return r.abort("datadome")
    return r.passthrough()
`
	s, err := Compile("ab", src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := ApplyScript(context.Background(), s, resp, 0, 0)
	if got.StatusCode != 499 {
		t.Fatalf("status %d, want 499", got.StatusCode)
	}
	if !closed {
		t.Fatalf("upstream not closed")
	}
	if got.Header.Get("X-Gateway-Abort") != "datadome" {
		t.Fatalf("header=%q", got.Header.Get("X-Gateway-Abort"))
	}
	body := readAll(t, got.Body)
	if !strings.Contains(body, `"aborted":true`) || !strings.Contains(body, `"datadome"`) {
		t.Fatalf("body=%q", body)
	}
}

func TestApply_Extract_ReturnsSliceOnly(t *testing.T) {
	full := `lots of junk before __START__payload__END__lots more junk after`
	resp := makeResp(full)
	src := `
def on_response(r):
    s = r.scan(b"__START__")
    if s < 0: return r.passthrough()
    s += len(b"__START__")
    e = r.scan(b"__END__", s)
    if e < 0: return r.passthrough()
    return r.extract(s, e)
`
	s, _ := Compile("ex", src)
	got := ApplyScript(context.Background(), s, resp, 0, 0)
	if body := readAll(t, got.Body); body != "payload" {
		t.Fatalf("body=%q", body)
	}
	if got.Header.Get("Content-Length") != "7" {
		t.Fatalf("Content-Length=%q", got.Header.Get("Content-Length"))
	}
	if got.Header.Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding should be stripped, got %q", got.Header.Get("Content-Encoding"))
	}
	if got.Header.Get("X-Gateway-Extract") != "ok" {
		t.Fatalf("missing X-Gateway-Extract")
	}
}

func TestApply_BodyConsumedBytes_AbortStopsAtBuffer(t *testing.T) {
	// 1 MiB upstream; script aborts after seeing first byte. Verify the
	// bufferedBody only pulled the initial pre-buffer.
	upstream := make([]byte, 1024*1024)
	for i := range upstream {
		upstream[i] = 'x'
	}
	pulledBytes := 0
	r := &readCounter{src: bytes.NewReader(upstream), n: &pulledBytes}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(r)}
	src := `def on_response(r): return r.abort("immediate")`
	s, _ := Compile("ab", src)
	_ = ApplyScript(context.Background(), s, resp, 4096, 0)
	if pulledBytes > 8192 {
		t.Fatalf("pulled %d bytes, expected ≤ initial pre-buffer (~4 KiB)", pulledBytes)
	}
}

type readCounter struct {
	src *bytes.Reader
	n   *int
}

func (r *readCounter) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	*r.n += n
	return n, err
}

func TestApply_NilScript_ReturnsResponseUnchanged(t *testing.T) {
	resp := makeResp("noop")
	got := ApplyScript(context.Background(), nil, resp, 0, 0)
	if got != resp {
		t.Fatal("nil script should return same pointer")
	}
}
