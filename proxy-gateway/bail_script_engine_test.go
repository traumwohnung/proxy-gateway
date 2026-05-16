package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ── Compile ────────────────────────────────────────────────────────────────

func TestCompile_Happy(t *testing.T) {
	if _, err := Compile("ok", `def bail(r): return None`); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestCompile_MissingBail(t *testing.T) {
	_, err := Compile("nofn", `x = 1`)
	if err == nil || !strings.Contains(err.Error(), "bail") {
		t.Fatalf("want missing-bail error, got %v", err)
	}
}

func TestCompile_SyntaxError(t *testing.T) {
	_, err := Compile("bad", `def bail(r):  ?? `)
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
	_, err := Compile("nc", `bail = 42`)
	if err == nil || !strings.Contains(err.Error(), "not callable") {
		t.Fatalf("want not-callable error, got %v", err)
	}
}

// ── Call return semantics ──────────────────────────────────────────────────

func runCall(t *testing.T, src string, buf []byte) (string, error) {
	t.Helper()
	s, err := Compile(t.Name(), src)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	peek := func(n int) []byte {
		if n < 0 || n > len(buf) {
			return buf
		}
		return buf[:n]
	}
	return s.Call(context.Background(), 200, nil, peek)
}

func TestCall_NoneContinues(t *testing.T) {
	reason, err := runCall(t, `def bail(r): return None`, nil)
	if err != nil || reason != "" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

func TestCall_ImplicitNoneContinues(t *testing.T) {
	reason, err := runCall(t, `def bail(r): pass`, nil)
	if err != nil || reason != "" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

func TestCall_StringBails(t *testing.T) {
	reason, err := runCall(t, `def bail(r): return "datadome"`, nil)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if reason != "datadome" {
		t.Fatalf("reason=%q", reason)
	}
}

func TestCall_RaisedErrorSurfaces(t *testing.T) {
	reason, err := runCall(t, `def bail(r): fail("bad")`, nil)
	if err == nil {
		t.Fatalf("want error, reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("reason should be empty on error, got %q", reason)
	}
}

func TestCall_UnexpectedReturnTypeTreatedAsContinue(t *testing.T) {
	reason, err := runCall(t, `def bail(r): return 42`, nil)
	if err != nil || reason != "" {
		t.Fatalf("expected continue, got reason=%q err=%v", reason, err)
	}
}

func TestCall_PeekAndScan(t *testing.T) {
	body := []byte("hello captcha-delivery.com middle")
	reason, err := runCall(t, `
def bail(r):
    if r.scan(b"captcha-delivery.com") >= 0:
        return "datadome"
    return None
`, body)
	if err != nil || reason != "datadome" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

func TestCall_HeadersLowercased(t *testing.T) {
	s, _ := Compile(t.Name(), `
def bail(r):
    if r.headers["content-type"] == ["text/html"]:
        return "is-html"
    return None
`)
	reason, err := s.Call(context.Background(), 200,
		map[string][]string{"Content-Type": {"text/html"}},
		func(int) []byte { return nil })
	if err != nil || reason != "is-html" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

// ── Limits ─────────────────────────────────────────────────────────────────

func TestCall_StepLimit_ReturnsError(t *testing.T) {
	_, err := runCall(t, `
def bail(r):
    n = 0
    for _ in range(1000000):
        n += 1
    return None
`, nil)
	if err == nil {
		t.Fatal("want step-limit error")
	}
}

func TestCall_ContextCancel_ReturnsError(t *testing.T) {
	s, _ := Compile(t.Name(), `
def bail(r):
    n = 0
    for i in range(99999):
        n = n + i
    return None
`)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(5 * time.Millisecond); cancel() }()
	_, err := s.Call(ctx, 200, nil, func(int) []byte { return nil })
	if err == nil {
		t.Fatal("want cancellation error")
	}
}

// ── bufferedBody ───────────────────────────────────────────────────────────

func TestBufferedBody_PullThenRead(t *testing.T) {
	upstream := io.NopCloser(bytes.NewReader([]byte("abcdefghij")))
	bb := newBufferedBody(upstream, 1024)
	n, err := bb.Pull(4)
	if err != nil || n != 4 || string(bb.Peek(-1)) != "abcd" {
		t.Fatalf("Pull(4): n=%d err=%v buf=%q", n, err, bb.Peek(-1))
	}
	out := make([]byte, 100)
	got, _ := bb.Read(out)
	if got != 4 || string(out[:got]) != "abcd" {
		t.Fatalf("Read drained prefix: %d %q", got, out[:got])
	}
	got, _ = bb.Read(out)
	if got != 6 || string(out[:got]) != "efghij" {
		t.Fatalf("Read tail: %d %q", got, out[:got])
	}
	if _, err := bb.Read(out); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestBufferedBody_HardCap(t *testing.T) {
	bb := newBufferedBody(io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 10000))), 100)
	n, _ := bb.Pull(60)
	if n != 60 {
		t.Fatalf("first Pull: n=%d", n)
	}
	n, _ = bb.Pull(60) // exceeds 100 cap
	if n != 40 {
		t.Fatalf("second Pull should clamp to 40, got %d", n)
	}
	_, err := bb.Pull(1)
	if err == nil {
		t.Fatal("want cap error after exhausting cap")
	}
}

func TestBufferedBody_CloseIdempotent(t *testing.T) {
	closes := 0
	upstream := &countingCloser{Reader: bytes.NewReader([]byte("x")), onClose: func() { closes++ }}
	bb := newBufferedBody(upstream, 1024)
	_ = bb.Close()
	_ = bb.Close()
	if closes != 1 {
		t.Fatalf("close called %d times, want 1", closes)
	}
}

type countingCloser struct {
	io.Reader
	onClose func()
}

func (c *countingCloser) Close() error { c.onClose(); return nil }

// ── Apply end-to-end ───────────────────────────────────────────────────────

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

func TestApply_NoBail_DeliversFullBody(t *testing.T) {
	s, _ := Compile("none", `def bail(r): return None`)
	resp := makeResp("hello world")
	got := Apply(context.Background(), s, resp, 0, 0)
	if got.StatusCode != 200 {
		t.Fatalf("status %d", got.StatusCode)
	}
	if body := readAll(t, got.Body); body != "hello world" {
		t.Fatalf("body=%q", body)
	}
	if got.Header.Get(HeaderBailScriptOutput) != "" {
		t.Fatalf("unexpected bail header")
	}
}

func TestApply_Bail_StatusPreservedReasonHeaderAdded(t *testing.T) {
	closed := false
	upstream := &countingCloser{
		Reader:  bytes.NewReader([]byte("blocked: captcha-delivery.com/...")),
		onClose: func() { closed = true },
	}
	resp := &http.Response{
		StatusCode: 403, Status: "403 Forbidden",
		Header: http.Header{"Content-Type": {"text/html"}}, Body: upstream,
	}
	src := `
def bail(r):
    if r.scan(b"captcha-delivery.com") >= 0:
        return "datadome"
    return None
`
	s, _ := Compile("ab", src)
	got := Apply(context.Background(), s, resp, 0, 0)
	if got.StatusCode != 403 {
		t.Fatalf("status must be preserved, got %d", got.StatusCode)
	}
	if !closed {
		t.Fatalf("upstream not closed")
	}
	if got.Header.Get(HeaderBailScriptOutput) != "datadome" {
		t.Fatalf("X-Bail-Reason=%q", got.Header.Get(HeaderBailScriptOutput))
	}
	// Body is what we received up to the bail point — at least the marker.
	body := readAll(t, got.Body)
	if !strings.Contains(body, "captcha-delivery.com") {
		t.Fatalf("body should contain what we received, got %q", body)
	}
}

func TestApply_ScriptError_AddsHeaderAndContinues(t *testing.T) {
	resp := makeResp("full body delivered intact")
	src := `def bail(r): fail("boom")`
	s, _ := Compile("bad", src)
	got := Apply(context.Background(), s, resp, 0, 0)
	if got.StatusCode != 200 {
		t.Fatalf("status %d", got.StatusCode)
	}
	if got.Header.Get(HeaderBailScriptError) == "" {
		t.Fatalf("missing X-Bail-Script-Error header")
	}
	if body := readAll(t, got.Body); body != "full body delivered intact" {
		t.Fatalf("body=%q (should pass through after error)", body)
	}
}

func TestApply_BailLimitsUpstreamReads(t *testing.T) {
	// 1 MiB upstream; script bails on first call. Only the initial chunk
	// should be pulled (8 KiB default).
	upstream := bytes.Repeat([]byte("x"), 1024*1024)
	pulledBytes := 0
	r := &readCounter{src: bytes.NewReader(upstream), n: &pulledBytes}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(r)}
	src := `def bail(r): return "immediate"`
	s, _ := Compile("imm", src)
	_ = Apply(context.Background(), s, resp, 8192, 0)
	if pulledBytes > 8192 {
		t.Fatalf("pulled %d bytes, want ≤ initial chunk size (~8 KiB)", pulledBytes)
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
	got := Apply(context.Background(), nil, resp, 0, 0)
	if got != resp {
		t.Fatal("nil script should return same pointer")
	}
}

func TestApply_BailOnLaterChunk(t *testing.T) {
	// First chunk has no marker; second chunk introduces it. Multi-call
	// semantics must catch it on the second invocation.
	chunk1 := strings.Repeat("clean ", 1000) // ~6 KiB
	chunk2 := "trigger captcha-delivery.com tail"
	full := chunk1 + chunk2
	resp := makeResp(full)
	src := `
def bail(r):
    if r.scan(b"captcha-delivery.com") >= 0:
        return "datadome"
    return None
`
	s, _ := Compile("late", src)
	got := Apply(context.Background(), s, resp, 4096, 0)
	if got.Header.Get(HeaderBailScriptOutput) != "datadome" {
		t.Fatalf("expected later-chunk bail, header=%q", got.Header.Get(HeaderBailScriptOutput))
	}
}

func TestApply_ReleaseCapWithoutDecision(t *testing.T) {
	// Script always returns None; body exceeds cap → release with no headers.
	full := strings.Repeat("y", 10*1024)
	resp := makeResp(full)
	s, _ := Compile("none", `def bail(r): return None`)
	got := Apply(context.Background(), s, resp, 1024, 2048) // cap < body
	if got.Header.Get(HeaderBailScriptOutput) != "" {
		t.Fatalf("no bail expected, got %q", got.Header.Get(HeaderBailScriptOutput))
	}
	// Should still deliver full body (buffered + remaining).
	if body := readAll(t, got.Body); body != full {
		t.Fatalf("body length mismatch: got %d want %d", len(body), len(full))
	}
}
