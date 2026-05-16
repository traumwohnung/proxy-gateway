// Starlark-based MITM bail script. Engine + lifecycle live here in
// package main because the bail logic is gateway-specific (it depends on
// the MITM hook contract from proxy-kit's Result.ResponseHook).
//
// A bail script is a short Starlark program that runs server-side on the
// proxy-gateway against each MITM'd response. It cannot modify status code
// or transform the body — it can only answer one question after the gateway
// has buffered each new chunk of upstream data:
//
//	"Should we close the upstream connection now?"
//
// The script defines a top-level function `bail(r)` that returns:
//
//   - None (or no explicit return): continue reading from upstream.
//   - str: bail. Close upstream now. The returned string is the reason and
//     is surfaced to the client as the X-Bail-Script-Output response header.
//   - any raised exception: log it, disable the script for this request,
//     keep streaming the response. The error message is surfaced to the
//     client as the X-Bail-Script-Error header (when not yet sent).
//
// The script is invoked once after headers are available, then again after
// every new chunk of body that the gateway buffers. It is never invoked
// again once it has bailed, errored, or the buffered body has reached the
// release cap.
//
// Within the script the `r` object exposes:
//
//	r.status         (int)            upstream status code
//	r.headers        (dict)           lower-cased response headers
//	r.peek(n=None)   -> bytes         buffered body so far (n bytes max)
//	r.scan(needle)   -> int           find `needle` in buffer (-1 if not found)
//
// Sandbox: Starlark is hermetic by default (no I/O, no clock, no imports).
// On top we enforce a per-call wall-clock budget and a step budget; either
// limit being hit logs and falls back to continue.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// Limits. See plan / README for rationale.
const (
	// MaxScriptSize is the maximum size of an inline Starlark source string.
	MaxScriptSize = 32 * 1024

	// MaxExecSteps caps each bail() call's Starlark instructions.
	MaxExecSteps = 100_000

	// MaxWallClock caps wall-clock time of a single bail() call.
	MaxWallClock = 50 * time.Millisecond

	// DefaultChunkBytes is how many additional body bytes the gateway pulls
	// between bail() invocations.
	DefaultChunkBytes = 8 * 1024

	// DefaultReleaseCapBytes is the cumulative cap on bytes the gateway will
	// buffer before releasing the response to the client unconditionally
	// (with script disabled for the remaining stream). Configurable per
	// proxy_set.
	DefaultReleaseCapBytes = 1024 * 1024

	// HeaderBailScriptOutput carries the script's bail string when it returned
	// one before any body was forwarded to the client.
	HeaderBailScriptOutput = "X-Bail-Script-Output"

	// HeaderBailScriptError carries the script's runtime error message when
	// it raised before any body was forwarded to the client.
	HeaderBailScriptError = "X-Bail-Script-Error"
)

// BailScript is a compiled, ready-to-run bail filter.
type BailScript struct {
	name string
	bail starlark.Value
}

// Compile parses and validates a Starlark source. The returned *BailScript
// can be reused across many invocations (each call gets its own thread).
//
// name is used in error messages and stack traces.
func Compile(name, src string) (*BailScript, error) {
	if len(src) > MaxScriptSize {
		return nil, fmt.Errorf("bail script %q: %d bytes exceeds limit %d", name, len(src), MaxScriptSize)
	}
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("bail script %q: empty source", name)
	}

	opts := &syntax.FileOptions{}
	thread := &starlark.Thread{Name: "init:" + name}
	thread.SetMaxExecutionSteps(MaxExecSteps)

	globals, err := starlark.ExecFileOptions(opts, thread, name, src, nil)
	if err != nil {
		return nil, fmt.Errorf("bail script %q: %w", name, err)
	}

	fn, ok := globals["bail"]
	if !ok {
		return nil, fmt.Errorf("bail script %q: missing bail(r) function", name)
	}
	if _, ok := fn.(starlark.Callable); !ok {
		return nil, fmt.Errorf("bail script %q: bail is not callable", name)
	}
	globals.Freeze()
	return &BailScript{name: name, bail: fn}, nil
}

// Call invokes bail() once with the given response handle. Three outcomes:
//
//   - reason != "":  script returned a non-empty string → caller should bail.
//   - err != nil:    script raised, timed out, or exhausted its step budget.
//     Caller should disable the script for the rest of this request.
//   - reason == "" && err == nil: continue.
//
// Any other return value (lists, dicts, ints) is treated as continue plus a
// warning log — scripts should always return None or string.
func (s *BailScript) Call(ctx context.Context, status int, headers map[string][]string, peek PeekFunc) (reason string, err error) {
	thread := &starlark.Thread{Name: "bail:" + s.name}
	thread.SetMaxExecutionSteps(MaxExecSteps)

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-time.After(MaxWallClock):
			thread.Cancel("wall-clock exceeded")
		case <-ctx.Done():
			thread.Cancel("context cancelled")
		}
	}()

	handle := &responseHandle{status: status, headers: headers, peek: peek}

	ret, callErr := starlark.Call(thread, s.bail, starlark.Tuple{handle}, nil)
	if callErr != nil {
		return "", fmt.Errorf("bail script %q runtime error: %w", s.name, callErr)
	}

	switch v := ret.(type) {
	case starlark.NoneType:
		return "", nil
	case starlark.String:
		return string(v), nil
	default:
		slog.Warn("bail script returned unexpected type, treating as continue",
			"script", s.name, "type", ret.Type())
		return "", nil
	}
}

// PeekFunc returns up to n bytes from the start of the currently buffered
// upstream prefix. If n < 0, returns the entire buffer.
type PeekFunc func(n int) []byte

// ── responseHandle: the `r` value exposed to Starlark ──────────────────────

type responseHandle struct {
	status  int
	headers map[string][]string
	peek    PeekFunc
}

var _ starlark.HasAttrs = (*responseHandle)(nil)

func (r *responseHandle) String() string        { return "<Response>" }
func (r *responseHandle) Type() string          { return "Response" }
func (r *responseHandle) Freeze()               {}
func (r *responseHandle) Truth() starlark.Bool  { return starlark.True }
func (r *responseHandle) Hash() (uint32, error) { return 0, errors.New("unhashable type: Response") }

func (r *responseHandle) Attr(name string) (starlark.Value, error) {
	switch name {
	case "status":
		return starlark.MakeInt(r.status), nil
	case "headers":
		return r.headersDict(), nil
	case "peek":
		return starlark.NewBuiltin("peek", r.builtinPeek), nil
	case "scan":
		return starlark.NewBuiltin("scan", r.builtinScan), nil
	}
	return nil, nil
}

func (r *responseHandle) AttrNames() []string {
	return []string{"headers", "peek", "scan", "status"}
}

func (r *responseHandle) headersDict() *starlark.Dict {
	d := starlark.NewDict(len(r.headers))
	for k, vs := range r.headers {
		l := starlark.NewList(make([]starlark.Value, 0, len(vs)))
		for _, v := range vs {
			_ = l.Append(starlark.String(v))
		}
		_ = d.SetKey(starlark.String(strings.ToLower(k)), l)
	}
	d.Freeze()
	return d
}

func (r *responseHandle) builtinPeek(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var n starlark.Value = starlark.None
	if err := starlark.UnpackArgs("peek", args, kwargs, "n?", &n); err != nil {
		return nil, err
	}
	size := -1
	if n != starlark.None {
		ni, ok := n.(starlark.Int)
		if !ok {
			return nil, fmt.Errorf("peek: n must be int or None, got %s", n.Type())
		}
		v, ok := ni.Int64()
		if !ok || v < 0 {
			return nil, fmt.Errorf("peek: n must be >= 0")
		}
		size = int(v)
	}
	return starlark.Bytes(r.peek(size)), nil
}

func (r *responseHandle) builtinScan(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var needle starlark.Bytes
	var start int
	if err := starlark.UnpackArgs("scan", args, kwargs, "needle", &needle, "start?", &start); err != nil {
		return nil, err
	}
	if start < 0 {
		return nil, fmt.Errorf("scan: start must be >= 0")
	}
	buf := r.peek(-1)
	if start >= len(buf) {
		return starlark.MakeInt(-1), nil
	}
	idx := strings.Index(string(buf[start:]), string(needle))
	if idx < 0 {
		return starlark.MakeInt(-1), nil
	}
	return starlark.MakeInt(start + idx), nil
}

// ── bufferedBody: io.ReadCloser wrapper with Peek + chunked pull ───────────

// bufferedBody wraps an io.ReadCloser and exposes Peek + Pull semantics for
// the bail-script loop. After the loop releases, the wrapper acts as a normal
// io.ReadCloser that drains the buffered prefix first then continues from
// upstream.
type bufferedBody struct {
	upstream io.ReadCloser
	buf      []byte
	cap      int
	readPos  int
	closed   bool
	eof      bool
}

func newBufferedBody(upstream io.ReadCloser, cap int) *bufferedBody {
	if cap <= 0 {
		cap = DefaultReleaseCapBytes
	}
	return &bufferedBody{upstream: upstream, cap: cap}
}

// Peek returns up to n bytes from the buffer (n < 0 = all).
func (b *bufferedBody) Peek(n int) []byte {
	if n < 0 || n >= len(b.buf) {
		return b.buf
	}
	return b.buf[:n]
}

// Pull reads up to n more bytes from upstream into the buffer. Returns the
// number of bytes actually appended and io.EOF on upstream exhaustion. A
// short return is fine — the script loop just calls Pull again next round.
func (b *bufferedBody) Pull(n int) (int, error) {
	if b.eof {
		return 0, io.EOF
	}
	if n <= 0 {
		return 0, nil
	}
	if remaining := b.cap - len(b.buf); n > remaining {
		n = remaining
	}
	if n <= 0 {
		return 0, errors.New("buffer cap reached")
	}
	chunk := make([]byte, n)
	m, err := b.upstream.Read(chunk)
	if m > 0 {
		b.buf = append(b.buf, chunk[:m]...)
	}
	if err == io.EOF {
		b.eof = true
	}
	return m, err
}

func (b *bufferedBody) Len() int { return len(b.buf) }

// Read drains the buffered prefix first, then reads from upstream.
func (b *bufferedBody) Read(p []byte) (int, error) {
	if b.readPos < len(b.buf) {
		n := copy(p, b.buf[b.readPos:])
		b.readPos += n
		return n, nil
	}
	if b.closed || b.eof {
		return 0, io.EOF
	}
	return b.upstream.Read(p)
}

// Close closes the upstream body. Idempotent.
func (b *bufferedBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.upstream.Close()
}

// ── Apply: glue script + response together ─────────────────────────────────

// Apply runs the bail script against the streaming upstream response and
// returns a transformed *http.Response. Status code is always preserved.
// Behaviour by outcome (decided before headers go to the client):
//
//   - Bail (script returned string): close upstream, attach X-Bail-Reason
//     header, body = bytes buffered up to the bail point.
//   - Script error (script raised, timed out, or exhausted steps): attach
//     X-Bail-Script-Error header, body = buffered prefix + remaining
//     upstream streamed normally; script does not run again for this request.
//   - Cap reached without decision: release as-is, no headers added, script
//     no longer runs for this request.
//   - No bail, no error (script returned None on every chunk through EOF):
//     pass body through unchanged.
//
// chunkSize and releaseCap default to DefaultChunkBytes / DefaultReleaseCapBytes
// when zero is passed.
func Apply(ctx context.Context, script *BailScript, resp *http.Response, chunkSize, releaseCap int) *http.Response {
	if resp == nil || resp.Body == nil || script == nil {
		return resp
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkBytes
	}
	if releaseCap <= 0 {
		releaseCap = DefaultReleaseCapBytes
	}

	bb := newBufferedBody(resp.Body, releaseCap)
	headers := map[string][]string(resp.Header)

	// Initial call: headers only, empty buffer.
	reason, err := script.Call(ctx, resp.StatusCode, headers, bb.Peek)
	if err != nil {
		return scriptErroredResponse(resp, bb, err)
	}
	if reason != "" {
		_ = bb.Close()
		return bailResponse(resp, bb, reason)
	}

	// Stream-and-poll until bail / script error / cap / EOF.
	for {
		if bb.Len() >= releaseCap {
			break // cap reached without decision; release as-is
		}
		_, pullErr := bb.Pull(chunkSize)
		if pullErr == io.EOF {
			// Final call so script sees the complete body.
			reason, err = script.Call(ctx, resp.StatusCode, headers, bb.Peek)
			if err != nil {
				return scriptErroredResponse(resp, bb, err)
			}
			if reason != "" {
				_ = bb.Close()
				return bailResponse(resp, bb, reason)
			}
			break
		}
		if pullErr != nil {
			// Upstream error — return as-is; let copyResponse surface it.
			break
		}
		reason, err = script.Call(ctx, resp.StatusCode, headers, bb.Peek)
		if err != nil {
			return scriptErroredResponse(resp, bb, err)
		}
		if reason != "" {
			_ = bb.Close()
			return bailResponse(resp, bb, reason)
		}
	}

	// No bail, no error: passthrough. Re-attach wrapper so buffered prefix
	// is delivered before continuing from upstream.
	resp.Body = bb
	return resp
}

func bailResponse(orig *http.Response, bb *bufferedBody, reason string) *http.Response {
	out := cloneRespShallow(orig)
	out.Header = cloneHeadersWithoutEncoding(orig.Header)
	out.Header.Set(HeaderBailScriptOutput, reason)
	body := append([]byte(nil), bb.buf...)
	out.Body = io.NopCloser(bytesReader(body))
	out.ContentLength = int64(len(body))
	out.Header.Set("Content-Length", fmtInt(len(body)))
	return out
}

func scriptErroredResponse(orig *http.Response, bb *bufferedBody, err error) *http.Response {
	slog.Warn("bail script disabled for request after error", "err", err)
	// Body continues normally; just attach the error header. We keep the
	// wrapper as the body so the buffered prefix + remaining upstream
	// stream through to the client.
	orig.Header.Set(HeaderBailScriptError, truncateForHeader(err.Error()))
	orig.Body = bb
	return orig
}

// ── small helpers (kept here to avoid touching unrelated files) ────────────

func cloneRespShallow(r *http.Response) *http.Response {
	cp := *r
	return &cp
}

func cloneHeadersWithoutEncoding(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Content-Encoding") ||
			strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		out[k] = v
	}
	return out
}

func truncateForHeader(s string) string {
	const maxHeaderValue = 512
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > maxHeaderValue {
		s = s[:maxHeaderValue-1] + "…"
	}
	return s
}

func fmtInt(n int) string {
	// strconv.Itoa avoidance for the smallest possible imports footprint;
	// in practice this file already imports plenty. Keep helper for clarity.
	return fmt.Sprintf("%d", n)
}

// bytesReader is a single-allocation wrapper that lets the body be re-read
// as an io.Reader without dragging in bytes.Reader's seek surface.
type bytesReadCloser struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReadCloser { return &bytesReadCloser{data: data} }

func (b *bytesReadCloser) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *bytesReadCloser) Close() error { return nil }
