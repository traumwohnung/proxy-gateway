// Package utils — Starlark-based MITM response filter.
//
// A response script is a short Starlark program that runs server-side on the
// proxy-gateway against each MITM'd response. It can inspect status/headers
// and a buffered prefix of the body, then decide one of:
//
//   - passthrough: let the response stream to the client unmodified
//   - abort:       close the upstream connection now; client sees 499 + reason
//   - extract:     close upstream after a sub-span; client receives only that slice
//
// The script must define a top-level function `on_response(r)`. The host
// invokes it once after upstream headers + an initial buffered prefix
// (default 8 KiB) are available. Within the script the `r` object exposes:
//
//	r.status         (int)            upstream status code
//	r.headers        (dict)           lower-cased response headers
//	r.peek(n=None)   -> bytes         bytes from start of buffer (n=None = all)
//	r.request_more(n)-> bool          pull at least n more bytes from upstream;
//	                                  False on EOF
//	r.scan(needle)   -> int           find `needle` in buffer (-1 if not found)
//	r.abort(reason)  -> None          close upstream, client sees 499
//	r.extract(s, e)  -> None          close upstream, client receives buffer[s:e]
//	r.passthrough()  -> None          default — stream rest of body unmodified
//
// Sandbox: Starlark is hermetic by default (no I/O, no clock, no imports).
// On top we enforce a per-call wall-clock budget and a step budget; either
// limit being hit logs and falls back to passthrough.
package utils

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// Limits. See plan / README for rationale.
const (
	// MaxScriptSize is the maximum size of an inline Starlark source string.
	MaxScriptSize = 32 * 1024

	// MaxExecSteps caps each on_response call's Starlark instructions.
	MaxExecSteps = 100_000

	// MaxWallClock caps wall-clock time of a single on_response call.
	MaxWallClock = 50 * time.Millisecond

	// DefaultInitialBufBytes is how many bytes the gateway buffers from
	// upstream before calling on_response.
	DefaultInitialBufBytes = 8 * 1024

	// DefaultMaxBufBytes is the cumulative cap on bytes a script can pull
	// via request_more. Configurable per proxy_set.
	DefaultMaxBufBytes = 1024 * 1024
)

// Action is the decision returned by on_response.
type Action int

const (
	// ActionPassthrough lets the response stream to the client unmodified.
	ActionPassthrough Action = iota
	// ActionAbort closes the upstream connection; client sees 499 + reason.
	ActionAbort
	// ActionExtract closes upstream after end-marker reached; client
	// receives buffer[ExtractStart:ExtractEnd] as a normal 200.
	ActionExtract
)

// Decision is what the script chose, after on_response returns.
type Decision struct {
	Action       Action
	AbortReason  string
	ExtractStart int
	ExtractEnd   int
}

// PeekFunc returns up to n bytes from the start of the currently buffered
// upstream prefix. If n < 0, returns the entire buffer.
type PeekFunc func(n int) []byte

// RequestMoreFunc asks the gateway to read at least n more bytes from
// upstream and append them to the buffer. Returns the new buffer size, or
// io.EOF when upstream is exhausted before n more arrived.
type RequestMoreFunc func(n int) (int, error)

// Script is a compiled, ready-to-run response filter.
type Script struct {
	name       string
	onResponse starlark.Value
}

// Compile parses and validates a Starlark source. The returned *Script can
// be reused across many Run calls (each call gets its own thread).
//
// name is used in error messages and stack traces.
func Compile(name, src string) (*Script, error) {
	if len(src) > MaxScriptSize {
		return nil, fmt.Errorf("response script %q: %d bytes exceeds limit %d", name, len(src), MaxScriptSize)
	}
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("response script %q: empty source", name)
	}

	opts := &syntax.FileOptions{}
	thread := &starlark.Thread{Name: "init:" + name}
	thread.SetMaxExecutionSteps(MaxExecSteps)

	globals, err := starlark.ExecFileOptions(opts, thread, name, src, nil)
	if err != nil {
		return nil, fmt.Errorf("response script %q: %w", name, err)
	}

	fn, ok := globals["on_response"]
	if !ok {
		return nil, fmt.Errorf("response script %q: missing on_response(r) function", name)
	}
	if _, ok := fn.(starlark.Callable); !ok {
		return nil, fmt.Errorf("response script %q: on_response is not callable", name)
	}
	globals.Freeze()
	return &Script{name: name, onResponse: fn}, nil
}

// Run invokes on_response with a fresh response handle. The script is given
// peek and request_more callbacks bound to the live upstream body.
//
// On timeout, step exhaustion, or any Starlark error the returned Decision
// is ActionPassthrough and a non-nil error is returned for logging. Callers
// should always honour the Decision regardless of err.
func (s *Script) Run(
	ctx context.Context,
	status int,
	headers map[string][]string,
	peek PeekFunc,
	requestMore RequestMoreFunc,
) (Decision, error) {
	thread := &starlark.Thread{Name: "on_response:" + s.name}
	thread.SetMaxExecutionSteps(MaxExecSteps)

	// Watchdog: wall-clock cap or external cancel.
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

	handle := &responseHandle{
		status:      status,
		headers:     headers,
		peek:        peek,
		requestMore: requestMore,
	}

	if _, err := starlark.Call(thread, s.onResponse, starlark.Tuple{handle}, nil); err != nil {
		return Decision{Action: ActionPassthrough}, fmt.Errorf("response script %q runtime error: %w", s.name, err)
	}

	if !handle.decisionSet {
		// Script returned without calling abort/extract/passthrough — treat
		// as implicit passthrough.
		return Decision{Action: ActionPassthrough}, nil
	}
	return handle.decision, nil
}

// ── responseHandle: the `r` value exposed to Starlark ──────────────────────

type responseHandle struct {
	status      int
	headers     map[string][]string
	peek        PeekFunc
	requestMore RequestMoreFunc

	decision    Decision
	decisionSet bool
	frozen      bool
}

var _ starlark.HasAttrs = (*responseHandle)(nil)

func (r *responseHandle) String() string        { return "<Response>" }
func (r *responseHandle) Type() string          { return "Response" }
func (r *responseHandle) Freeze()               { r.frozen = true }
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
	case "request_more":
		return starlark.NewBuiltin("request_more", r.builtinRequestMore), nil
	case "scan":
		return starlark.NewBuiltin("scan", r.builtinScan), nil
	case "abort":
		return starlark.NewBuiltin("abort", r.builtinAbort), nil
	case "extract":
		return starlark.NewBuiltin("extract", r.builtinExtract), nil
	case "passthrough":
		return starlark.NewBuiltin("passthrough", r.builtinPassthrough), nil
	}
	return nil, nil // not found; Starlark surfaces AttributeError
}

func (r *responseHandle) AttrNames() []string {
	return []string{
		"abort", "extract", "headers", "passthrough",
		"peek", "request_more", "scan", "status",
	}
}

func (r *responseHandle) headersDict() *starlark.Dict {
	d := starlark.NewDict(len(r.headers))
	for k, vs := range r.headers {
		l := starlark.NewList(make([]starlark.Value, 0, len(vs)))
		for _, v := range vs {
			_ = l.Append(starlark.String(v))
		}
		// Lower-case keys; ignore SetKey error (keys are strings, always hashable).
		_ = d.SetKey(starlark.String(strings.ToLower(k)), l)
	}
	d.Freeze()
	return d
}

// ── builtins ───────────────────────────────────────────────────────────────

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

func (r *responseHandle) builtinRequestMore(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var n int
	if err := starlark.UnpackArgs("request_more", args, kwargs, "n", &n); err != nil {
		return nil, err
	}
	if n < 0 {
		return nil, fmt.Errorf("request_more: n must be >= 0")
	}
	_, err := r.requestMore(n)
	if err != nil {
		return starlark.False, nil
	}
	return starlark.True, nil
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

func (r *responseHandle) builtinAbort(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var reason string
	if err := starlark.UnpackArgs("abort", args, kwargs, "reason?", &reason); err != nil {
		return nil, err
	}
	if err := r.setDecision(Decision{Action: ActionAbort, AbortReason: reason}); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (r *responseHandle) builtinExtract(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var start, end int
	if err := starlark.UnpackArgs("extract", args, kwargs, "start", &start, "end", &end); err != nil {
		return nil, err
	}
	if start < 0 || end < start {
		return nil, fmt.Errorf("extract: invalid range [%d:%d]", start, end)
	}
	if err := r.setDecision(Decision{Action: ActionExtract, ExtractStart: start, ExtractEnd: end}); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (r *responseHandle) builtinPassthrough(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("passthrough", args, kwargs); err != nil {
		return nil, err
	}
	if err := r.setDecision(Decision{Action: ActionPassthrough}); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (r *responseHandle) setDecision(d Decision) error {
	if r.decisionSet {
		return fmt.Errorf("response decision already set to %s; cannot also call %s",
			actionName(r.decision.Action), actionName(d.Action))
	}
	r.decision = d
	r.decisionSet = true
	return nil
}

func actionName(a Action) string {
	switch a {
	case ActionAbort:
		return "abort"
	case ActionExtract:
		return "extract"
	default:
		return "passthrough"
	}
}

// ── bufferedBody: io.ReadCloser wrapper with Peek + RequestMore ────────────

// bufferedBody wraps an io.ReadCloser and lets a Starlark script peek at the
// already-buffered prefix and pull more bytes from upstream on demand. After
// the script returns passthrough, the wrapper acts as a normal io.ReadCloser
// that drains the buffered prefix first then continues from upstream.
type bufferedBody struct {
	upstream io.ReadCloser
	buf      []byte // bytes already pulled from upstream
	cap      int    // hard cap on total bytes we will pull
	readPos  int    // for post-script Read draining of buf
	closed   bool
	eof      bool
}

func newBufferedBody(upstream io.ReadCloser, cap int) *bufferedBody {
	if cap <= 0 {
		cap = DefaultMaxBufBytes
	}
	return &bufferedBody{upstream: upstream, cap: cap}
}

// Peek returns up to n bytes from the start of the buffer. n < 0 returns all.
func (b *bufferedBody) Peek(n int) []byte {
	if n < 0 || n >= len(b.buf) {
		return b.buf
	}
	return b.buf[:n]
}

// RequestMore pulls at least n more bytes from upstream into the buffer.
// Returns the new buffer length, or io.EOF if upstream ended before n more
// arrived. Subsequent calls after EOF immediately return EOF.
func (b *bufferedBody) RequestMore(n int) (int, error) {
	if b.eof {
		return len(b.buf), io.EOF
	}
	if n <= 0 {
		return len(b.buf), nil
	}
	if remaining := b.cap - len(b.buf); n > remaining {
		n = remaining
	}
	if n <= 0 {
		return len(b.buf), errors.New("buffer cap reached")
	}

	chunk := make([]byte, n)
	got := 0
	for got < n {
		m, err := b.upstream.Read(chunk[got:])
		if m > 0 {
			got += m
		}
		if err == io.EOF {
			b.buf = append(b.buf, chunk[:got]...)
			b.eof = true
			return len(b.buf), io.EOF
		}
		if err != nil {
			b.buf = append(b.buf, chunk[:got]...)
			return len(b.buf), err
		}
		if m == 0 {
			break // defensive: shouldn't happen but avoid infinite loop
		}
	}
	b.buf = append(b.buf, chunk[:got]...)
	return len(b.buf), nil
}

// Read drains the buffered prefix first, then reads from upstream directly.
// Used by copyResponse after a passthrough decision.
func (b *bufferedBody) Read(p []byte) (int, error) {
	if b.readPos < len(b.buf) {
		n := copy(p, b.buf[b.readPos:])
		b.readPos += n
		return n, nil
	}
	if b.closed {
		return 0, io.EOF
	}
	if b.eof {
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

// ── ApplyScript: glue the engine to an *http.Response ──────────────────────

// ApplyScript wraps an upstream response with the given script. It pre-buffers
// an initial prefix, runs on_response, and dispatches one of:
//
//   - passthrough: returns the original response with a wrapper body that
//     continues to stream from upstream (existing prefix delivered first).
//   - abort: closes upstream, returns a synthetic 499 with a small JSON body
//     {"aborted":true,"reason":"…"}.
//   - extract: continues reading until ExtractEnd is buffered, closes
//     upstream, returns a response of the upstream status with body limited
//     to buffer[ExtractStart:ExtractEnd]. Content-Length is rewritten and
//     Content-Encoding / Transfer-Encoding are stripped since the body has
//     been re-materialised as a plain byte slice.
//
// Initial buffer size and cumulative pull cap default to
// DefaultInitialBufBytes / DefaultMaxBufBytes; pass 0 to use those.
func ApplyScript(ctx context.Context, script *Script, resp *http.Response, initialBuf, maxBuf int) *http.Response {
	if resp == nil || resp.Body == nil || script == nil {
		return resp
	}
	if initialBuf <= 0 {
		initialBuf = DefaultInitialBufBytes
	}
	if maxBuf <= 0 {
		maxBuf = DefaultMaxBufBytes
	}

	bb := newBufferedBody(resp.Body, maxBuf)

	// Pre-buffer; ignore EOF since the script can still decide on a short body.
	if _, err := bb.RequestMore(initialBuf); err != nil && err != io.EOF {
		slog.Warn("response script: pre-buffer error", "err", err)
	}

	decision, runErr := script.Run(ctx, resp.StatusCode, map[string][]string(resp.Header), bb.Peek, bb.RequestMore)
	if runErr != nil {
		slog.Warn("response script: runtime error, falling back to passthrough",
			"script", script.name, "err", runErr)
	}

	switch decision.Action {
	case ActionAbort:
		_ = bb.Close()
		return abortResponse(resp, decision.AbortReason)
	case ActionExtract:
		// Ensure we have enough buffered for the requested span.
		if decision.ExtractEnd > len(bb.buf) {
			need := decision.ExtractEnd - len(bb.buf)
			_, _ = bb.RequestMore(need)
		}
		end := decision.ExtractEnd
		if end > len(bb.buf) {
			end = len(bb.buf)
		}
		start := decision.ExtractStart
		if start > end {
			start = end
		}
		// Defensive copy so closing the upstream doesn't invalidate the slice.
		slice := append([]byte(nil), bb.buf[start:end]...)
		_ = bb.Close()
		return extractResponse(resp, slice)
	default:
		// Passthrough: re-attach the wrapper as the body. copyResponse will
		// drain the prefix then continue from upstream.
		resp.Body = bb
		return resp
	}
}

func abortResponse(orig *http.Response, reason string) *http.Response {
	body := fmt.Sprintf(`{"aborted":true,"reason":%s}`, strconv.Quote(reason))
	h := http.Header{
		"Content-Type":   {"application/json"},
		"Content-Length": {strconv.Itoa(len(body))},
	}
	if reason != "" {
		h.Set("X-Gateway-Abort", reason)
	}
	return &http.Response{
		StatusCode:    499, // 499 Client Closed Request (nginx convention, not std lib)
		Status:        "499 Client Closed Request",
		Proto:         orig.Proto,
		ProtoMajor:    orig.ProtoMajor,
		ProtoMinor:    orig.ProtoMinor,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       orig.Request,
	}
}

func extractResponse(orig *http.Response, slice []byte) *http.Response {
	h := http.Header{}
	for k, v := range orig.Header {
		// Drop encodings — the body is now a plain byte slice.
		if strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Content-Encoding") ||
			strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		h[k] = v
	}
	h.Set("Content-Length", strconv.Itoa(len(slice)))
	h.Set("X-Gateway-Extract", "ok")
	return &http.Response{
		StatusCode:    orig.StatusCode,
		Status:        orig.Status,
		Proto:         orig.Proto,
		ProtoMajor:    orig.ProtoMajor,
		ProtoMinor:    orig.ProtoMinor,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(slice)),
		ContentLength: int64(len(slice)),
		Request:       orig.Request,
	}
}
