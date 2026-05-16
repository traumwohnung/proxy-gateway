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
	"context"
	"errors"
	"fmt"
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
