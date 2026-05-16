// Bail script — first concrete script type built on script_engine.
//
// A bail script is a short Starlark program that runs server-side on each
// MITM'd response. It cannot modify status code, headers, or body — its
// only output is a decision: "should the gateway close the upstream
// connection now?". See BAIL_SCRIPTS.md for the full guide.
//
// The script defines a top-level `bail(r)` function returning:
//
//   - None / no return: continue (called again after next body chunk)
//   - str:              bail with that string as reason
//   - any raised err:   disable for the rest of this request
//
// `r` exposes status, headers (lower-cased dict), peek(n=None), scan(needle).
//
// Future scripts (request_modify, response_modify) will plug into
// script_engine the same way, with their own entry-point names and handle
// types — the engine layer itself is type-agnostic.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.starlark.net/starlark"
)

// BailScript is a compiled, ready-to-run bail filter.
type BailScript struct {
	inner *script
}

// Compile parses and validates a bail-script source. Returned *BailScript can
// be reused across many invocations.
func Compile(name, src string) (*BailScript, error) {
	s, err := compileScript(name, src, "bail")
	if err != nil {
		return nil, fmt.Errorf("bail %w", err)
	}
	return &BailScript{inner: s}, nil
}

// Call invokes bail() once with the given response handle. Three outcomes:
//
//   - reason != "":  script returned a non-empty string → caller should bail.
//   - err != nil:    script raised / timed out / blew the step budget.
//     Caller should disable the script for the rest of the request.
//   - reason == "" && err == nil: continue.
//
// Any non-None / non-string return value is treated as continue plus a
// warning log — scripts should always return None or string.
func (s *BailScript) Call(ctx context.Context, status int, headers map[string][]string, peek PeekFunc) (reason string, err error) {
	handle := &responseHandle{status: status, headers: headers, peek: peek}
	ret, callErr := runScript(ctx, s.inner, handle)
	if callErr != nil {
		return "", callErr
	}
	switch v := ret.(type) {
	case starlark.NoneType:
		return "", nil
	case starlark.String:
		return string(v), nil
	default:
		slog.Warn("bail script returned unexpected type, treating as continue",
			"script", s.inner.name, "type", ret.Type())
		return "", nil
	}
}

// PeekFunc returns up to n bytes from the start of the currently buffered
// upstream prefix. If n < 0, returns the entire buffer.
type PeekFunc func(n int) []byte

// ── responseHandle: the `r` value exposed to bail() ────────────────────────

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
