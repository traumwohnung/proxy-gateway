// Script — compiled Starlark module with zero or more known entry points.
//
// Today the only recognised entry is `bail(r)`. Future phases (e.g.
// request_modify, response_modify) will land here as additional optional
// entry points that scripts may define independently. Compile errors if
// the source defines no recognised entry point at all (catches typos
// like `def ball(r): …`).
//
// A request's script chain is an ordered slice of *Script. Each phase
// dispatches across the chain in order. The bail phase short-circuits on
// the first script that bails; future modify phases are expected to run
// every script in order regardless.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.starlark.net/starlark"
)

// Script is a compiled Starlark module that may define any combination of
// the recognised entry points. Inspect HasBail() etc. before dispatching.
type Script struct {
	name string
	bail starlark.Value // nil if not defined
}

// recognisedEntryPoints lists every entry function name the gateway knows
// about. Adding a new function type (e.g. "response_modify") means: add it
// here, add a typed field on Script, and add a Call* method.
var recognisedEntryPoints = []string{"bail"}

// Compile parses and validates a script source. At least one recognised
// entry point must be defined; otherwise the script can't do anything and
// is rejected with a hopefully-useful error.
func Compile(name, src string) (*Script, error) {
	inner, err := compileScript(name, src, "" /* no required entry */)
	if err != nil {
		return nil, err
	}
	s := &Script{name: name}
	for _, ep := range recognisedEntryPoints {
		fn, ok := inner.globals[ep]
		if !ok {
			continue
		}
		if _, ok := fn.(starlark.Callable); !ok {
			return nil, fmt.Errorf("script %q: %s is not callable", name, ep)
		}
		switch ep {
		case "bail":
			s.bail = fn
		}
	}
	if s.empty() {
		return nil, fmt.Errorf("script %q: defines no recognised entry point (expected one of %v)",
			name, recognisedEntryPoints)
	}
	return s, nil
}

func (s *Script) empty() bool {
	return s.bail == nil
}

// HasBail reports whether the script defines a bail(r) function.
func (s *Script) HasBail() bool { return s != nil && s.bail != nil }

// CallBail invokes bail() once with a fresh response handle. Outcomes:
//
//   - reason != "":  bail with that reason.
//   - err != nil:    script raised / timed out / blew the step budget.
//   - reason == "" && err == nil: continue.
//
// Any non-None / non-string return is treated as continue plus a warning log.
func (s *Script) CallBail(ctx context.Context, status int, headers map[string][]string, peek PeekFunc) (reason string, err error) {
	if s == nil || s.bail == nil {
		return "", nil
	}
	handle := &responseHandle{status: status, headers: headers, peek: peek}
	ret, callErr := runCallable(ctx, s.name, "bail", s.bail, handle)
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
			"script", s.name, "type", ret.Type())
		return "", nil
	}
}

// ── responseHandle: the `r` value exposed to bail() ────────────────────────

// PeekFunc returns up to n bytes from the start of the currently buffered
// upstream prefix. If n < 0, returns the entire buffer.
type PeekFunc func(n int) []byte

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
