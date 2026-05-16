// Shared Starlark engine used by all script-driven hooks (currently only
// BailScript; request/response modification scripts will plug in here when
// they exist).
//
// What lives here:
//   - Compile-time limits + sandbox setup
//   - The set of predeclared host builtins (e.g. `regex(...)`) exposed to
//     every script type at script-init
//   - The per-call thread + watchdog + step-budget plumbing
//
// What does NOT live here:
//   - The script-type-specific entry-point name (e.g. "bail")
//   - The Starlark value exposed to the user's function as `r`
//   - How the script's return value is interpreted
//   - How its decision drives the gateway pipeline
//
// Each script type (bail today; request_modify / response_modify in the
// future) wraps the internal `script` handle and provides those bits.
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

// Shared sandbox limits.
const (
	// MaxScriptSize is the maximum size of an inline Starlark source string.
	MaxScriptSize = 32 * 1024

	// MaxExecSteps caps each script entry-point call's Starlark instructions.
	MaxExecSteps = 100_000

	// MaxWallClock caps wall-clock time of a single script entry-point call.
	MaxWallClock = 50 * time.Millisecond
)

// script is the compiled representation shared by every script type. The
// entry-point function is resolved + frozen at compile time; subsequent
// runs just look up its value and call it.
type script struct {
	name       string
	entryPoint string         // e.g. "bail"
	fn         starlark.Value // resolved + frozen entry function
}

// compileScript parses src, runs its module-level init (which freezes the
// globals — so e.g. `PAT = regex(...)` evaluates here exactly once), and
// returns a handle pointing at the named entry function.
//
// entryPoint must name a top-level callable produced by the script's init.
func compileScript(name, src, entryPoint string) (*script, error) {
	if len(src) > MaxScriptSize {
		return nil, fmt.Errorf("script %q: %d bytes exceeds limit %d", name, len(src), MaxScriptSize)
	}
	if strings.TrimSpace(src) == "" {
		return nil, fmt.Errorf("script %q: empty source", name)
	}

	opts := &syntax.FileOptions{}
	thread := &starlark.Thread{Name: "init:" + name}
	thread.SetMaxExecutionSteps(MaxExecSteps)

	globals, err := starlark.ExecFileOptions(opts, thread, name, src, predeclared())
	if err != nil {
		return nil, fmt.Errorf("script %q: %w", name, err)
	}

	fn, ok := globals[entryPoint]
	if !ok {
		return nil, fmt.Errorf("script %q: missing %s() function", name, entryPoint)
	}
	if _, ok := fn.(starlark.Callable); !ok {
		return nil, fmt.Errorf("script %q: %s is not callable", name, entryPoint)
	}
	globals.Freeze()
	return &script{name: name, entryPoint: entryPoint, fn: fn}, nil
}

// runScript invokes the entry function with a single argument and the standard
// sandbox guards (step cap + wall-clock watchdog + context cancellation).
// The returned starlark.Value is whatever the user's function returned; the
// caller is responsible for interpreting it.
func runScript(ctx context.Context, s *script, arg starlark.Value) (starlark.Value, error) {
	thread := &starlark.Thread{Name: s.entryPoint + ":" + s.name}
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

	ret, err := starlark.Call(thread, s.fn, starlark.Tuple{arg}, nil)
	if err != nil {
		return nil, fmt.Errorf("script %q runtime error: %w", s.name, err)
	}
	return ret, nil
}

// predeclared returns the set of host builtins available at script-init time.
// New cross-script-type builtins land here. Per-script-type values (e.g. `r`)
// are passed to the entry function as arguments, not predeclared.
func predeclared() starlark.StringDict {
	return starlark.StringDict{
		"regex": starlark.NewBuiltin("regex", regexBuiltin),
	}
}
