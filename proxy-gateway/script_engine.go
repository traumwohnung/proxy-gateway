// Shared Starlark engine used by all script-driven hooks.
//
// What lives here:
//   - Compile-time limits + sandbox setup
//   - The set of predeclared host builtins (e.g. `regex(...)`) exposed to
//     every script at script-init
//   - compileScript: parse + run init, return frozen globals
//   - runCallable: per-call thread + watchdog + step-budget plumbing
//
// What does NOT live here:
//   - Which entry-point names the script type recognises
//   - The Starlark value exposed to the user's function as `r`
//   - How return values are interpreted
//   - How decisions drive the gateway pipeline
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

	// MaxExecSteps caps each entry-point call's Starlark instructions.
	MaxExecSteps = 100_000

	// MaxWallClock caps wall-clock time of a single entry-point call.
	MaxWallClock = 50 * time.Millisecond
)

// compiledModule is the raw output of compileScript: name + frozen
// module-level globals. Script-type wrappers (currently *Script in
// bail_script.go) cherry-pick the entry points they recognise.
type compiledModule struct {
	name    string
	globals starlark.StringDict
}

// compileScript parses src and runs its module-level init (so module-level
// expressions like `PAT = regex(...)` evaluate exactly once). Returns the
// frozen globals dict; callers resolve the entry points they care about.
//
// If requiredEntry != "", compileScript additionally enforces that the
// named function exists and is callable. Pass "" to defer entry-point
// resolution to the caller (the common case now that scripts may define
// any combination of recognised entries).
func compileScript(name, src, requiredEntry string) (*compiledModule, error) {
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
	if requiredEntry != "" {
		fn, ok := globals[requiredEntry]
		if !ok {
			return nil, fmt.Errorf("script %q: missing %s() function", name, requiredEntry)
		}
		if _, ok := fn.(starlark.Callable); !ok {
			return nil, fmt.Errorf("script %q: %s is not callable", name, requiredEntry)
		}
	}
	globals.Freeze()
	return &compiledModule{name: name, globals: globals}, nil
}

// runCallable invokes a starlark callable with a single argument and the
// standard sandbox guards (step cap + wall-clock watchdog + context
// cancellation). entryName is used for error messages and the thread name.
func runCallable(ctx context.Context, scriptName, entryName string, fn starlark.Value, arg starlark.Value) (starlark.Value, error) {
	thread := &starlark.Thread{Name: entryName + ":" + scriptName}
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

	ret, err := starlark.Call(thread, fn, starlark.Tuple{arg}, nil)
	if err != nil {
		return nil, fmt.Errorf("script %q runtime error: %w", scriptName, err)
	}
	return ret, nil
}

// predeclared returns the set of host builtins available at script-init time.
// New cross-script-type builtins land here.
func predeclared() starlark.StringDict {
	return starlark.StringDict{
		"regex": starlark.NewBuiltin("regex", regexBuiltin),
	}
}
