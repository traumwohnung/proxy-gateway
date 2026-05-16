// Generic Starlark "namespace" value — a frozen attribute bag of named
// builtins. Used by the host to expose grouped capabilities to scripts
// (Regex.new, Json.encode, Base64.decode, …) so the top-level global
// surface stays small and self-describing.
package main

import (
	"fmt"
	"sort"

	"go.starlark.net/starlark"
)

type namespace struct {
	name  string
	funcs map[string]*starlark.Builtin
	names []string // cached sorted name list
}

func newNamespace(name string, funcs map[string]*starlark.Builtin) *namespace {
	names := make([]string, 0, len(funcs))
	for k := range funcs {
		names = append(names, k)
	}
	sort.Strings(names)
	return &namespace{name: name, funcs: funcs, names: names}
}

var _ starlark.HasAttrs = (*namespace)(nil)

func (n *namespace) String() string        { return n.name }
func (n *namespace) Type() string          { return "namespace" }
func (n *namespace) Freeze()               {}
func (n *namespace) Truth() starlark.Bool  { return starlark.True }
func (n *namespace) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable type: %s", n.name) }

func (n *namespace) Attr(name string) (starlark.Value, error) {
	if f, ok := n.funcs[name]; ok {
		return f, nil
	}
	return nil, nil
}

func (n *namespace) AttrNames() []string { return n.names }
