// Script registry — name → *Script lookup used by ParseUsername to resolve
// references in the username's `scripts` array, and by config loading to
// resolve a proxy_set's `default_scripts` list.
package main

// ScriptRegistry is the interface ParseUsername needs to dereference named
// script references inside a username payload. nil means "no registry; all
// references will fail to resolve".
type ScriptRegistry interface {
	Lookup(name string) (*Script, bool)
}

// scriptMap is the trivial map-backed implementation built from config.
type scriptMap map[string]*Script

func (m scriptMap) Lookup(name string) (*Script, bool) {
	s, ok := m[name]
	return s, ok
}
