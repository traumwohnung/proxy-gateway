// regex(pattern) host builtin — available to every script type during init,
// so patterns can be compiled once into frozen globals and reused on each
// entry-function invocation without paying compile cost per call.
//
// Script usage:
//
//	DD = regex(rb'geo\.captcha-delivery\.com')
//
//	def bail(r):
//	    if DD.test(r.peek()):
//	        return 'datadome'
//
// Backed by Go's regexp (RE2 syntax): no backreferences, no lookarounds, but
// linear-time guaranteed — safe to expose to user code.
package main

import (
	"errors"
	"fmt"
	"regexp"

	"go.starlark.net/starlark"
)

const (
	// MaxRegexPatternSize caps a single regex pattern source string.
	MaxRegexPatternSize = 4 * 1024
)

func regexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pat starlark.Value
	if err := starlark.UnpackArgs("regex", args, kwargs, "pattern", &pat); err != nil {
		return nil, err
	}
	var src string
	switch v := pat.(type) {
	case starlark.Bytes:
		src = string(v)
	case starlark.String:
		src = string(v)
	default:
		return nil, fmt.Errorf("regex: pattern must be bytes or string, got %s", pat.Type())
	}
	if len(src) > MaxRegexPatternSize {
		return nil, fmt.Errorf("regex: pattern %d bytes exceeds limit %d", len(src), MaxRegexPatternSize)
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, fmt.Errorf("regex: compile %q: %w", truncateForHeader(src), err)
	}
	return &regexValue{re: re, src: src}, nil
}

// regexValue is the Starlark value returned by regex(). Methods: test,
// search, find, find_all. All inputs accept bytes or string; outputs are
// bytes (Bytes / list[Bytes]) or int.
type regexValue struct {
	re  *regexp.Regexp
	src string
}

var _ starlark.HasAttrs = (*regexValue)(nil)

func (r *regexValue) String() string        { return fmt.Sprintf("regex(%q)", r.src) }
func (r *regexValue) Type() string          { return "regex" }
func (r *regexValue) Freeze()               {}
func (r *regexValue) Truth() starlark.Bool  { return starlark.True }
func (r *regexValue) Hash() (uint32, error) { return 0, errors.New("unhashable type: regex") }

func (r *regexValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "test":
		return starlark.NewBuiltin("test", r.test), nil
	case "search":
		return starlark.NewBuiltin("search", r.search), nil
	case "find":
		return starlark.NewBuiltin("find", r.find), nil
	case "find_all":
		return starlark.NewBuiltin("find_all", r.findAll), nil
	}
	return nil, nil
}

func (r *regexValue) AttrNames() []string {
	return []string{"find", "find_all", "search", "test"}
}

// unpackHaystackAndStart extracts a bytes haystack plus an optional
// non-negative start offset. Both bytes and string are accepted.
func unpackHaystackAndStart(fnName string, args starlark.Tuple, kwargs []starlark.Tuple, allowStart bool) ([]byte, int, error) {
	var hay starlark.Value
	var start int
	if allowStart {
		if err := starlark.UnpackArgs(fnName, args, kwargs, "haystack", &hay, "start?", &start); err != nil {
			return nil, 0, err
		}
	} else {
		if err := starlark.UnpackArgs(fnName, args, kwargs, "haystack", &hay); err != nil {
			return nil, 0, err
		}
	}
	var data []byte
	switch v := hay.(type) {
	case starlark.Bytes:
		data = []byte(v)
	case starlark.String:
		data = []byte(string(v))
	default:
		return nil, 0, fmt.Errorf("%s: haystack must be bytes or string, got %s", fnName, hay.Type())
	}
	if start < 0 {
		return nil, 0, fmt.Errorf("%s: start must be >= 0", fnName)
	}
	if start > len(data) {
		start = len(data)
	}
	return data, start, nil
}

func (r *regexValue) test(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, _, err := unpackHaystackAndStart("test", args, kwargs, false)
	if err != nil {
		return nil, err
	}
	return starlark.Bool(r.re.Match(data)), nil
}

func (r *regexValue) search(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, start, err := unpackHaystackAndStart("search", args, kwargs, true)
	if err != nil {
		return nil, err
	}
	loc := r.re.FindIndex(data[start:])
	if loc == nil {
		return starlark.MakeInt(-1), nil
	}
	return starlark.MakeInt(start + loc[0]), nil
}

func (r *regexValue) find(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, start, err := unpackHaystackAndStart("find", args, kwargs, true)
	if err != nil {
		return nil, err
	}
	m := r.re.Find(data[start:])
	if m == nil {
		return starlark.None, nil
	}
	return starlark.Bytes(m), nil
}

func (r *regexValue) findAll(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	data, _, err := unpackHaystackAndStart("find_all", args, kwargs, false)
	if err != nil {
		return nil, err
	}
	all := r.re.FindAll(data, -1)
	out := starlark.NewList(make([]starlark.Value, 0, len(all)))
	for _, m := range all {
		_ = out.Append(starlark.Bytes(m))
	}
	return out, nil
}
