// Host builtins exposed to every script at init time, alongside `regex(...)`
// in script_regex.go. Available via the predeclared() globals dict.
//
//   json_decode(input)         -> None | bool | int | float | str | list | dict
//   json_encode(value)         -> bytes
//   base64_decode(input)       -> bytes (None on parse error)
//   base64_encode(input)       -> str
//   url_decode(input)          -> str   (None on parse error)
//   url_encode(input)          -> str
//   xpath(expression)          -> xpath value with .query(html) -> list[bytes]
//
// All accept both bytes and str input where it makes sense. Decoders return
// None rather than raise on malformed input — keeps scripts tolerant of
// partial or weird responses without an explicit try/except (Starlark has
// no try/except).
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xpath"
	"go.starlark.net/starlark"
)

// ── json_decode / json_encode ─────────────────────────────────────────────

func jsonDecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("json_decode", args, kwargs, "input", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("json_decode", input)
	if err != nil {
		return nil, err
	}
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return starlark.None, nil // tolerant: caller treats None as "no data"
	}
	return goToStarlark(parsed)
}

func jsonEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("json_encode", args, kwargs, "value", &input); err != nil {
		return nil, err
	}
	g, err := starlarkToGo(input)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("json_encode: %w", err)
	}
	return starlark.Bytes(out), nil
}

// goToStarlark converts a JSON-unmarshalled value tree into Starlark values.
// JSON has no integer type; we promote whole-number floats to ints since
// that's almost always what scripts want.
func goToStarlark(v any) (starlark.Value, error) {
	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(x), nil
	case float64:
		if x == float64(int64(x)) {
			return starlark.MakeInt64(int64(x)), nil
		}
		return starlark.Float(x), nil
	case string:
		return starlark.String(x), nil
	case []any:
		list := starlark.NewList(make([]starlark.Value, 0, len(x)))
		for _, item := range x {
			sv, err := goToStarlark(item)
			if err != nil {
				return nil, err
			}
			_ = list.Append(sv)
		}
		return list, nil
	case map[string]any:
		d := starlark.NewDict(len(x))
		for k, vv := range x {
			sv, err := goToStarlark(vv)
			if err != nil {
				return nil, err
			}
			_ = d.SetKey(starlark.String(k), sv)
		}
		return d, nil
	}
	return nil, fmt.Errorf("json_decode: unsupported value type %T", v)
}

// starlarkToGo converts a Starlark value tree back into JSON-encodable Go.
func starlarkToGo(v starlark.Value) (any, error) {
	switch x := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(x), nil
	case starlark.Int:
		if i, ok := x.Int64(); ok {
			return i, nil
		}
		// big int — encode as string fallback
		return x.String(), nil
	case starlark.Float:
		return float64(x), nil
	case starlark.String:
		return string(x), nil
	case starlark.Bytes:
		return string(x), nil // JSON has no bytes; encode as string
	case *starlark.List:
		out := make([]any, 0, x.Len())
		it := x.Iterate()
		defer it.Done()
		var item starlark.Value
		for it.Next(&item) {
			g, err := starlarkToGo(item)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	case *starlark.Dict:
		out := make(map[string]any, x.Len())
		for _, k := range x.Keys() {
			ks, ok := k.(starlark.String)
			if !ok {
				return nil, fmt.Errorf("json_encode: dict keys must be strings, got %s", k.Type())
			}
			val, _, _ := x.Get(k)
			g, err := starlarkToGo(val)
			if err != nil {
				return nil, err
			}
			out[string(ks)] = g
		}
		return out, nil
	case starlark.Tuple:
		out := make([]any, 0, len(x))
		for _, item := range x {
			g, err := starlarkToGo(item)
			if err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, nil
	}
	return nil, fmt.Errorf("json_encode: unsupported type %s", v.Type())
}

// ── base64_decode / base64_encode ────────────────────────────────────────

func base64DecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("base64_decode", args, kwargs, "input", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("base64_decode", input)
	if err != nil {
		return nil, err
	}
	// Try standard then URL-safe; both with and without padding.
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, derr := enc.DecodeString(string(data)); derr == nil {
			return starlark.Bytes(decoded), nil
		}
	}
	return starlark.None, nil
}

func base64EncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("base64_encode", args, kwargs, "input", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("base64_encode", input)
	if err != nil {
		return nil, err
	}
	return starlark.String(base64.StdEncoding.EncodeToString(data)), nil
}

// ── url_decode / url_encode ──────────────────────────────────────────────

func urlDecodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("url_decode", args, kwargs, "input", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("url_decode", input)
	if err != nil {
		return nil, err
	}
	decoded, derr := url.QueryUnescape(string(data))
	if derr != nil {
		return starlark.None, nil
	}
	return starlark.String(decoded), nil
}

func urlEncodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("url_encode", args, kwargs, "input", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("url_encode", input)
	if err != nil {
		return nil, err
	}
	return starlark.String(url.QueryEscape(string(data))), nil
}

// ── xpath(expression) → xpathValue ────────────────────────────────────────

// MaxXPathExprSize caps a single XPath expression source string.
const MaxXPathExprSize = 2048

func xpathBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var expr string
	if err := starlark.UnpackArgs("xpath", args, kwargs, "expression", &expr); err != nil {
		return nil, err
	}
	if len(expr) > MaxXPathExprSize {
		return nil, fmt.Errorf("xpath: expression %d bytes exceeds limit %d", len(expr), MaxXPathExprSize)
	}
	compiled, err := xpath.Compile(expr)
	if err != nil {
		return nil, fmt.Errorf("xpath: compile %q: %w", truncateForHeader(expr), err)
	}
	return &xpathValue{src: expr, expr: compiled}, nil
}

// xpathValue is the Starlark value returned by xpath(). Methods: query, test.
type xpathValue struct {
	src  string
	expr *xpath.Expr
}

var _ starlark.HasAttrs = (*xpathValue)(nil)

func (x *xpathValue) String() string        { return fmt.Sprintf("xpath(%q)", x.src) }
func (x *xpathValue) Type() string          { return "xpath" }
func (x *xpathValue) Freeze()               {}
func (x *xpathValue) Truth() starlark.Bool  { return starlark.True }
func (x *xpathValue) Hash() (uint32, error) { return 0, errors.New("unhashable type: xpath") }

func (x *xpathValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "query":
		return starlark.NewBuiltin("query", x.query), nil
	case "test":
		return starlark.NewBuiltin("test", x.test), nil
	}
	return nil, nil
}

func (x *xpathValue) AttrNames() []string {
	return []string{"query", "test"}
}

// query(html) → list[bytes]: parses html (tolerant of incomplete markup) and
// returns the inner text of every matched node as bytes. Returns an empty
// list when the document is unparseable or the expression matches nothing.
func (x *xpathValue) query(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("query", args, kwargs, "html", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("xpath.query", input)
	if err != nil {
		return nil, err
	}
	doc, err := htmlquery.Parse(bytes.NewReader(data))
	if err != nil {
		return starlark.NewList(nil), nil
	}
	nodes := htmlquery.QuerySelectorAll(doc, x.expr)
	out := starlark.NewList(make([]starlark.Value, 0, len(nodes)))
	for _, n := range nodes {
		_ = out.Append(starlark.Bytes(htmlquery.InnerText(n)))
	}
	return out, nil
}

// test(html) → bool: shorthand for len(.query(html)) > 0.
func (x *xpathValue) test(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	if err := starlark.UnpackArgs("test", args, kwargs, "html", &input); err != nil {
		return nil, err
	}
	data, err := bytesOrString("xpath.test", input)
	if err != nil {
		return nil, err
	}
	doc, err := htmlquery.Parse(bytes.NewReader(data))
	if err != nil {
		return starlark.False, nil
	}
	nodes := htmlquery.QuerySelectorAll(doc, x.expr)
	return starlark.Bool(len(nodes) > 0), nil
}

// ── small shared helper ──────────────────────────────────────────────────

// bytesOrString accepts a Starlark bytes or string value and returns the raw
// byte slice. Centralises the type-check that almost every builtin needs.
func bytesOrString(fnName string, v starlark.Value) ([]byte, error) {
	switch x := v.(type) {
	case starlark.Bytes:
		return []byte(x), nil
	case starlark.String:
		return []byte(string(x)), nil
	}
	return nil, fmt.Errorf("%s: input must be bytes or string, got %s", fnName, v.Type())
}
