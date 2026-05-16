package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"proxy-kit"
	"proxy-kit/utils"
)

// Username is the parsed proxy-gateway username JSON.
//
//	{"set":"residential", "minutes":5, "session_params":{"platform":"myapp","user":"alice"}}
//	{"set":"direct", "httpcloak":{"preset":"chrome-latest"}}
//	{"set":"direct", "httpcloak":{"preset":"chrome-latest"}, "scripts":["antibot", {"source":"..."}]}
type Username struct {
	SessionParams SessionParams
	Minutes       int
	Httpcloak     *utils.HTTPCloakSpec   // optional; triggers MITM + TLS fingerprint spoofing
	SessionMeta   map[string]interface{} // optional; informational only — never affects session/IP
	Scripts       []*Script              // optional ordered chain; resolved from refs + inline
	Raw           string                 // original JSON string, stored as session label
}

// ParseUsername parses a raw JSON (or base64-encoded JSON) username string.
// When the payload's `scripts` array contains string entries (references by
// name) or `{"ref":"name"}` objects, registry is consulted to resolve them.
// Pass nil registry to disable refs (any string/ref entry then errors at
// parse time).
func ParseUsername(raw string, registry ScriptRegistry) (*Username, error) {
	jsonBytes := []byte(raw)
	if len(raw) > 0 && raw[0] != '{' {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("username is neither JSON nor valid base64: %w", err)
			}
		}
		jsonBytes = decoded
	}
	var j struct {
		Set           string                 `json:"set"`
		Minutes       int                    `json:"minutes"`
		SessionParams map[string]interface{} `json:"session_params"`
		SessionMeta   map[string]interface{} `json:"session_meta"`
		Httpcloak     json.RawMessage        `json:"httpcloak"`
		Scripts       []json.RawMessage      `json:"scripts"`
	}
	if err := json.Unmarshal(jsonBytes, &j); err != nil {
		return nil, fmt.Errorf("username is not valid JSON: %w", err)
	}
	if j.Set == "" {
		return nil, fmt.Errorf("'set' must not be empty")
	}
	spec, err := utils.ParseHTTPCloakSpec(j.Httpcloak)
	if err != nil {
		return nil, fmt.Errorf("httpcloak: %w", err)
	}

	scripts, err := resolveScriptList("username", j.Scripts, registry, "username")
	if err != nil {
		return nil, err
	}
	if len(scripts) > 0 && spec == nil {
		return nil, fmt.Errorf("scripts requires httpcloak to be set (MITM required)")
	}

	return &Username{
		SessionParams: SessionParams{Set: j.Set, Meta: j.SessionParams},
		Minutes:       j.Minutes,
		Httpcloak:     spec,
		SessionMeta:   j.SessionMeta,
		Scripts:       scripts,
		Raw:           string(jsonBytes),
	}, nil
}

// resolveScriptList parses a JSON array whose entries are either:
//   - a JSON string (shorthand for {"kind":"ref","name":<string>})
//   - {"kind":"ref","name":"..."}    — reference a named script
//   - {"kind":"source","source":"..."}— inline source compiled now
//
// Returns the ordered slice of *Script. inlineNamePrefix is used in the
// compile-error context (e.g. "username" or "config:residential").
func resolveScriptList(context string, entries []json.RawMessage, registry ScriptRegistry, inlineNamePrefix string) ([]*Script, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make([]*Script, 0, len(entries))
	for i, raw := range entries {
		raw = trimJSONSpace(raw)
		if len(raw) == 0 {
			return nil, fmt.Errorf("%s scripts[%d]: empty entry", context, i)
		}
		// Shorthand: bare string = ref by name.
		if raw[0] == '"' {
			var name string
			if err := json.Unmarshal(raw, &name); err != nil {
				return nil, fmt.Errorf("%s scripts[%d]: %w", context, i, err)
			}
			s, err := resolveRef(context, i, name, registry)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
			continue
		}
		// Tagged form: discriminated by "kind".
		var obj struct {
			Kind   string `json:"kind"`
			Name   string `json:"name"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("%s scripts[%d]: %w", context, i, err)
		}
		switch obj.Kind {
		case "ref":
			if obj.Name == "" {
				return nil, fmt.Errorf("%s scripts[%d]: kind=ref requires non-empty 'name'", context, i)
			}
			s, err := resolveRef(context, i, obj.Name, registry)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		case "source":
			if obj.Source == "" {
				return nil, fmt.Errorf("%s scripts[%d]: kind=source requires non-empty 'source'", context, i)
			}
			name := fmt.Sprintf("%s[%d]", inlineNamePrefix, i)
			s, err := Compile(name, obj.Source)
			if err != nil {
				return nil, fmt.Errorf("%s scripts[%d]: %w", context, i, err)
			}
			out = append(out, s)
		case "":
			return nil, fmt.Errorf("%s scripts[%d]: missing 'kind' discriminator (expected \"ref\" or \"source\")", context, i)
		default:
			return nil, fmt.Errorf("%s scripts[%d]: unknown kind %q (expected \"ref\" or \"source\")", context, i, obj.Kind)
		}
	}
	return out, nil
}

func resolveRef(context string, i int, name string, registry ScriptRegistry) (*Script, error) {
	if registry == nil {
		return nil, fmt.Errorf("%s scripts[%d]: reference %q but no script registry configured", context, i, name)
	}
	s, ok := registry.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("%s scripts[%d]: unknown script reference %q", context, i, name)
	}
	return s, nil
}

func trimJSONSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return b
}

// ---------------------------------------------------------------------------
// Context keys
// ---------------------------------------------------------------------------

type ctxKey int

const (
	ctxSet ctxKey = iota
	ctxHTTPCloakPreset
	ctxMinutes
	ctxSessionMetaJSON
	ctxScripts
)

func withMinutes(ctx context.Context, m int) context.Context {
	return context.WithValue(ctx, ctxMinutes, m)
}

func getMinutes(ctx context.Context) int {
	v, _ := ctx.Value(ctxMinutes).(int)
	return v
}

func withSet(ctx context.Context, set string) context.Context {
	return context.WithValue(ctx, ctxSet, set)
}

func getSet(ctx context.Context) string {
	v, _ := ctx.Value(ctxSet).(string)
	return v
}

func withSessionMetaJSON(ctx context.Context, canonicalJSON string) context.Context {
	return context.WithValue(ctx, ctxSessionMetaJSON, canonicalJSON)
}

func getSessionMetaJSON(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionMetaJSON).(string)
	return v
}

func withHTTPCloakSpec(ctx context.Context, spec *utils.HTTPCloakSpec) context.Context {
	return context.WithValue(ctx, ctxHTTPCloakPreset, spec)
}

func getHTTPCloakSpec(ctx context.Context) *utils.HTTPCloakSpec {
	v, _ := ctx.Value(ctxHTTPCloakPreset).(*utils.HTTPCloakSpec)
	return v
}

// withScripts stores the per-request resolved script chain (username
// override or per-set default) on the context.
func withScripts(ctx context.Context, scripts []*Script) context.Context {
	if len(scripts) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxScripts, scripts)
}

func getScripts(ctx context.Context) []*Script {
	v, _ := ctx.Value(ctxScripts).([]*Script)
	return v
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// ParseJSONCreds is middleware that parses RawUsername as a JSON object and
// populates context. registry is consulted when the username references
// named scripts; pass nil to disable refs.
func ParseJSONCreds(registry ScriptRegistry, next proxykit.Handler) proxykit.Handler {
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		if req.RawUsername == "" {
			return nil, fmt.Errorf("empty username")
		}
		u, err := ParseUsername(req.RawUsername, registry)
		if err != nil {
			return nil, err
		}

		ctx = withSet(ctx, u.SessionParams.Set)
		ctx = withMinutes(ctx, u.Minutes)
		ctx = utils.WithSeedTTL(ctx, time.Duration(u.Minutes)*time.Minute)
		ctx = utils.WithTopLevelSeed(ctx, u.SessionParams.Seed())
		ctx = utils.WithSessionLabel(ctx, u.Raw)
		ctx = utils.WithSessionParamsJSON(ctx, u.SessionParams.CanonicalJSON())
		ctx = utils.WithProxysetName(ctx, u.SessionParams.Set)
		ctx = withSessionMetaJSON(ctx, MetaCanonicalJSON(u.SessionMeta))
		ctx = withHTTPCloakSpec(ctx, u.Httpcloak)
		ctx = withScripts(ctx, u.Scripts)

		return next.Resolve(ctx, req)
	})
}

// PasswordAuth is middleware that checks req.RawPassword against a fixed
// password. If password is empty, all requests pass through.
func PasswordAuth(password string, next proxykit.Handler) proxykit.Handler {
	if password == "" {
		return next
	}
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		if req.RawPassword != password {
			return nil, fmt.Errorf("invalid credentials")
		}
		return next.Resolve(ctx, req)
	})
}
