package proxygatewayclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// UsernameParams holds the decoded components of a proxy-gateway username.
//
// MITM mode is opt-in via the MITM flag (or implicitly by setting HTTPCloak
// or Scripts). When MITM is enabled but HTTPCloak is nil, the gateway
// defaults to the chrome-latest preset.
type UsernameParams struct {
	// Set is the proxy set name — must match a [[proxy_set]] name in the server config.
	Set string `json:"set"`
	// Minutes is the session duration (0 = new proxy every request, 1–1440 = sticky session).
	Minutes int `json:"minutes"`
	// SessionParams is an arbitrary key/value map that, together with Set, forms
	// the session identity key. Changing SessionParams creates a new session
	// (different upstream IP). Use it for fields that should partition traffic
	// into distinct sessions (e.g. per-user, per-region).
	SessionParams map[string]any `json:"session_params,omitempty"`
	// SessionMeta is arbitrary informational metadata attached to each request.
	// It does NOT influence session identity or IP selection — same SessionParams
	// + different SessionMeta = same upstream IP. Carried through to the
	// analytics service for filtering/grouping (tenant, campaign, request_id, …).
	SessionMeta map[string]any `json:"session_meta,omitempty"`
	// MITM toggles MITM mode. Marshaled as the presence of the `mitm` wire
	// object. Setting HTTPCloak or Scripts implicitly enables MITM as well.
	MITM bool `json:"-"`
	// HTTPCloak enables TLS fingerprint spoofing. Wire form lives under
	// `mitm.httpcloak`. Setting this implies MITM is on.
	HTTPCloak *HTTPCloakSpec `json:"-"`
	// Scripts is the ordered chain of Starlark scripts evaluated server-side
	// on this request's MITM'd response. Each entry is either a reference
	// to a named [[script]] declared in the gateway's config.toml, or an
	// inline source. Wire form lives under `mitm.scripts`. Setting this
	// implies MITM is on.
	//
	// See the gateway's SCRIPTS.md for the full guide.
	Scripts []ScriptEntry `json:"-"`
}

// mitmWire is the on-wire `mitm` object embedded inside a username payload.
type mitmWire struct {
	HTTPCloak *HTTPCloakSpec `json:"httpcloak,omitempty"`
	Scripts   []ScriptEntry  `json:"scripts,omitempty"`
}

// usernameWire mirrors UsernameParams' on-wire shape, with `mitm` scoped
// around httpcloak + scripts.
type usernameWire struct {
	Set           string         `json:"set"`
	Minutes       int            `json:"minutes,omitempty"`
	SessionParams map[string]any `json:"session_params,omitempty"`
	SessionMeta   map[string]any `json:"session_meta,omitempty"`
	MITM          *mitmWire      `json:"mitm,omitempty"`
}

// MarshalJSON emits the wire form, scoping httpcloak + scripts inside `mitm`.
// `mitm` is emitted whenever the configuration enables MITM in any way —
// either explicitly via MITM=true, or implicitly by carrying a non-nil
// HTTPCloak or a non-empty Scripts slice.
func (p UsernameParams) MarshalJSON() ([]byte, error) {
	w := usernameWire{
		Set:           p.Set,
		Minutes:       p.Minutes,
		SessionParams: p.SessionParams,
		SessionMeta:   p.SessionMeta,
	}
	if p.MITM || p.HTTPCloak != nil || len(p.Scripts) > 0 {
		w.MITM = &mitmWire{HTTPCloak: p.HTTPCloak, Scripts: p.Scripts}
	}
	return json.Marshal(w)
}

// UnmarshalJSON reads the wire form. Presence of `mitm` toggles MITM=true.
// Top-level `httpcloak`/`scripts` keys are rejected to match the gateway.
func (p *UsernameParams) UnmarshalJSON(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return err
	}
	if _, ok := top["httpcloak"]; ok {
		return errors.New("top-level 'httpcloak' is no longer accepted — move it inside the 'mitm' object")
	}
	if _, ok := top["scripts"]; ok {
		return errors.New("top-level 'scripts' is no longer accepted — move it inside the 'mitm' object")
	}
	var w usernameWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	*p = UsernameParams{
		Set:           w.Set,
		Minutes:       w.Minutes,
		SessionParams: w.SessionParams,
		SessionMeta:   w.SessionMeta,
	}
	if w.MITM != nil {
		p.MITM = true
		p.HTTPCloak = w.MITM.HTTPCloak
		p.Scripts = w.MITM.Scripts
	}
	return nil
}

// ScriptEntry is one entry in a username's `scripts` chain. Wire form is a
// tagged discriminated union with `kind` as the discriminator:
//
//   - {"kind": "ref",    "name":   "antibot"}
//   - {"kind": "source", "source": "def response_bailing(r): pass"}
//
// On the gateway-side username parser a bare string is also accepted as
// shorthand for {kind:"ref", name:<string>}; this SDK always emits the
// tagged form for clarity.
//
// Use ScriptRef / ScriptSource constructors rather than building this
// struct by hand.
type ScriptEntry struct {
	Kind   ScriptEntryKind `json:"kind"`
	Name   string          `json:"name,omitempty"`
	Source string          `json:"source,omitempty"`
}

// ScriptEntryKind is the discriminator field on a ScriptEntry.
type ScriptEntryKind string

const (
	// ScriptEntryKindRef references a named [[script]] on the gateway.
	ScriptEntryKindRef ScriptEntryKind = "ref"
	// ScriptEntryKindSource carries inline Starlark source.
	ScriptEntryKindSource ScriptEntryKind = "source"
)

// MarshalJSON emits the wire form and validates internal consistency.
func (e ScriptEntry) MarshalJSON() ([]byte, error) {
	switch e.Kind {
	case ScriptEntryKindRef:
		if e.Name == "" {
			return nil, errors.New("ScriptEntry: kind=ref requires Name")
		}
		if e.Source != "" {
			return nil, errors.New("ScriptEntry: kind=ref must not carry Source")
		}
		return json.Marshal(struct {
			Kind ScriptEntryKind `json:"kind"`
			Name string          `json:"name"`
		}{e.Kind, e.Name})
	case ScriptEntryKindSource:
		if e.Source == "" {
			return nil, errors.New("ScriptEntry: kind=source requires Source")
		}
		if e.Name != "" {
			return nil, errors.New("ScriptEntry: kind=source must not carry Name")
		}
		return json.Marshal(struct {
			Kind   ScriptEntryKind `json:"kind"`
			Source string          `json:"source"`
		}{e.Kind, e.Source})
	default:
		return nil, fmt.Errorf("ScriptEntry: invalid Kind %q (expected %q or %q)",
			e.Kind, ScriptEntryKindRef, ScriptEntryKindSource)
	}
}

// UnmarshalJSON accepts a bare string ("name", shorthand for ref-by-name)
// or the tagged object form.
func (e *ScriptEntry) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		e.Kind = ScriptEntryKindRef
		e.Name = s
		return nil
	}
	var obj struct {
		Kind   ScriptEntryKind `json:"kind"`
		Name   string          `json:"name"`
		Source string          `json:"source"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	switch obj.Kind {
	case ScriptEntryKindRef:
		if obj.Name == "" {
			return errors.New("ScriptEntry: kind=ref requires non-empty 'name'")
		}
		*e = ScriptEntry{Kind: ScriptEntryKindRef, Name: obj.Name}
	case ScriptEntryKindSource:
		if obj.Source == "" {
			return errors.New("ScriptEntry: kind=source requires non-empty 'source'")
		}
		*e = ScriptEntry{Kind: ScriptEntryKindSource, Source: obj.Source}
	case "":
		return errors.New("ScriptEntry: missing 'kind' discriminator (expected \"ref\" or \"source\")")
	default:
		return fmt.Errorf("ScriptEntry: unknown kind %q (expected \"ref\" or \"source\")", obj.Kind)
	}
	return nil
}

// ScriptRef builds a ScriptEntry referencing a named server-side script.
func ScriptRef(name string) ScriptEntry { return ScriptEntry{Kind: ScriptEntryKindRef, Name: name} }

// ScriptSource builds a ScriptEntry with inline Starlark source.
func ScriptSource(src string) ScriptEntry {
	return ScriptEntry{Kind: ScriptEntryKindSource, Source: src}
}

// HTTPCloakSpec configures TLS fingerprint spoofing.
type HTTPCloakSpec struct {
	// Preset is the browser fingerprint preset (e.g. "chrome-latest", "firefox-latest").
	Preset string `json:"preset"`
	// UserAgent controls User-Agent handling: "ignore" (default), "preset", or "check".
	UserAgent string `json:"user_agent,omitempty"`
	// JA3 overrides the preset's TLS fingerprint (advanced).
	JA3 string `json:"ja3,omitempty"`
	// Akamai overrides the preset's HTTP/2 fingerprint (advanced).
	Akamai string `json:"akamai,omitempty"`
	// ECH controls Encrypted Client Hello (hides SNI from network observers):
	//   nil/true — auto-fetch ECH config from DNS (default)
	//   false    — disable ECH
	//   "domain" — fetch ECH config from this domain instead of target
	ECH any `json:"ech,omitempty"`
}

// BuildUsername encodes the given parameters into a base64 proxy-gateway username.
// The returned string is used as the Proxy-Authorization username; the password is always "x".
//
//	username := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
//	    Set:           "residential",
//	    Minutes:       60,
//	    SessionParams: map[string]any{"user": "alice"},
//	    SessionMeta:   map[string]any{"tenant": "acme", "campaign": "spring"},
//	})
func BuildUsername(p UsernameParams) (string, error) {
	if p.Set == "" {
		return "", errors.New("proxy set name must not be empty")
	}
	if p.Minutes < 0 || p.Minutes > 1440 {
		return "", fmt.Errorf("minutes must be between 0 and 1440, got %d", p.Minutes)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshalling username: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// MustBuildUsername is like BuildUsername but panics on error.
// Intended for use with static/compile-time-known parameters.
func MustBuildUsername(p UsernameParams) string {
	u, err := BuildUsername(p)
	if err != nil {
		panic("proxygatewayclient.MustBuildUsername: " + err.Error())
	}
	return u
}

// ParseUsername decodes a base64 proxy-gateway username back into its components.
func ParseUsername(username string) (*UsernameParams, error) {
	raw, err := base64.StdEncoding.DecodeString(username)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(username)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 username: %w", err)
		}
	}
	var p UsernameParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parsing username JSON: %w", err)
	}
	if p.Set == "" {
		return nil, errors.New("username JSON missing 'set' field")
	}
	return &p, nil
}
