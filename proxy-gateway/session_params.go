package main

import (
	"encoding/json"
	"sort"

	"proxy-kit"
)

// SessionParams are the fields that determine session identity.
// Two requests with the same SessionParams get the same session.
// minutes (TTL) is deliberately excluded — changing TTL doesn't create
// a new session.
type SessionParams struct {
	Set  string                 `json:"set"`
	Meta map[string]interface{} `json:"meta"`
}

// Seed computes the uint64 session identity seed.
func (a *SessionParams) Seed() uint64 {
	return proxykit.TopLevelSeed(a.Set + "\x00" + canonicalMeta(a.Meta))
}

// CanonicalJSON returns a stable JSON representation of the session params
// suitable for use as a JSON value in analytics events.
func (a *SessionParams) CanonicalJSON() string {
	return canonicalMeta(a.Meta)
}

// MetaCanonicalJSON returns the canonical JSON for a free-form session_meta
// map. Reuses canonicalMeta so session_meta serializes identically to
// session_params (sorted keys, no whitespace). Unlike session_params, meta
// never affects session identity — it's informational only and stored on
// the analytics side keyed by the session_params hash.
func MetaCanonicalJSON(m map[string]interface{}) string {
	return canonicalMeta(m)
}

// ---------------------------------------------------------------------------
// Canonical map serialization (sorted keys for stable hashing)
// ---------------------------------------------------------------------------

func canonicalMeta(meta map[string]interface{}) string {
	if len(meta) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b, _ := json.Marshal(orderedMap{keys: keys, m: meta})
	return string(b)
}

type orderedMap struct {
	keys []string
	m    map[string]interface{}
}

func (o orderedMap) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, k := range o.keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, _ := json.Marshal(k)
		val, _ := json.Marshal(o.m[k])
		buf = append(buf, key...)
		buf = append(buf, ':')
		buf = append(buf, val...)
	}
	buf = append(buf, '}')
	return buf, nil
}
