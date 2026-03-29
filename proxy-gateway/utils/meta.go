package utils

import "context"

// Meta is a flat map of string/value metadata that callers can attach to
// a request context for use by proxy sources.
type Meta map[string]interface{}

// GetString returns the string value for key, or "".
func (m Meta) GetString(key string) string {
	v, _ := m[key].(string)
	return v
}

type metaCtxKey struct{}

// WithMeta stores metadata in context for downstream handlers to read.
func WithMeta(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, metaCtxKey{}, m)
}

// GetMeta reads metadata from context.
func GetMeta(ctx context.Context) Meta {
	v, _ := ctx.Value(metaCtxKey{}).(Meta)
	return v
}
