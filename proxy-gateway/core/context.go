package core

import "context"

// Meta is a flat map of string/number metadata values.
type Meta map[string]interface{}

// GetString returns the string value for key, or "".
func (m Meta) GetString(key string) string {
	v, _ := m[key].(string)
	return v
}

// TLSState holds MITM TLS interception state.
type TLSState struct {
	Broken     bool   // TLS has been terminated by MITM
	ServerName string // SNI hostname
}

// ---------------------------------------------------------------------------
// Context helpers — middleware sets these, handlers read them
// ---------------------------------------------------------------------------

type ctxKey int

const (
	ctxSub ctxKey = iota
	ctxPassword
	ctxSet
	ctxMeta
	ctxSessionKey
	ctxSessionTTL
	ctxTLSState
)

func WithSub(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, ctxSub, sub)
}

func Sub(ctx context.Context) string {
	v, _ := ctx.Value(ctxSub).(string)
	return v
}

func WithPassword(ctx context.Context, pw string) context.Context {
	return context.WithValue(ctx, ctxPassword, pw)
}

func Password(ctx context.Context) string {
	v, _ := ctx.Value(ctxPassword).(string)
	return v
}

func WithSet(ctx context.Context, set string) context.Context {
	return context.WithValue(ctx, ctxSet, set)
}

func Set(ctx context.Context) string {
	v, _ := ctx.Value(ctxSet).(string)
	return v
}

func WithMeta(ctx context.Context, m Meta) context.Context {
	return context.WithValue(ctx, ctxMeta, m)
}

func GetMeta(ctx context.Context) Meta {
	v, _ := ctx.Value(ctxMeta).(Meta)
	return v
}

func WithSessionKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, ctxSessionKey, key)
}

func SessionKey(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionKey).(string)
	return v
}

func WithSessionTTL(ctx context.Context, minutes int) context.Context {
	return context.WithValue(ctx, ctxSessionTTL, minutes)
}

func SessionTTL(ctx context.Context) int {
	v, _ := ctx.Value(ctxSessionTTL).(int)
	return v
}

func WithTLSState(ctx context.Context, state TLSState) context.Context {
	return context.WithValue(ctx, ctxTLSState, state)
}

func GetTLSState(ctx context.Context) TLSState {
	v, _ := ctx.Value(ctxTLSState).(TLSState)
	return v
}
