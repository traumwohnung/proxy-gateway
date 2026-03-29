package core

import "context"

// TLSState holds MITM TLS interception state.
type TLSState struct {
	Broken     bool   // TLS has been terminated by MITM
	ServerName string // SNI hostname
}

// ---------------------------------------------------------------------------
// Context helpers — the framework's own context keys
// ---------------------------------------------------------------------------

type ctxKey int

const (
	ctxIdentity ctxKey = iota
	ctxCredential
	ctxTLSState
)

// WithIdentity stores the caller's identity in context.
// Used by Auth to validate credentials and by RateLimit/Session as the
// default bucket/affinity key.
func WithIdentity(ctx context.Context, identity string) context.Context {
	return context.WithValue(ctx, ctxIdentity, identity)
}

// Identity reads the caller's identity from context.
func Identity(ctx context.Context) string {
	v, _ := ctx.Value(ctxIdentity).(string)
	return v
}

// WithCredential stores the caller's credential (password/token) in context.
func WithCredential(ctx context.Context, credential string) context.Context {
	return context.WithValue(ctx, ctxCredential, credential)
}

// Credential reads the caller's credential from context.
func Credential(ctx context.Context) string {
	v, _ := ctx.Value(ctxCredential).(string)
	return v
}

// WithTLSState stores TLS interception state in context.
func WithTLSState(ctx context.Context, state TLSState) context.Context {
	return context.WithValue(ctx, ctxTLSState, state)
}

// GetTLSState reads TLS interception state from context.
func GetTLSState(ctx context.Context) TLSState {
	v, _ := ctx.Value(ctxTLSState).(TLSState)
	return v
}
