package main

import (
	"context"
	"time"

	"proxy-gateway/utils"
)

// This file defines the server's own context keys — our specific domain
// concepts that don't belong in the core framework.

type serverCtxKey int

const (
	ctxSet serverCtxKey = iota
	ctxSessionKey
	ctxSessionTTL
)

func withSet(ctx context.Context, set string) context.Context {
	return context.WithValue(ctx, ctxSet, set)
}

func getSet(ctx context.Context) string {
	v, _ := ctx.Value(ctxSet).(string)
	return v
}

func withSessionKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, ctxSessionKey, key)
}

func getSessionKey(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionKey).(string)
	return v
}

func withSessionTTL(ctx context.Context, ttl time.Duration) context.Context {
	return context.WithValue(ctx, ctxSessionTTL, ttl)
}

func getSessionTTL(ctx context.Context) time.Duration {
	v, _ := ctx.Value(ctxSessionTTL).(time.Duration)
	return v
}

// Re-export utils.WithMeta/GetMeta for use in parse_json_creds.go
var withMeta = utils.WithMeta
