package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"proxy-gateway/core"
	"proxy-gateway/utils"
)

// ParseJSONCreds parses RawUsername as a JSON object and populates context
// with the server's domain concepts (identity, set, session TTL, metadata).
//
// Expected JSON format:
//
//	{"sub":"alice", "set":"residential", "minutes":5, "meta":{"app":"crawler"}}
func ParseJSONCreds(next core.Handler) core.Handler {
	return core.HandlerFunc(func(ctx context.Context, req *core.Request) (*core.Result, error) {
		if req.RawUsername == "" {
			return nil, fmt.Errorf("empty username")
		}

		var parsed struct {
			Sub     string                 `json:"sub"`
			Set     string                 `json:"set"`
			Minutes int                    `json:"minutes"`
			Meta    map[string]interface{} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(req.RawUsername), &parsed); err != nil {
			return nil, fmt.Errorf("username is not valid JSON: %w", err)
		}
		if parsed.Sub == "" {
			return nil, fmt.Errorf("'sub' must not be empty")
		}
		if parsed.Set == "" {
			return nil, fmt.Errorf("'set' must not be empty")
		}

		ctx = core.WithIdentity(ctx, parsed.Sub)
		ctx = core.WithCredential(ctx, req.RawPassword)
		ctx = withSet(ctx, parsed.Set)
		ctx = withSessionTTL(ctx, time.Duration(parsed.Minutes)*time.Minute)
		ctx = withMeta(ctx, utils.Meta(parsed.Meta))
		// Session key: stable across TTL changes — keyed by identity+set only.
		ctx = withSessionKey(ctx, parsed.Sub+"\x00"+parsed.Set)

		return next.Resolve(ctx, req)
	})
}
