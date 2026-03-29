package main

import (
	"context"
	"fmt"

	"proxy-gateway/core"
	"proxy-gateway/utils"
)

// Server holds the assembled pipeline and all introspection handles.
type Server struct {
	Pipeline core.Handler
	Sessions *core.SessionHandler
}

// BuildServer assembles the full handler pipeline from config.
func BuildServer(cfg *Config, configDir string) (*Server, error) {
	users, err := cfg.authUsers()
	if err != nil {
		return nil, err
	}

	sources := make(map[string]core.Handler)
	for _, raw := range cfg.ProxySets {
		src, err := buildSource(&raw, configDir)
		if err != nil {
			return nil, fmt.Errorf("proxy set %q: %w", raw.Name, err)
		}
		sources[raw.Name] = src
	}

	router := core.HandlerFunc(func(ctx context.Context, req *core.Request) (*core.Result, error) {
		set := core.Set(ctx)
		h, ok := sources[set]
		if !ok {
			return nil, fmt.Errorf("unknown proxy set %q", set)
		}
		return h.Resolve(ctx, req)
	})

	sessions := core.Session(router)

	pipeline := ParseJSONCreds(
		core.Auth(
			utils.NewMapAuth(users),
			sessions,
		),
	)

	return &Server{
		Pipeline: pipeline,
		Sessions: sessions,
	}, nil
}
