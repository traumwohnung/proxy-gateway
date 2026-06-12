package main

import (
	"context"
	"fmt"
	"net"
	"strings"

	proxykit "proxy-kit"
)

// DestinationAllowlist matches a request's destination host against a set of
// allowed hosts and parent domains. It exists to stop the gateway being used
// as an open forward proxy for arbitrary destinations (egress laundering,
// internal SSRF, paid-quota burn). See TRA-302 / audit H4.
//
// Matching is case-insensitive on the hostname only (the port is ignored).
// Two forms are supported per entry:
//
//   - exact host:        "www.immobilienscout24.de" matches only that host.
//   - domain suffix:     ".immobilienscout24.de" matches that host and any
//     subdomain of it (foo.immobilienscout24.de, immobilienscout24.de).
type DestinationAllowlist struct {
	exact   map[string]struct{}
	domains []string // normalized to ".example.com"
}

// NewDestinationAllowlist builds an allowlist from config entries. An entry
// beginning with "." (or "*.") is treated as a domain suffix; anything else is
// an exact host. Empty entries are ignored. Returns nil when no entries are
// given, which callers treat as "allowlist disabled".
func NewDestinationAllowlist(entries []string) *DestinationAllowlist {
	al := &DestinationAllowlist{exact: map[string]struct{}{}}
	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" {
			continue
		}
		switch {
		case strings.HasPrefix(e, "*."):
			al.domains = append(al.domains, e[1:]) // "*.x.com" -> ".x.com"
		case strings.HasPrefix(e, "."):
			al.domains = append(al.domains, e)
		default:
			al.exact[e] = struct{}{}
		}
	}
	if len(al.exact) == 0 && len(al.domains) == 0 {
		return nil
	}
	return al
}

// Allows reports whether the given destination (host or host:port) is permitted.
func (al *DestinationAllowlist) Allows(target string) bool {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	if _, ok := al.exact[host]; ok {
		return true
	}
	for _, d := range al.domains {
		// ".example.com" matches "example.com" and "*.example.com".
		if host == d[1:] || strings.HasSuffix(host, d) {
			return true
		}
	}
	return false
}

// AllowDestinations is middleware that rejects any request whose destination
// host is not on the allowlist. If al is nil the middleware is a no-op
// passthrough (allowlist disabled).
func AllowDestinations(al *DestinationAllowlist, next proxykit.Handler) proxykit.Handler {
	if al == nil {
		return next
	}
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		if !al.Allows(req.Target) {
			return nil, fmt.Errorf("destination not allowed: %s", req.Target)
		}
		return next.Resolve(ctx, req)
	})
}
