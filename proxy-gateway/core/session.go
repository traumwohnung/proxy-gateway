package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SessionInfo describes an active sticky session (for API introspection).
type SessionInfo struct {
	SessionID      uint64    `json:"session_id"`
	SessionKey     string    `json:"session_key"`
	Upstream       string    `json:"upstream"`
	CreatedAt      time.Time `json:"created_at"`
	NextRotationAt time.Time `json:"next_rotation_at"`
	LastRotationAt time.Time `json:"last_rotation_at"`
}

// SessionParams holds the session key and TTL for a request.
// Provided by the caller's KeyFunc.
type SessionParams struct {
	Key string        // stable affinity key (e.g. "alice\x00residential")
	TTL time.Duration // how long to pin this session (0 = no affinity)
}

// KeyFunc extracts SessionParams from a context.
// The framework does not define what the key means — callers provide this.
//
// Example (our server):
//
//	func sessionKey(ctx context.Context) core.SessionParams {
//	    return core.SessionParams{
//	        Key: myIdentity(ctx) + "\x00" + mySet(ctx),
//	        TTL: time.Duration(myTTLMinutes(ctx)) * time.Minute,
//	    }
//	}
type KeyFunc func(ctx context.Context) SessionParams

// IdentityKey is a KeyFunc that uses Identity(ctx) as the session key
// with no TTL (pass-through). Useful for simple deployments.
func IdentityKey(ctx context.Context) SessionParams {
	return SessionParams{Key: Identity(ctx)}
}

type stickyEntry struct {
	sessionID      uint64
	proxy          Proxy
	startedAt      time.Time
	nextRotationAt time.Time
	lastRotationAt time.Time
	duration       time.Duration
}

// SessionHandler wraps an inner Handler and provides sticky-session affinity.
// Requests where KeyFunc returns the same Key get the same upstream proxy
// for the configured TTL.
type SessionHandler struct {
	next     Handler
	keyFn    KeyFunc
	mu       sync.RWMutex
	sessions map[string]*stickyEntry
	nextID   atomic.Uint64
}

// Session creates a SessionHandler. keyFn extracts the session key and TTL
// from each request's context. If keyFn returns an empty Key or zero TTL,
// the request passes straight through to next.
//
// A cleanup goroutine is started automatically to prune expired sessions.
func Session(keyFn KeyFunc, next Handler) *SessionHandler {
	s := &SessionHandler{
		next:     next,
		keyFn:    keyFn,
		sessions: make(map[string]*stickyEntry),
	}
	go s.runCleanup()
	return s
}

// Resolve implements Handler.
func (s *SessionHandler) Resolve(ctx context.Context, req *Request) (*Result, error) {
	params := s.keyFn(ctx)
	if params.TTL <= 0 || params.Key == "" {
		return s.next.Resolve(ctx, req)
	}

	s.mu.RLock()
	entry, ok := s.sessions[params.Key]
	if ok && time.Since(entry.startedAt) < entry.duration {
		p := entry.proxy
		s.mu.RUnlock()
		return Resolved(&p), nil
	}
	s.mu.RUnlock()

	result, err := s.next.Resolve(ctx, req)
	if err != nil || result == nil || result.Proxy == nil {
		return result, err
	}

	now := time.Now().UTC()
	newEntry := &stickyEntry{
		sessionID:      s.nextID.Add(1) - 1,
		proxy:          *result.Proxy,
		startedAt:      now,
		nextRotationAt: now.Add(params.TTL),
		lastRotationAt: now,
		duration:       params.TTL,
	}

	s.mu.Lock()
	if existing, ok := s.sessions[params.Key]; ok && time.Since(existing.startedAt) < existing.duration {
		p := existing.proxy
		s.mu.Unlock()
		return Resolved(&p), nil
	}
	s.sessions[params.Key] = newEntry
	s.mu.Unlock()

	return result, nil
}

// GetSession returns info about an active session, or nil.
func (s *SessionHandler) GetSession(key string) *SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.sessions[key]
	if !ok || time.Since(e.startedAt) >= e.duration {
		return nil
	}
	return infoFrom(key, e)
}

// ListSessions returns info about all active sessions.
func (s *SessionHandler) ListSessions() []SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SessionInfo
	for key, e := range s.sessions {
		if time.Since(e.startedAt) < e.duration {
			out = append(out, *infoFrom(key, e))
		}
	}
	return out
}

// ForceRotate resolves a new proxy for the given session key.
func (s *SessionHandler) ForceRotate(ctx context.Context, key string) (*SessionInfo, error) {
	s.mu.RLock()
	e, ok := s.sessions[key]
	if !ok || time.Since(e.startedAt) >= e.duration {
		s.mu.RUnlock()
		return nil, nil
	}
	duration := e.duration
	s.mu.RUnlock()

	result, err := s.next.Resolve(ctx, &Request{})
	if err != nil || result == nil || result.Proxy == nil {
		return nil, err
	}

	now := time.Now().UTC()
	s.mu.Lock()
	e, ok = s.sessions[key]
	if !ok {
		s.mu.Unlock()
		return nil, nil
	}
	e.proxy = *result.Proxy
	e.lastRotationAt = now
	e.nextRotationAt = now.Add(duration)
	info := infoFrom(key, e)
	s.mu.Unlock()

	return info, nil
}

func (s *SessionHandler) runCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		for key, e := range s.sessions {
			if time.Since(e.startedAt) >= e.duration {
				delete(s.sessions, key)
			}
		}
		s.mu.Unlock()
	}
}

func infoFrom(key string, e *stickyEntry) *SessionInfo {
	return &SessionInfo{
		SessionID:      e.sessionID,
		SessionKey:     key,
		Upstream:       fmt.Sprintf("%s:%d", e.proxy.Host, e.proxy.Port),
		CreatedAt:      e.startedAt,
		NextRotationAt: e.nextRotationAt,
		LastRotationAt: e.lastRotationAt,
	}
}
