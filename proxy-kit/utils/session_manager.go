package utils

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"proxy-kit"
)

// ---------------------------------------------------------------------------
// Context helpers — top-level seed & TTL
// ---------------------------------------------------------------------------

type sessionMgrCtxKey int

const (
	ctxTopLevelSeed sessionMgrCtxKey = iota
	ctxSeedTTL
	ctxSessionLabel
)

// WithTopLevelSeed stores the top-level seed in context.
// This is a uint64 derived from affinity params (e.g. hash of "alice\x00residential").
// The SessionManager mixes it with the rotation counter to produce a
// *proxykit.SessionSeed.
func WithTopLevelSeed(ctx context.Context, seed uint64) context.Context {
	return context.WithValue(ctx, ctxTopLevelSeed, seed)
}

// GetTopLevelSeed reads the top-level seed from context.
// Returns 0 if not set.
func GetTopLevelSeed(ctx context.Context) uint64 {
	v, _ := ctx.Value(ctxTopLevelSeed).(uint64)
	return v
}

// WithSeedTTL stores the seed TTL in context. Controls how long the
// SessionManager caches a resolved proxy for a given top-level seed.
func WithSeedTTL(ctx context.Context, ttl time.Duration) context.Context {
	return context.WithValue(ctx, ctxSeedTTL, ttl)
}

// GetSeedTTL reads the seed TTL from context.
func GetSeedTTL(ctx context.Context) time.Duration {
	v, _ := ctx.Value(ctxSeedTTL).(time.Duration)
	return v
}

// WithSessionLabel stores an opaque label in context that the SessionManager
// attaches to the session entry. Useful for API introspection (e.g. returning
// the original username string).
func WithSessionLabel(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, ctxSessionLabel, label)
}

// GetSessionLabel reads the session label from context.
func GetSessionLabel(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionLabel).(string)
	return v
}

// ---------------------------------------------------------------------------
// SessionInfo — introspection
// ---------------------------------------------------------------------------

// SessionInfo describes an active session managed by SessionManager.
type SessionInfo struct {
	ID             uint64    `json:"id"`
	Label          string    `json:"label"`
	TopLevelSeed   uint64    `json:"top_level_seed"`
	Upstream       string    `json:"upstream"`
	Seed           uint64    `json:"seed"`
	Rotation       uint64    `json:"rotation"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	LastRotationAt time.Time `json:"last_rotation_at"`
}

// ---------------------------------------------------------------------------
// SessionManager — Handler middleware
// ---------------------------------------------------------------------------

type sessionEntry struct {
	id             uint64
	label          string
	proxy          proxykit.Proxy
	seed           *proxykit.SessionSeed
	rotation       uint64
	resolveCtx     context.Context // carries domain values for re-resolve on managed rotate
	startedAt      time.Time
	expiresAt      time.Time
	lastRotationAt time.Time
	duration       time.Duration
}

// SessionManager is Handler middleware that combines a top-level seed (uint64),
// a TTL, and a rotation counter into a deterministic *proxykit.SessionSeed.
//
// It reads GetTopLevelSeed/GetSeedTTL from context and:
//
//   - TTL > 0: looks up its cache keyed by the top-level seed. On hit, returns
//     the cached proxy. On miss, picks a random rotation, computes
//     SessionSeed = hash(topLevelSeed + rotation), stores it in context
//     via proxykit.WithSessionSeed, calls next, and caches the result.
//   - TTL = 0 or zero seed: passes through with no SessionSeed in context (nil).
//     Sources decide what nil means for their domain.
//
// RotateNow re-rolls rotation to a fresh random uint64 → new
// SessionSeed → new source choices.
type SessionManager struct {
	next    proxykit.Handler
	mu      sync.RWMutex
	entries map[uint64]*sessionEntry
	nextID  atomic.Uint64
}

// NewSessionManager creates a SessionManager wrapping the given next handler.
// A cleanup goroutine prunes expired entries every 60 seconds.
func NewSessionManager(next proxykit.Handler) *SessionManager {
	m := &SessionManager{
		next:    next,
		entries: make(map[uint64]*sessionEntry),
	}
	go m.runCleanup()
	return m
}

// Resolve implements proxykit.Handler.
func (m *SessionManager) Resolve(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
	tls := GetTopLevelSeed(ctx)
	ttl := GetSeedTTL(ctx)
	if ttl <= 0 || tls == 0 {
		return m.next.Resolve(ctx, req)
	}

	m.mu.RLock()
	e, ok := m.entries[tls]
	if ok && time.Now().Before(e.expiresAt) {
		p := e.proxy
		m.mu.RUnlock()
		return proxykit.Resolved(&p), nil
	}
	m.mu.RUnlock()

	rotation := rand.Uint64()
	seed := proxykit.NewSessionSeed(tls, rotation)
	ctx = proxykit.WithSessionSeed(ctx, seed)

	result, err := m.next.Resolve(ctx, req)
	if err != nil || result == nil || result.Proxy == nil {
		return result, err
	}

	now := time.Now().UTC()
	ne := &sessionEntry{
		id:             m.nextID.Add(1) - 1,
		label:          GetSessionLabel(ctx),
		proxy:          *result.Proxy,
		seed:           seed,
		rotation:       rotation,
		resolveCtx:     ctx,
		startedAt:      now,
		expiresAt:      now.Add(ttl),
		lastRotationAt: now,
		duration:       ttl,
	}

	m.mu.Lock()
	if existing, ok := m.entries[tls]; ok && time.Now().Before(existing.expiresAt) {
		p := existing.proxy
		m.mu.Unlock()
		return proxykit.Resolved(&p), nil
	}
	m.entries[tls] = ne
	m.mu.Unlock()

	return result, nil
}

// RotateNow re-rolls the rotation for the given top-level seed to a
// fresh random uint64, producing a new SessionSeed, and re-resolves
// through the source using the stored context.
func (m *SessionManager) RotateNow(topLevelSeed uint64) (*SessionInfo, error) {
	m.mu.RLock()
	e, ok := m.entries[topLevelSeed]
	if !ok || !time.Now().Before(e.expiresAt) {
		m.mu.RUnlock()
		return nil, nil
	}
	nextRotation := rand.Uint64()
	resolveCtx := e.resolveCtx
	duration := e.duration
	m.mu.RUnlock()

	seed := proxykit.NewSessionSeed(topLevelSeed, nextRotation)
	resolveCtx = proxykit.WithSessionSeed(resolveCtx, seed)

	result, err := m.next.Resolve(resolveCtx, &proxykit.Request{})
	if err != nil || result == nil || result.Proxy == nil {
		return nil, err
	}

	now := time.Now().UTC()
	m.mu.Lock()
	e, ok = m.entries[topLevelSeed]
	if !ok {
		m.mu.Unlock()
		return nil, nil
	}
	e.proxy = *result.Proxy
	e.seed = seed
	e.rotation = nextRotation
	e.lastRotationAt = now
	e.expiresAt = now.Add(duration)
	info := sessionInfoFrom(topLevelSeed, e)
	m.mu.Unlock()

	return info, nil
}

// GetSession returns info about an active session, or nil.
func (m *SessionManager) GetSession(topLevelSeed uint64) *SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[topLevelSeed]
	if !ok || !time.Now().Before(e.expiresAt) {
		return nil
	}
	return sessionInfoFrom(topLevelSeed, e)
}

// ListEntries returns info about all active sessions.
func (m *SessionManager) ListEntries() []SessionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	var out []SessionInfo
	for tls, e := range m.entries {
		if now.Before(e.expiresAt) {
			out = append(out, *sessionInfoFrom(tls, e))
		}
	}
	return out
}

func (m *SessionManager) runCleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for tls, e := range m.entries {
			if !now.Before(e.expiresAt) {
				delete(m.entries, tls)
			}
		}
		m.mu.Unlock()
	}
}

func sessionInfoFrom(topLevelSeed uint64, e *sessionEntry) *SessionInfo {
	var seed uint64
	if e.seed != nil {
		seed = e.seed.Value()
	}
	return &SessionInfo{
		ID:             e.id,
		Label:          e.label,
		TopLevelSeed:   topLevelSeed,
		Upstream:       fmt.Sprintf("%s:%d", e.proxy.Host, e.proxy.Port),
		Seed:           seed,
		Rotation:       e.rotation,
		CreatedAt:      e.startedAt,
		ExpiresAt:      e.expiresAt,
		LastRotationAt: e.lastRotationAt,
	}
}
