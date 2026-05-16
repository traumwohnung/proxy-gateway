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
	ctxSessionParamsHash
	ctxProxysetName
	ctxSessionParamsJSON
	ctxProviderName
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

// WithSessionParamsHash stores the analytics hash (first 16 bytes of
// SHA-256 over the canonical JSON of the session params, hex-encoded).
// The SessionManager uses this as the key for per-hash epoch tracking and
// includes it in EpochEvent payloads. Set this in your auth/parse middleware
// alongside WithTopLevelSeed.
func WithSessionParamsHash(ctx context.Context, hash string) context.Context {
	return context.WithValue(ctx, ctxSessionParamsHash, hash)
}

// GetSessionParamsHash reads the session_params_hash from context.
func GetSessionParamsHash(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionParamsHash).(string)
	return v
}

// WithProxysetName stores the human-readable proxyset name. Used only as
// metadata on EpochEvents; the SessionManager itself doesn't read it for
// dispatch.
func WithProxysetName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxProxysetName, name)
}

// GetProxysetName reads the proxyset name from context.
func GetProxysetName(ctx context.Context) string {
	v, _ := ctx.Value(ctxProxysetName).(string)
	return v
}

// WithSessionParamsJSON stores the canonical JSON of the session params.
// Carried on EpochEvents with start_reason="first_bind" so the analytics
// server can backfill session_params_dim.params_json.
func WithSessionParamsJSON(ctx context.Context, json string) context.Context {
	return context.WithValue(ctx, ctxSessionParamsJSON, json)
}

// GetSessionParamsJSON reads the canonical session params JSON from context.
func GetSessionParamsJSON(ctx context.Context) string {
	v, _ := ctx.Value(ctxSessionParamsJSON).(string)
	return v
}

// WithProviderName stores the upstream provider identifier (e.g.
// "bottingtools", "geonode", "static_file"). Threaded into EpochEvents and
// per-connection records.
func WithProviderName(ctx context.Context, provider string) context.Context {
	return context.WithValue(ctx, ctxProviderName, provider)
}

// GetProviderName reads the provider identifier from context.
func GetProviderName(ctx context.Context) string {
	v, _ := ctx.Value(ctxProviderName).(string)
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
	Epoch          int32     `json:"epoch"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	LastRotationAt time.Time `json:"last_rotation_at"`
}

// ---------------------------------------------------------------------------
// EpochListener — analytics hook
// ---------------------------------------------------------------------------

// EpochEvent describes an IP-binding transition for a logical session. It is
// emitted whenever the IP associated with a session_params_hash changes.
//
// PrevEpoch is -1 on first_bind; PrevIP is empty on first_bind.
type EpochEvent struct {
	SessionParamsHash string
	// ParamsJSON is the canonical JSON of the session params. Populated on
	// first_bind so the consumer can backfill any identity tables; empty on
	// subsequent transitions.
	ParamsJSON   string
	ProxysetName string
	ProviderName string
	PrevEpoch    int32
	NewEpoch     int32
	PrevIP       string
	NewIP        string
	// first_bind | ttl | forced
	StartReason string
}

// EpochListener receives an event each time the SessionManager binds a new
// IP to a session. The callback runs synchronously inside SessionManager —
// it must be non-blocking (e.g. enqueue to an analytics client).
type EpochListener interface {
	OnEpochTransition(ev EpochEvent)
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
	epoch          int32  // current IP-binding generation, monotonic per hash
	hash           string // session_params_hash captured at create-time
	proxyset       string // proxyset name captured at create-time
	provider       string // provider name captured at create-time
	resolveCtx     context.Context
	startedAt      time.Time
	expiresAt      time.Time
	lastRotationAt time.Time
	duration       time.Duration
}

// hashState tracks the last-known epoch and IP for a given session hash so
// that epoch numbering remains monotonic across TTL evictions. Entries here
// outlive sessionEntry: when an entry is evicted by the cleanup goroutine,
// hashState[hash] survives so the next Resolve emits ttl→epoch=N+1, not a
// fresh first_bind→epoch=0.
type hashState struct {
	lastEpoch int32
	lastIP    string
}

// SessionManager is Handler middleware that combines a top-level seed (uint64),
// a TTL, and a rotation counter into a deterministic *proxykit.SessionSeed.
//
// It also tracks IP-binding generations (epochs) per session_params_hash and,
// when configured with an EpochListener, fires an event on each transition.
type SessionManager struct {
	next     proxykit.Handler
	listener EpochListener

	mu          sync.RWMutex
	entries     map[uint64]*sessionEntry
	hashState   map[string]*hashState
	nextID      atomic.Uint64
}

// NewSessionManager creates a SessionManager wrapping the given next handler.
// A cleanup goroutine prunes expired entries every 60 seconds.
func NewSessionManager(next proxykit.Handler) *SessionManager {
	return NewSessionManagerWithListener(next, nil)
}

// NewSessionManagerWithListener is like NewSessionManager but also installs
// an EpochListener that receives an event on every IP-binding transition.
func NewSessionManagerWithListener(next proxykit.Handler, listener EpochListener) *SessionManager {
	m := &SessionManager{
		next:      next,
		listener:  listener,
		entries:   make(map[uint64]*sessionEntry),
		hashState: make(map[string]*hashState),
	}
	go m.runCleanup()
	return m
}

// SetEpochListener installs (or replaces) the EpochListener. Safe to call
// before the manager is in use; not safe to call concurrently with Resolve.
func (m *SessionManager) SetEpochListener(l EpochListener) {
	m.listener = l
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

	hash := GetSessionParamsHash(ctx)
	proxyset := GetProxysetName(ctx)
	provider := GetProviderName(ctx)
	newIP := result.Proxy.Host
	now := time.Now().UTC()

	m.mu.Lock()
	if existing, ok := m.entries[tls]; ok && time.Now().Before(existing.expiresAt) {
		p := existing.proxy
		m.mu.Unlock()
		return proxykit.Resolved(&p), nil
	}

	var ev *EpochEvent
	if hash != "" {
		prev, hadPrev := m.hashState[hash]
		var newEpoch int32
		startReason := "first_bind"
		prevEpoch := int32(-1)
		prevIP := ""
		if hadPrev {
			newEpoch = prev.lastEpoch + 1
			prevEpoch = prev.lastEpoch
			prevIP = prev.lastIP
			startReason = "ttl"
		}
		m.hashState[hash] = &hashState{lastEpoch: newEpoch, lastIP: newIP}
		paramsJSON := ""
		if startReason == "first_bind" {
			paramsJSON = GetSessionParamsJSON(ctx)
		}
		ev = &EpochEvent{
			SessionParamsHash: hash,
			ParamsJSON:        paramsJSON,
			ProxysetName:      proxyset,
			ProviderName:      provider,
			PrevEpoch:         prevEpoch,
			NewEpoch:          newEpoch,
			PrevIP:            prevIP,
			NewIP:             newIP,
			StartReason:       startReason,
		}
	}

	ne := &sessionEntry{
		id:             m.nextID.Add(1) - 1,
		label:          GetSessionLabel(ctx),
		proxy:          *result.Proxy,
		seed:           seed,
		rotation:       rotation,
		hash:           hash,
		proxyset:       proxyset,
		provider:       provider,
		resolveCtx:     ctx,
		startedAt:      now,
		expiresAt:      now.Add(ttl),
		lastRotationAt: now,
		duration:       ttl,
	}
	if ev != nil {
		ne.epoch = ev.NewEpoch
	}
	m.entries[tls] = ne
	m.mu.Unlock()

	if ev != nil && m.listener != nil {
		m.listener.OnEpochTransition(*ev)
	}

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
	newIP := result.Proxy.Host
	var ev *EpochEvent

	m.mu.Lock()
	e, ok = m.entries[topLevelSeed]
	if !ok {
		m.mu.Unlock()
		return nil, nil
	}

	if e.hash != "" {
		prev, hadPrev := m.hashState[e.hash]
		var newEpoch int32
		var prevEpoch int32
		var prevIP string
		if hadPrev {
			newEpoch = prev.lastEpoch + 1
			prevEpoch = prev.lastEpoch
			prevIP = prev.lastIP
		} else {
			// Defensive: entry without hashState shouldn't happen, but
			// recover by treating as first_bind-style numbering.
			newEpoch = 0
			prevEpoch = -1
		}
		m.hashState[e.hash] = &hashState{lastEpoch: newEpoch, lastIP: newIP}
		e.epoch = newEpoch
		ev = &EpochEvent{
			SessionParamsHash: e.hash,
			ProxysetName:      e.proxyset,
			ProviderName:      e.provider,
			PrevEpoch:         prevEpoch,
			NewEpoch:          newEpoch,
			PrevIP:            prevIP,
			NewIP:             newIP,
			StartReason:       "forced",
		}
	}

	e.proxy = *result.Proxy
	e.seed = seed
	e.rotation = nextRotation
	e.lastRotationAt = now
	e.expiresAt = now.Add(duration)
	info := sessionInfoFrom(topLevelSeed, e)
	m.mu.Unlock()

	if ev != nil && m.listener != nil {
		m.listener.OnEpochTransition(*ev)
	}

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
		Epoch:          e.epoch,
		CreatedAt:      e.startedAt,
		ExpiresAt:      e.expiresAt,
		LastRotationAt: e.lastRotationAt,
	}
}
