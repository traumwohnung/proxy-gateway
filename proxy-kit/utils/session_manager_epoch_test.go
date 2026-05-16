package utils

import (
	"context"
	"sync"
	"testing"
	"time"

	proxykit "proxy-kit"
)

// recordingListener captures every EpochEvent for assertions.
type recordingListener struct {
	mu     sync.Mutex
	events []EpochEvent
}

func (r *recordingListener) OnEpochTransition(ev EpochEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *recordingListener) snapshot() []EpochEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]EpochEvent, len(r.events))
	copy(out, r.events)
	return out
}

// ipRollingSource hands out a different IP on each Resolve call so
// transitions can be observed by their NewIP.
type ipRollingSource struct {
	mu  sync.Mutex
	n   int
	ips []string
}

func (s *ipRollingSource) Resolve(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip := s.ips[s.n%len(s.ips)]
	s.n++
	return proxykit.Resolved(&proxykit.Proxy{Host: ip, Port: 8080}), nil
}

func ctxWithSession(hash, params, proxyset string, ttl time.Duration, seed uint64) context.Context {
	ctx := context.Background()
	ctx = WithTopLevelSeed(ctx, seed)
	ctx = WithSeedTTL(ctx, ttl)
	ctx = WithSessionParamsHash(ctx, hash)
	ctx = WithSessionParamsJSON(ctx, params)
	ctx = WithProxysetName(ctx, proxyset)
	return ctx
}

func TestEpochListener_FirstBindEmitsZeroEpoch(t *testing.T) {
	src := &ipRollingSource{ips: []string{"10.0.0.1"}}
	rec := &recordingListener{}
	sm := NewSessionManagerWithListener(src, rec)

	ctx := ctxWithSession("hashA", `{"u":"alice"}`, "residential", time.Minute, 12345)
	if _, err := sm.Resolve(ctx, &proxykit.Request{}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	evs := rec.snapshot()
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
	ev := evs[0]
	if ev.StartReason != "first_bind" {
		t.Errorf("start_reason: want first_bind, got %q", ev.StartReason)
	}
	if ev.PrevEpoch != -1 || ev.NewEpoch != 0 {
		t.Errorf("epochs: want prev=-1 new=0, got prev=%d new=%d", ev.PrevEpoch, ev.NewEpoch)
	}
	if ev.NewIP != "10.0.0.1" || ev.PrevIP != "" {
		t.Errorf("ips: want new=10.0.0.1 prev=empty, got new=%q prev=%q", ev.NewIP, ev.PrevIP)
	}
	if ev.SessionParamsHash != "hashA" || ev.ParamsJSON != `{"u":"alice"}` {
		t.Errorf("identity: hash=%q params=%q", ev.SessionParamsHash, ev.ParamsJSON)
	}
}

func TestEpochListener_RotateNowEmitsForcedAndBumpsEpoch(t *testing.T) {
	src := &ipRollingSource{ips: []string{"10.0.0.1", "10.0.0.2"}}
	rec := &recordingListener{}
	sm := NewSessionManagerWithListener(src, rec)

	ctx := ctxWithSession("hashA", `{"u":"alice"}`, "residential", time.Minute, 7777)
	if _, err := sm.Resolve(ctx, &proxykit.Request{}); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	info, err := sm.RotateNow(7777)
	if err != nil || info == nil {
		t.Fatalf("rotate: info=%v err=%v", info, err)
	}

	evs := rec.snapshot()
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	rot := evs[1]
	if rot.StartReason != "forced" {
		t.Errorf("start_reason: want forced, got %q", rot.StartReason)
	}
	if rot.PrevEpoch != 0 || rot.NewEpoch != 1 {
		t.Errorf("epochs: want prev=0 new=1, got prev=%d new=%d", rot.PrevEpoch, rot.NewEpoch)
	}
	if rot.PrevIP != "10.0.0.1" || rot.NewIP != "10.0.0.2" {
		t.Errorf("ips: want prev=10.0.0.1 new=10.0.0.2, got prev=%q new=%q", rot.PrevIP, rot.NewIP)
	}
	// ParamsJSON should NOT be re-sent on rotations (only first_bind carries it).
	if rot.ParamsJSON != "" {
		t.Errorf("params_json should be empty on non-first_bind, got %q", rot.ParamsJSON)
	}
	if info.Epoch != 1 {
		t.Errorf("SessionInfo.Epoch: want 1, got %d", info.Epoch)
	}
}

func TestEpochListener_TTLEvictThenResolveEmitsTTLReason(t *testing.T) {
	src := &ipRollingSource{ips: []string{"10.0.0.1", "10.0.0.2"}}
	rec := &recordingListener{}
	sm := NewSessionManagerWithListener(src, rec)

	// First resolve creates the entry.
	ctx := ctxWithSession("hashA", `{"u":"alice"}`, "residential", time.Millisecond, 4242)
	if _, err := sm.Resolve(ctx, &proxykit.Request{}); err != nil {
		t.Fatalf("resolve1: %v", err)
	}
	// Wait for the entry to expire (TTL is 1ms).
	time.Sleep(20 * time.Millisecond)

	// Manually evict, bypassing the 60s cleanup goroutine.
	sm.mu.Lock()
	delete(sm.entries, 4242)
	sm.mu.Unlock()

	// Second resolve creates a fresh entry; hashState[hashA] survives so
	// the new event must carry start_reason="ttl" with prev_epoch=0.
	if _, err := sm.Resolve(ctx, &proxykit.Request{}); err != nil {
		t.Fatalf("resolve2: %v", err)
	}

	evs := rec.snapshot()
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	second := evs[1]
	if second.StartReason != "ttl" {
		t.Errorf("start_reason: want ttl, got %q", second.StartReason)
	}
	if second.PrevEpoch != 0 || second.NewEpoch != 1 {
		t.Errorf("epochs: want prev=0 new=1, got prev=%d new=%d", second.PrevEpoch, second.NewEpoch)
	}
	if second.PrevIP != "10.0.0.1" || second.NewIP != "10.0.0.2" {
		t.Errorf("ips: prev=%q new=%q", second.PrevIP, second.NewIP)
	}
}

func TestEpochListener_NoEmissionWithoutHash(t *testing.T) {
	src := &ipRollingSource{ips: []string{"10.0.0.1"}}
	rec := &recordingListener{}
	sm := NewSessionManagerWithListener(src, rec)

	// No WithSessionParamsHash → no analytics emission.
	ctx := context.Background()
	ctx = WithTopLevelSeed(ctx, 9999)
	ctx = WithSeedTTL(ctx, time.Minute)

	if _, err := sm.Resolve(ctx, &proxykit.Request{}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("expected no events when hash is empty, got %d", len(rec.snapshot()))
	}
}
