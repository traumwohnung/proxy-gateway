package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	proxykit "proxy-kit"
)

// recorder collects connRecord/byte tuples for assertions.
type recorder struct {
	mu     sync.Mutex
	closes []recordedClose
}

type recordedClose struct {
	rec      connRecord
	upload   int64
	download int64
	reason   string
}

func (r *recorder) all() []recordedClose {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedClose, len(r.closes))
	copy(out, r.closes)
	return out
}

// captureTracker drops through to a recorder instead of a real analytics
// client. Its record method mirrors UsageTracker.record minus the gRPC
// dispatch.
type captureTracker struct {
	r *recorder
}

func (c *captureTracker) record(rec connRecord, upload, download int64, reason string) {
	if upload == 0 && download == 0 && (reason == "" || reason == "ok") {
		return
	}
	c.r.mu.Lock()
	c.r.closes = append(c.r.closes, recordedClose{rec: rec, upload: upload, download: download, reason: reason})
	c.r.mu.Unlock()
}

// captureConnTracker mirrors usageConnTracker but writes to the recorder.
type captureConnTracker struct {
	t   *captureTracker
	rec connRecord
}

func (c *captureConnTracker) RecordTraffic(_ bool, _ int64, _ func()) {}
func (c *captureConnTracker) Close(sent, received int64, reason string) {
	c.t.record(c.rec, sent, received, reason)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestUsageTracker_RecordSkipsZeroBytes(t *testing.T) {
	r := &recorder{}
	ct := &captureTracker{r: r}
	// nil-client path of the real tracker should not panic.
	(&UsageTracker{client: nil}).record(connRecord{proxyset: "set"}, 0, 0, "ok")
	// And the capture variant skips zero-byte "ok" too.
	ct.record(connRecord{proxyset: "set"}, 0, 0, "ok")
	if len(r.all()) != 0 {
		t.Fatalf("zero-byte record should not emit, got %d", len(r.all()))
	}
}

func TestUsageConnTracker_CloseEmitsOneEvent(t *testing.T) {
	r := &recorder{}
	rec := connRecord{
		connectionID:      "conn-1",
		proxyset:          "datacenter",
		sessionParamsHash: "deadbeef",
		minutes:           60,
		upstreamIP:        "1.2.3.4",
		startedAt:         time.Now().Add(-100 * time.Millisecond).UTC(),
	}
	ct := &captureConnTracker{t: &captureTracker{r: r}, rec: rec}
	ct.Close(1024, 4096, "ok")

	got := r.all()
	if len(got) != 1 {
		t.Fatalf("want 1 close, got %d", len(got))
	}
	c := got[0]
	if c.rec.proxyset != "datacenter" || c.rec.sessionParamsHash != "deadbeef" ||
		c.rec.minutes != 60 || c.upload != 1024 || c.download != 4096 ||
		c.rec.upstreamIP != "1.2.3.4" || c.rec.connectionID != "conn-1" || c.reason != "ok" {
		t.Errorf("record mismatch: %+v upload=%d download=%d reason=%q", c.rec, c.upload, c.download, c.reason)
	}
}

func TestUsageConnTracker_CloseEmitsFailureReasonEvenAtZeroBytes(t *testing.T) {
	r := &recorder{}
	ct := &captureConnTracker{
		t:   &captureTracker{r: r},
		rec: connRecord{connectionID: "x", proxyset: "set", startedAt: time.Now().UTC()},
	}
	ct.Close(0, 0, "upstream_err")

	got := r.all()
	if len(got) != 1 || got[0].reason != "upstream_err" {
		t.Fatalf("want one upstream_err event, got %+v", got)
	}
}

func TestTrackUsageMiddleware_NilTrackerIsNoop(t *testing.T) {
	pipeline := ParseJSONCreds(trackUsage(nil, nil, testProxySource()))
	result, err := pipeline.Resolve(context.Background(), testProxyRequest("residential", ""))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ConnTracker != nil {
		t.Fatal("expected nil ConnTracker when tracker is nil")
	}
}

func TestTrackUsageMiddleware_AttachesConnTrackerWithHash(t *testing.T) {
	tracker := &UsageTracker{client: nil}
	pipeline := ParseJSONCreds(trackUsage(tracker, nil, testProxySource()))
	result, err := pipeline.Resolve(context.Background(), testProxyRequest("residential", `{"user":"alice"}`))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ConnTracker == nil {
		t.Fatal("expected ConnTracker to be set")
	}
	// Reach inside to verify the connRecord was populated correctly.
	ct, ok := result.ConnTracker.(*usageConnTracker)
	if !ok {
		t.Fatalf("ConnTracker is not *usageConnTracker, got %T", result.ConnTracker)
	}
	if ct.rec.proxyset != "residential" {
		t.Errorf("want proxyset=residential, got %q", ct.rec.proxyset)
	}
	if ct.rec.sessionParamsHash == "" {
		t.Error("session_params_hash should be non-empty when affinity meta is set")
	}
	if ct.rec.connectionID == "" {
		t.Error("connection_id should be non-empty")
	}
	if ct.rec.upstreamIP != "upstream" {
		t.Errorf("want upstreamIP=upstream, got %q", ct.rec.upstreamIP)
	}
	if ct.rec.epoch != 0 {
		t.Errorf("want epoch=0 in slice 1, got %d", ct.rec.epoch)
	}
	// Close on a tracker with nil client should not panic.
	result.ConnTracker.Close(100, 200, "ok")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testProxySource() proxykit.Handler {
	return proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		return proxykit.Resolved(&proxykit.Proxy{Host: "upstream", Port: 8080}), nil
	})
}

func testProxyRequest(set, meta string) *proxykit.Request {
	var username string
	if meta == "" {
		username = fmt.Sprintf(`{"set":%q,"minutes":5}`, set)
	} else {
		username = fmt.Sprintf(`{"set":%q,"minutes":5,"affinity":%s}`, set, meta)
	}
	return &proxykit.Request{RawUsername: username}
}
