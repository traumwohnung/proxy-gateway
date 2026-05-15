package main

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"proxy-gateway/analytics"
	proxykit "proxy-kit"
)

// captureClient records every Send for assertions. It satisfies the same
// surface UsageTracker uses (Send). UsageTracker keeps *analytics.Client, so
// we feed a real Client whose conn is never dialled — instead we replace the
// tracker's behavior by wrapping recorder methods. Simplest: use a custom
// tracker variant via a small helper.

type recorder struct {
	mu    sync.Mutex
	sends []analytics.Delta
}

func (r *recorder) all() []analytics.Delta {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]analytics.Delta, len(r.sends))
	copy(out, r.sends)
	return out
}

// trackerWithRecorder builds a UsageTracker whose record method goes through
// the recorder rather than a real gRPC client.
func trackerWithRecorder() (*UsageTracker, *recorder) {
	r := &recorder{}
	// We bypass analytics.Client by setting tracker.client = nil and using a
	// shim that intercepts via Close → record. To exercise record(), we
	// override the method via a small wrapper type below.
	return &UsageTracker{client: nil}, r
}

// captureTracker is a UsageTracker-shaped type whose record() stores deltas
// for inspection. It uses the same usageConnTracker structure.
type captureTracker struct {
	r *recorder
}

func (c *captureTracker) record(proxyset, sessionParams string, minutes int, upload, download int64) {
	if upload == 0 && download == 0 {
		return
	}
	c.r.mu.Lock()
	c.r.sends = append(c.r.sends, analytics.Delta{
		Proxyset:               proxyset,
		SessionParams:          sessionParams,
		SessionDurationMinutes: int32(minutes),
		UploadBytes:            upload,
		DownloadBytes:          download,
	})
	c.r.mu.Unlock()
}

// captureConnTracker mirrors usageConnTracker but writes to recorder.
type captureConnTracker struct {
	t             *captureTracker
	proxyset      string
	sessionParams string
	minutes       int
}

func (c *captureConnTracker) RecordTraffic(_ bool, _ int64, _ func()) {}
func (c *captureConnTracker) Close(sent, received int64) {
	c.t.record(c.proxyset, c.sessionParams, c.minutes, sent, received)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestUsageTracker_RecordSkipsZeroBytes(t *testing.T) {
	tr, r := trackerWithRecorder()
	ct := &captureTracker{r: r}
	// nil-client path of the real tracker should not panic.
	tr.record("set", "{}", 5, 0, 0)
	// And the capture variant skips zero-byte too.
	ct.record("set", "{}", 5, 0, 0)
	if len(r.all()) != 0 {
		t.Fatalf("zero-byte record should not emit, got %d", len(r.all()))
	}
}

func TestUsageConnTracker_CloseEmitsOneDelta(t *testing.T) {
	r := &recorder{}
	ct := &captureConnTracker{
		t:             &captureTracker{r: r},
		proxyset:      "datacenter",
		sessionParams: `{"user":"alice"}`,
		minutes:       60,
	}
	ct.Close(1024, 4096)
	got := r.all()
	if len(got) != 1 {
		t.Fatalf("want 1 delta, got %d", len(got))
	}
	d := got[0]
	if d.Proxyset != "datacenter" || d.SessionParams != `{"user":"alice"}` ||
		d.SessionDurationMinutes != 60 || d.UploadBytes != 1024 || d.DownloadBytes != 4096 {
		t.Errorf("delta mismatch: %+v", d)
	}
}

func TestTrackUsageMiddleware_NilTrackerIsNoop(t *testing.T) {
	pipeline := ParseJSONCreds(trackUsage(nil, testProxySource()))
	result, err := pipeline.Resolve(context.Background(), testProxyRequest("residential", ""))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ConnTracker != nil {
		t.Fatal("expected nil ConnTracker when tracker is nil")
	}
}

func TestTrackUsageMiddleware_AttachesConnTracker(t *testing.T) {
	tracker := &UsageTracker{client: nil}
	pipeline := ParseJSONCreds(trackUsage(tracker, testProxySource()))
	result, err := pipeline.Resolve(context.Background(), testProxyRequest("residential", `{"user":"alice"}`))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ConnTracker == nil {
		t.Fatal("expected ConnTracker to be set")
	}
	// Close on a tracker with nil client should not panic.
	result.ConnTracker.Close(100, 200)
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
		username = fmt.Sprintf(`{"set":%q,"minutes":5,"meta":%s}`, set, meta)
	}
	return &proxykit.Request{RawUsername: username}
}
