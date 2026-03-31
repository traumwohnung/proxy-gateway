package main

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	proxykit "proxy-kit"
	db "proxy-gateway/db/gen"
)

// usageRow mirrors a row from the usage table for test assertions.
type usageRow struct {
	HourTS         time.Time
	Proxyset       string
	AffinityParams string // raw JSON
	UploadBytes    int64
	DownloadBytes  int64
}

func readBuckets(t *testing.T, pool *pgxpool.Pool) []usageRow {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT hour_ts, proxyset, affinity_params, upload_bytes, download_bytes FROM usage ORDER BY id`)
	if err != nil {
		t.Fatalf("readBuckets query: %v", err)
	}
	defer rows.Close()

	var out []usageRow
	for rows.Next() {
		var r usageRow
		var ap []byte
		if err := rows.Scan(&r.HourTS, &r.Proxyset, &ap, &r.UploadBytes, &r.DownloadBytes); err != nil {
			t.Fatalf("readBuckets scan: %v", err)
		}
		r.AffinityParams = string(ap)
		out = append(out, r)
	}
	return out
}

// ---------------------------------------------------------------------------
// Unit tests (no DB)
// ---------------------------------------------------------------------------

func TestUsageTracker_RecordAggregatesDeltas(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}

	tracker.record("residential", `{}`, 100, 200)
	tracker.record("residential", `{}`, 50, 75)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var found bool
	for k, v := range tracker.deltas {
		if k.Proxyset == "residential" {
			found = true
			if v[0] != 150 {
				t.Errorf("upload want 150 got %d", v[0])
			}
			if v[1] != 275 {
				t.Errorf("download want 275 got %d", v[1])
			}
		}
	}
	if !found {
		t.Fatal("expected residential bucket")
	}
}

func TestUsageTracker_DifferentProxysetsAreSeparateBuckets(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}

	tracker.record("residential", `{}`, 100, 0)
	tracker.record("datacenter", `{}`, 0, 200)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if len(tracker.deltas) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(tracker.deltas))
	}
}

func TestUsageTracker_DifferentAffinityParamsAreSeparateBuckets(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}

	tracker.record("residential", `{"user":"alice"}`, 100, 0)
	tracker.record("residential", `{"user":"bob"}`, 100, 0)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if len(tracker.deltas) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(tracker.deltas))
	}
}

func TestUsageTracker_ZeroBytesSkipped(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}

	tracker.record("residential", `{}`, 0, 0)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	if len(tracker.deltas) != 0 {
		t.Fatal("zero-byte record should not create a bucket")
	}
}

func TestUsageTracker_FlushSwapsMap(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}

	tracker.record("residential", `{}`, 100, 200)

	tracker.mu.Lock()
	pending := tracker.deltas
	tracker.deltas = make(map[bucketKey][2]int64)
	tracker.mu.Unlock()

	if len(pending) != 1 {
		t.Fatal("expected pending to have 1 bucket")
	}
	if len(tracker.deltas) != 0 {
		t.Fatal("expected deltas to be empty after swap")
	}
}

func TestUsageConnTracker_CloseRecordsBytes(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}
	ct := &usageConnTracker{
		tracker:        tracker,
		proxyset:       "datacenter",
		affinityParams: `{"user":"test"}`,
	}

	ct.Close(512, 1024)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var found bool
	for k, v := range tracker.deltas {
		if k.Proxyset == "datacenter" {
			found = true
			if v[0] != 512 {
				t.Errorf("upload want 512 got %d", v[0])
			}
			if v[1] != 1024 {
				t.Errorf("download want 1024 got %d", v[1])
			}
		}
	}
	if !found {
		t.Fatal("expected datacenter bucket")
	}
}

// ---------------------------------------------------------------------------
// E2E tests (real embedded Postgres)
// ---------------------------------------------------------------------------

func TestUsageTracker_E2E_FlushWritesToDB(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)

	tracker.record("residential", `{}`, 1000, 2000)
	tracker.flush(context.Background())

	buckets := readBuckets(t, pool)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(buckets))
	}
	b := buckets[0]
	if b.Proxyset != "residential" {
		t.Errorf("proxyset want residential got %q", b.Proxyset)
	}
	if b.UploadBytes != 1000 {
		t.Errorf("upload want 1000 got %d", b.UploadBytes)
	}
	if b.DownloadBytes != 2000 {
		t.Errorf("download want 2000 got %d", b.DownloadBytes)
	}
	if b.HourTS.IsZero() {
		t.Error("hour_ts should not be zero")
	}
}

func TestUsageTracker_E2E_UpsertAccumulatesAcrossFlushes(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)
	ctx := context.Background()

	tracker.record("datacenter", `{}`, 100, 200)
	tracker.flush(ctx)

	tracker.record("datacenter", `{}`, 50, 75)
	tracker.flush(ctx)

	buckets := readBuckets(t, pool)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket after two flushes, got %d", len(buckets))
	}
	b := buckets[0]
	if b.UploadBytes != 150 {
		t.Errorf("accumulated upload want 150 got %d", b.UploadBytes)
	}
	if b.DownloadBytes != 275 {
		t.Errorf("accumulated download want 275 got %d", b.DownloadBytes)
	}
}

func TestUsageTracker_E2E_DifferentProxysetsAreSeparateBuckets(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)
	ctx := context.Background()

	tracker.record("residential", `{}`, 100, 0)
	tracker.record("datacenter", `{}`, 0, 200)
	tracker.flush(ctx)

	buckets := readBuckets(t, pool)
	if len(buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(buckets))
	}
}

func TestUsageTracker_E2E_AffinityParamsJSONBDeepMatch(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)
	ctx := context.Background()

	// Write with key order {"a":1,"b":2}
	tracker.record("residential", `{"a":1,"b":2}`, 100, 0)
	tracker.flush(ctx)

	// Write again with different key order — Postgres JSONB treats these as
	// equal so it must accumulate into the same bucket.
	tracker.record("residential", `{"b":2,"a":1}`, 50, 0)
	tracker.flush(ctx)

	buckets := readBuckets(t, pool)
	if len(buckets) != 1 {
		t.Fatalf("JSONB deep-match: expected 1 bucket, got %d", len(buckets))
	}
	if buckets[0].UploadBytes != 150 {
		t.Errorf("JSONB deep-match: upload want 150 got %d", buckets[0].UploadBytes)
	}
}

func TestUsageTracker_E2E_AffinityParamsStoredAsJSONB(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)
	ctx := context.Background()

	meta := `{"platform":"ios","user":"alice"}`
	tracker.record("residential", meta, 512, 1024)
	tracker.flush(ctx)

	buckets := readBuckets(t, pool)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(buckets))
	}

	// Parse back — JSONB may reorder keys so check by value not string equality.
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(buckets[0].AffinityParams), &parsed); err != nil {
		t.Fatalf("affinity_params is not valid JSON: %v", err)
	}
	if parsed["user"] != "alice" {
		t.Errorf("expected user=alice, got %v", parsed["user"])
	}
	if parsed["platform"] != "ios" {
		t.Errorf("expected platform=ios, got %v", parsed["platform"])
	}
}

func TestUsageTracker_E2E_RunFlushesEverySecond(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go tracker.Run(ctx)

	tracker.record("residential", `{}`, 100, 200)

	// Wait up to 3 seconds for the ticker to fire.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		buckets := readBuckets(t, pool)
		if len(buckets) > 0 {
			cancel()
			b := buckets[0]
			if b.UploadBytes != 100 || b.DownloadBytes != 200 {
				t.Errorf("want up=100 down=200, got up=%d down=%d", b.UploadBytes, b.DownloadBytes)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("timed out waiting for flush")
}

func TestUsageTracker_E2E_RunFinalFlushOnShutdown(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)

	ctx, cancel := context.WithCancel(context.Background())

	go tracker.Run(ctx)

	// Record bytes then cancel immediately — Run's final flush must commit them.
	tracker.record("residential", `{}`, 999, 888)
	cancel()

	// Give Run() a moment to execute the final flush.
	time.Sleep(200 * time.Millisecond)

	buckets := readBuckets(t, pool)
	if len(buckets) == 0 {
		t.Fatal("final flush on shutdown should have written to DB")
	}
	b := buckets[0]
	if b.UploadBytes != 999 || b.DownloadBytes != 888 {
		t.Errorf("want up=999 down=888, got up=%d down=%d", b.UploadBytes, b.DownloadBytes)
	}
}

func TestUsageTracker_E2E_HourBucketTruncation(t *testing.T) {
	pool := newTestDB(t)
	queries := db.New(pool)
	tracker := NewUsageTracker(queries)

	tracker.record("residential", `{}`, 1, 1)
	tracker.flush(context.Background())

	buckets := readBuckets(t, pool)
	if len(buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(buckets))
	}

	hourTS := buckets[0].HourTS.UTC()
	if hourTS.Minute() != 0 || hourTS.Second() != 0 || hourTS.Nanosecond() != 0 {
		t.Errorf("hour_ts not truncated to hour: %v", hourTS)
	}
}

// ---------------------------------------------------------------------------
// Pipeline integration: trackUsage middleware wires bytes into tracker
// ---------------------------------------------------------------------------

func TestTrackUsageMiddleware_PopulatesConnTracker(t *testing.T) {
	tracker := &UsageTracker{deltas: make(map[bucketKey][2]int64)}

	pipeline := ParseJSONCreds(trackUsage(tracker, testProxySource()))

	result, err := pipeline.Resolve(context.Background(), testProxyRequest("residential", `{"user":"alice"}`))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ConnTracker == nil {
		t.Fatal("expected ConnTracker to be set on result")
	}

	// Simulate connection close.
	result.ConnTracker.Close(1024, 4096)

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	var found bool
	for k, v := range tracker.deltas {
		if k.Proxyset == "residential" {
			found = true
			if v[0] != 1024 {
				t.Errorf("upload want 1024 got %d", v[0])
			}
			if v[1] != 4096 {
				t.Errorf("download want 4096 got %d", v[1])
			}
		}
	}
	if !found {
		t.Fatal("expected residential bucket in tracker after Close()")
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
