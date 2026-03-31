package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"proxy-gateway/db/gen"
)

// bucketKey uniquely identifies a usage bucket.
type bucketKey struct {
	HourTS         time.Time // UTC, truncated to full hour
	Proxyset       string
	AffinityParams string // canonical JSON
}

// UsageTracker accumulates upload/download byte deltas in memory and
// flushes them to Postgres every second via an atomic upsert.
type UsageTracker struct {
	mu      sync.Mutex
	deltas  map[bucketKey][2]int64 // [0]=upload [1]=download
	queries *db.Queries
}

func NewUsageTracker(queries *db.Queries) *UsageTracker {
	return &UsageTracker{
		deltas:  make(map[bucketKey][2]int64),
		queries: queries,
	}
}

// record adds upload/download bytes to the in-memory bucket for the given key.
func (t *UsageTracker) record(proxyset, affinityJSON string, upload, download int64) {
	if upload == 0 && download == 0 {
		return
	}
	key := bucketKey{
		HourTS:         time.Now().UTC().Truncate(time.Hour),
		Proxyset:       proxyset,
		AffinityParams: affinityJSON,
	}
	t.mu.Lock()
	cur := t.deltas[key]
	cur[0] += upload
	cur[1] += download
	t.deltas[key] = cur
	t.mu.Unlock()
}

// flush swaps out the current deltas map and upserts each bucket to Postgres.
func (t *UsageTracker) flush(ctx context.Context) {
	t.mu.Lock()
	if len(t.deltas) == 0 {
		t.mu.Unlock()
		return
	}
	pending := t.deltas
	t.deltas = make(map[bucketKey][2]int64)
	t.mu.Unlock()

	for key, counts := range pending {
		err := t.queries.UpsertUsageBucket(ctx, db.UpsertUsageBucketParams{
			HourTs:         pgtype.Timestamptz{Time: key.HourTS, Valid: true},
			Proxyset:       key.Proxyset,
			AffinityParams: []byte(key.AffinityParams),
			UploadBytes:    counts[0],
			DownloadBytes:  counts[1],
		})
		if err != nil {
			slog.Warn("usage flush: upsert failed", "proxyset", key.Proxyset, "err", err)
		}
	}
}

// Run starts the 1-second flush loop. It blocks until ctx is cancelled.
func (t *UsageTracker) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			t.flush(ctx)
		case <-ctx.Done():
			// Final flush on shutdown.
			t.flush(context.Background())
			return
		}
	}
}

// ---------------------------------------------------------------------------
// ConnTracker integration
// ---------------------------------------------------------------------------

// usageConnTracker is a per-connection proxykit.ConnTracker that records
// final byte totals into the UsageTracker when the connection closes.
type usageConnTracker struct {
	tracker        *UsageTracker
	proxyset       string
	affinityParams string
}

func (u *usageConnTracker) RecordTraffic(_ bool, _ int64, _ func()) {
	// We use the totals passed to Close() rather than per-read deltas to
	// avoid taking the mutex on every read syscall.
}

func (u *usageConnTracker) Close(sent, received int64) {
	u.tracker.record(u.proxyset, u.affinityParams, sent, received)
}
