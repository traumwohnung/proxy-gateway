package main

import (
	"time"

	"proxy-gateway/analytics"
)

// UsageTracker forwards per-connection usage records to the analytics service.
// There is no in-process aggregation: each closed connection produces exactly
// one ingest message. The "in-memory store" per connection is just the byte
// counters maintained by the proxykit ConnTracker until Close fires.
type UsageTracker struct {
	client *analytics.Client
}

func NewUsageTracker(client *analytics.Client) *UsageTracker {
	return &UsageTracker{client: client}
}

// record builds and dispatches one Delta. Called once per connection close.
func (t *UsageTracker) record(proxyset, sessionParams string, minutes int, upload, download int64) {
	if t == nil || t.client == nil {
		return
	}
	if upload == 0 && download == 0 {
		return
	}
	t.client.Send(analytics.Delta{
		Timestamp:              time.Now().UTC(),
		Proxyset:               proxyset,
		SessionParams:          sessionParams,
		SessionDurationMinutes: int32(minutes),
		UploadBytes:            upload,
		DownloadBytes:          download,
	})
}

// usageConnTracker records the final byte totals once when the connection
// closes. RecordTraffic is intentionally a no-op: we only care about totals,
// not per-read deltas (taking the mutex on every read would be expensive).
type usageConnTracker struct {
	tracker       *UsageTracker
	proxyset      string
	sessionParams string
	minutes       int
}

func (u *usageConnTracker) RecordTraffic(_ bool, _ int64, _ func()) {}

func (u *usageConnTracker) Close(sent, received int64) {
	u.tracker.record(u.proxyset, u.sessionParams, u.minutes, sent, received)
}
