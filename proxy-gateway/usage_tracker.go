package main

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"proxy-gateway/analytics"
)

// UsageTracker forwards per-connection ConnectionClosed events to the
// analytics service. There is no in-process aggregation: each closed
// connection produces exactly one event. The "in-memory store" per
// connection is just the byte counters maintained by the proxykit
// ConnTracker until Close fires.
type UsageTracker struct {
	client *analytics.Client
}

func NewUsageTracker(client *analytics.Client) *UsageTracker {
	return &UsageTracker{client: client}
}

// record builds and dispatches one ConnectionClosed event. Called once per
// connection close. reason is one of the canonical values defined on
// proxykit.ConnTracker.Close ("ok", "upstream_err", "client_close",
// "timeout", "auth_fail"); empty defaults to "ok".
func (t *UsageTracker) record(c connRecord, upload, download int64, reason string) {
	if t == nil || t.client == nil {
		return
	}
	// Record failures (no bytes flowed) so close_reason distributions are
	// observable, but skip the truly empty "ok" case where we have nothing
	// to attribute. Reason-tagged closes always emit.
	if upload == 0 && download == 0 && (reason == "" || reason == "ok") {
		return
	}
	if reason == "" {
		reason = "ok"
	}
	t.client.SendConnectionClosed(analytics.ConnectionClosed{
		Timestamp:              time.Now().UTC(),
		ConnectionID:           c.connectionID,
		Proxyset:               c.proxyset,
		Provider:               c.provider,
		SessionParams:          c.sessionParams,
		SessionDurationMinutes: int32(c.minutes),
		Epoch:                  c.epoch,
		UpstreamIP:             c.upstreamIP,
		SNI:                    c.sni,
		CloseReason:            reason,
		UploadBytes:            upload,
		DownloadBytes:          download,
		DurationMs:             time.Since(c.startedAt).Milliseconds(),
		SessionMeta:            c.sessionMeta,
	})
}

// connRecord is the per-connection context the tracker needs at Close-time.
// Populated by the trackUsage middleware when the connection is dialled.
type connRecord struct {
	connectionID  string
	proxyset      string
	provider      string
	sessionParams string // canonical JSON
	sessionMeta   string // canonical JSON; "{}" when none supplied
	minutes       int
	epoch         int32
	upstreamIP    string
	sni           string
	startedAt     time.Time
}

// usageConnTracker records the final byte totals once when the connection
// closes. RecordTraffic is intentionally a no-op: we only care about totals,
// not per-read deltas (taking the mutex on every read would be expensive).
type usageConnTracker struct {
	tracker *UsageTracker
	rec     connRecord
}

func (u *usageConnTracker) RecordTraffic(_ bool, _ int64, _ func()) {}

func (u *usageConnTracker) Close(sent, received int64, reason string) {
	u.tracker.record(u.rec, sent, received, reason)
}

// newConnectionID returns a 32-char hex random ID. Used as the analytics
// connection_id so per-connection events can later be correlated (e.g.
// MITM requests inside a tunnel) without any DB round-trip.
func newConnectionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
