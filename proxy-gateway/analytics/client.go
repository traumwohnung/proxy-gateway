// Package analytics is a thin gRPC client that streams observability Events
// to the analytics-service. It is write-only: the gateway never reads back.
//
// The wire protocol carries one Event per message, each with a oneof payload
// (ConnectionClosed, EpochTransition, DropReport, MitmRequest). The gateway
// produces those variants via the typed Send* methods below; this file
// handles only transport (queue, reconnect, drop accounting).
package analytics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	ingestv1 "proxy-gateway/analytics/gen/ingest/v1"
)

// ConnectionClosed is the gateway-facing shape for the variant of the same
// name in the proto. Field names mirror the proto exactly.
type ConnectionClosed struct {
	Timestamp              time.Time
	ConnectionID           string
	Proxyset               string
	Provider               string
	// SessionParams is the canonical (sorted-keys) JSON of the session
	// params. Drives session identity / IP selection. The analytics server
	// derives session_hash = sha256[:16] of this string for joins.
	SessionParams          string
	SessionDurationMinutes int32
	Epoch                  int32
	UpstreamIP             string
	SNI                    string
	CloseReason            string
	UploadBytes            int64
	DownloadBytes          int64
	DurationMs             int64
	// SessionMeta is the canonical JSON of the informational meta map.
	// Stored on the analytics side as a column on session_params_dim keyed
	// by session_hash — no separate hash, last-write-wins on overlap.
	SessionMeta string
}

// EpochTransition is the gateway-facing shape for the EpochTransition
// variant. PrevEpoch is -1 on first_bind; PrevIP empty on first_bind.
type EpochTransition struct {
	Timestamp     time.Time
	SessionParams string // canonical JSON; server derives session_hash
	Proxyset      string
	Provider      string
	PrevEpoch     int32
	NewEpoch      int32
	PrevIP        string
	NewIP         string
	StartReason   string
}

// Client maintains a long-lived RecordEvents stream with reconnect+backoff
// and a bounded send queue. Send* are non-blocking — when the queue is full
// the event is dropped and the drop counter is incremented. The gateway hot
// path must never stall on analytics.
type Client struct {
	addr  string
	token string

	queue chan *ingestv1.Event
	cc    *grpc.ClientConn

	// Drop accounting. A background goroutine periodically emits a
	// DropReport variant carrying the running count over a window.
	droppedSinceReport atomic.Int64
	dropWindowStart    atomic.Int64 // unix seconds

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

const (
	queueCapacity        = 4096
	dropReportInterval   = 60 * time.Second
	dropReportMinDropped = 1
)

// Dial constructs a Client and starts its background sender. Returns nil and
// logs if addr is empty (analytics disabled).
func Dial(addr, token string) (*Client, error) {
	if addr == "" {
		return nil, nil
	}
	cc, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		addr:   addr,
		token:  token,
		queue:  make(chan *ingestv1.Event, queueCapacity),
		cc:     cc,
		cancel: cancel,
	}
	c.dropWindowStart.Store(time.Now().Unix())
	c.wg.Add(2)
	go c.run(ctx)
	go c.dropReportLoop(ctx)
	return c, nil
}

// SendConnectionClosed enqueues a ConnectionClosed event. Non-blocking;
// drops if queue is full.
func (c *Client) SendConnectionClosed(cc ConnectionClosed) {
	if c == nil {
		return
	}
	ev := &ingestv1.Event{
		Ts:      timestamppb.New(coalesceTime(cc.Timestamp)),
		EventId: newEventID(),
		Payload: &ingestv1.Event_ConnectionClosed{
			ConnectionClosed: &ingestv1.ConnectionClosed{
				ConnectionId:           cc.ConnectionID,
				Proxyset:               cc.Proxyset,
				Provider:               cc.Provider,
				SessionParams:          cc.SessionParams,
				SessionDurationMinutes: cc.SessionDurationMinutes,
				Epoch:                  cc.Epoch,
				UpstreamIp:             cc.UpstreamIP,
				Sni:                    cc.SNI,
				CloseReason:            cc.CloseReason,
				UploadBytes:            cc.UploadBytes,
				DownloadBytes:          cc.DownloadBytes,
				DurationMs:             cc.DurationMs,
				SessionMeta:            cc.SessionMeta,
			},
		},
	}
	c.enqueue(ev, cc.Proxyset)
}

// SendEpochTransition enqueues an EpochTransition event. Non-blocking;
// drops if queue is full.
func (c *Client) SendEpochTransition(t EpochTransition) {
	if c == nil {
		return
	}
	ev := &ingestv1.Event{
		Ts:      timestamppb.New(coalesceTime(t.Timestamp)),
		EventId: newEventID(),
		Payload: &ingestv1.Event_EpochTransition{
			EpochTransition: &ingestv1.EpochTransition{
				SessionParams: t.SessionParams,
				Proxyset:      t.Proxyset,
				Provider:      t.Provider,
				PrevEpoch:     t.PrevEpoch,
				NewEpoch:      t.NewEpoch,
				PrevIp:        t.PrevIP,
				NewIp:         t.NewIP,
				StartReason:   t.StartReason,
			},
		},
	}
	c.enqueue(ev, t.Proxyset)
}

func (c *Client) enqueue(ev *ingestv1.Event, debugTag string) {
	select {
	case c.queue <- ev:
	default:
		c.droppedSinceReport.Add(1)
		slog.Warn("analytics: send queue full, dropping event", "proxyset", debugTag)
	}
}

// Close drains the queue best-effort, closes the stream and connection.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.cancel()
	c.wg.Wait()
	return c.cc.Close()
}

func (c *Client) run(ctx context.Context) {
	defer c.wg.Done()
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.session(ctx); err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("analytics: stream session ended", "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second
	}
}

func (c *Client) session(ctx context.Context) error {
	client := ingestv1.NewIngestClient(c.cc)
	streamCtx := ctx
	if c.token != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, "authorization", "Bearer "+c.token)
	}
	stream, err := client.RecordEvents(streamCtx)
	if err != nil {
		return err
	}
	slog.Info("analytics: stream opened", "addr", c.addr)
	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return ctx.Err()
		case msg := <-c.queue:
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// dropReportLoop periodically flushes the drop counter as a DropReport event.
// We do this through the same queue so it is naturally ordered with other
// events, and so it inherits the same backpressure semantics (if the queue is
// full the DropReport itself is dropped, which is fine — the next interval
// covers it).
func (c *Client) dropReportLoop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(dropReportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.flushDropReport()
			return
		case <-t.C:
			c.flushDropReport()
		}
	}
}

func (c *Client) flushDropReport() {
	n := c.droppedSinceReport.Swap(0)
	if n < dropReportMinDropped {
		return
	}
	now := time.Now()
	winStart := c.dropWindowStart.Swap(now.Unix())
	ev := &ingestv1.Event{
		Ts:      timestamppb.New(now),
		EventId: newEventID(),
		Payload: &ingestv1.Event_DropReport{
			DropReport: &ingestv1.DropReport{
				DroppedEvents: n,
				WindowStart:   timestamppb.New(time.Unix(winStart, 0)),
				WindowEnd:     timestamppb.New(now),
			},
		},
	}
	select {
	case c.queue <- ev:
	default:
		// Drop the drop-report itself if the queue is full; restore the
		// counter so the next interval captures it.
		c.droppedSinceReport.Add(n)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func coalesceTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}
