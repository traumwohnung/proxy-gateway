// Package analytics is a thin gRPC client that streams UsageDelta messages
// to the analytics-service. It is write-only: the gateway never reads back.
package analytics

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	ingestv1 "proxy-gateway/analytics/gen/ingest/v1"
)

// Delta is a single usage record handed to the client — one per closed
// connection.
type Delta struct {
	Timestamp              time.Time
	Proxyset               string
	SessionParams          string // raw JSON
	SessionDurationMinutes int32
	UploadBytes            int64
	DownloadBytes          int64
}

// Client maintains a long-lived RecordUsage stream with reconnect-with-backoff
// and a bounded send queue. Send is non-blocking — when the queue is full the
// delta is dropped and a warning is logged. The gateway hot path must never
// stall on analytics.
type Client struct {
	addr  string
	token string

	queue chan *ingestv1.UsageDelta

	cc *grpc.ClientConn

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

const queueCapacity = 4096

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
		queue:  make(chan *ingestv1.UsageDelta, queueCapacity),
		cc:     cc,
		cancel: cancel,
	}
	c.wg.Add(1)
	go c.run(ctx)
	return c, nil
}

// Send enqueues a delta. Non-blocking: drops if queue is full.
func (c *Client) Send(d Delta) {
	if c == nil {
		return
	}
	msg := &ingestv1.UsageDelta{
		Timestamp:              timestamppb.New(d.Timestamp),
		Proxyset:               d.Proxyset,
		SessionParams:          d.SessionParams,
		SessionDurationMinutes: d.SessionDurationMinutes,
		UploadBytes:            d.UploadBytes,
		DownloadBytes:          d.DownloadBytes,
	}
	select {
	case c.queue <- msg:
	default:
		slog.Warn("analytics: send queue full, dropping delta", "proxyset", d.Proxyset)
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

// run is the background sender loop. It maintains one open stream and
// reconnects with exponential backoff on failure.
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
	stream, err := client.RecordUsage(streamCtx)
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
