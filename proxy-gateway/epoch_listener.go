package main

import (
	"time"

	"proxy-gateway/analytics"
	"proxy-kit/utils"
)

// analyticsEpochListener adapts utils.EpochListener to the analytics client.
// It is a zero-overhead bridge: the session manager already runs the callback
// inline, and the analytics client's enqueue is non-blocking.
type analyticsEpochListener struct {
	client *analytics.Client
}

// newAnalyticsEpochListener returns nil when client is nil — installing a
// nil listener on SessionManager disables emission.
func newAnalyticsEpochListener(client *analytics.Client) *analyticsEpochListener {
	if client == nil {
		return nil
	}
	return &analyticsEpochListener{client: client}
}

// OnEpochTransition forwards the event to analytics. SessionParams is the
// canonical JSON of the session params — the analytics server derives its
// own session_hash from it.
func (l *analyticsEpochListener) OnEpochTransition(ev utils.EpochEvent) {
	if l == nil || l.client == nil {
		return
	}
	l.client.SendEpochTransition(analytics.EpochTransition{
		Timestamp:     time.Now().UTC(),
		SessionParams: ev.SessionParams,
		Proxyset:      ev.ProxysetName,
		Provider:      ev.ProviderName,
		PrevEpoch:     ev.PrevEpoch,
		NewEpoch:      ev.NewEpoch,
		PrevIP:        ev.PrevIP,
		NewIP:         ev.NewIP,
		StartReason:   ev.StartReason,
	})
}
