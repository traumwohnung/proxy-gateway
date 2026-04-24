package utils

import (
	"errors"
	"fmt"
	"testing"

	httpcloaktransport "github.com/sardanioss/httpcloak/transport"
)

// TestClassifyError_TransportErrors verifies that ClassifyError still maps the
// error-message shapes produced by the httpcloak transport layer onto the
// ErrorKind enum. These substrings are part of the interface between our
// MITM layer and the httpcloak fork — a drift here silently demotes every
// dial_proxy / tls_handshake / pooled_request failure to KindUnknown and
// breaks retry/alerting logic.
func TestClassifyError_TransportErrors(t *testing.T) {
	underlying := errors.New("proxy CONNECT failed: 500 Internal Server Error")

	cases := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{
			name: "dial_proxy wraps 500 → UpstreamProxy5xx",
			err:  httpcloaktransport.NewProxyError("dial_proxy", "example.com", "443", underlying),
			want: KindUpstreamProxy5xx,
		},
		{
			name: "dial_proxy with generic dial error → UpstreamProxyDial",
			err:  httpcloaktransport.NewProxyError("dial_proxy", "example.com", "443", errors.New("dial tcp: connection refused")),
			want: KindUpstreamProxyDial,
		},
		{
			name: "407 response → UpstreamProxyAuth",
			err:  fmt.Errorf("proxy CONNECT failed: 407 Proxy Authentication Required"),
			want: KindUpstreamProxyAuth,
		},
		{
			name: "tls_handshake → TargetTLS",
			err:  httpcloaktransport.NewTLSError("tls_handshake", "example.com", "443", "h1", errors.New("EOF")),
			want: KindTargetTLS,
		},
		{
			name: "pooled_request wraps underlying → PooledConnDead",
			err:  httpcloaktransport.WrapError("pooled_request", "example.com", "443", "h1", errors.New("use of closed network connection")),
			want: KindPooledConnDead,
		},
		{
			name: "i/o timeout → TargetReadTimeout",
			err:  errors.New("read tcp 1.2.3.4:443: i/o timeout"),
			want: KindTargetReadTimeout,
		},
		{
			name: "unknown error → KindUnknown",
			err:  errors.New("something unexpected happened"),
			want: KindUnknown,
		},
		{
			name: "nil → empty",
			err:  nil,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.err)
			if got != tc.want {
				t.Errorf("ClassifyError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestErrorKind_IsSafeToRetry asserts the retry policy for each error class.
// Safe-to-retry == target server saw zero bytes; unsafe == target may have
// seen the request. Getting this wrong turns a transient glitch into
// duplicate non-idempotent delivery.
func TestErrorKind_IsSafeToRetry(t *testing.T) {
	safe := []ErrorKind{
		KindUpstreamProxyDial,
		KindUpstreamProxy5xx,
		KindTargetTLS,
	}
	unsafe := []ErrorKind{
		KindUpstreamProxyAuth,    // won't recover
		KindPooledConnDead,       // target may have seen bytes
		KindTargetReadTimeout,    // request definitely sent
		KindContextCanceled,      // caller gave up
		KindUnknown,              // default to unsafe
	}

	for _, k := range safe {
		if !k.IsSafeToRetry() {
			t.Errorf("%q should be safe to retry", k)
		}
	}
	for _, k := range unsafe {
		if k.IsSafeToRetry() {
			t.Errorf("%q should NOT be safe to retry", k)
		}
	}
}
