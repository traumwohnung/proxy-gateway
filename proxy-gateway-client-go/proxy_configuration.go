package proxygatewayclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ProxyConfiguration is the fluent builder for a single proxy-gateway proxy
// configuration. From it you can:
//
//   - BuildUsername     — base64-encoded username string only
//   - BuildURL          — full http://user:x@host:port URL
//   - BuildHTTPClient   — *http.Client whose Transport routes through that URL
//   - Rotate            — re-roll the rotation via the admin API
//   - Retry / RetryN    — see retry.go
//
// Calling BuildUsername with identical configuration always produces the
// same base64 username — building the same configuration twice does not
// change any rotation state, which keeps sessions stable across processes
// and call sites.
type ProxyConfiguration struct {
	params UsernameParams
	client *ProxyClient
}

// NewProxyConfiguration creates a configuration builder for the given
// proxy set.
func NewProxyConfiguration(set string) *ProxyConfiguration {
	return &ProxyConfiguration{
		params: UsernameParams{
			Set:      set,
			Affinity: map[string]any{},
		},
	}
}

// Clone returns a deep copy of the configuration. The affinity map is
// copied so further mutations on the clone do not affect the original.
// The bound *ProxyClient pointer is shared (it is immutable in practice).
func (b *ProxyConfiguration) Clone() *ProxyConfiguration {
	cp := &ProxyConfiguration{
		params: b.params,
		client: b.client,
	}
	if b.params.Affinity != nil {
		cp.params.Affinity = make(map[string]any, len(b.params.Affinity))
		for k, v := range b.params.Affinity {
			cp.params.Affinity[k] = v
		}
	}
	return cp
}

// Minutes sets the session-affinity duration (0 = new proxy per request,
// 1–1440 = sticky).
func (b *ProxyConfiguration) Minutes(n int) *ProxyConfiguration {
	b.params.Minutes = n
	return b
}

// Affinity adds a key/value to the affinity map. Two configurations with
// the same set + same affinity map share a session on the gateway.
func (b *ProxyConfiguration) Affinity(key string, value any) *ProxyConfiguration {
	if b.params.Affinity == nil {
		b.params.Affinity = map[string]any{}
	}
	b.params.Affinity[key] = value
	return b
}

// HTTPCloak enables TLS fingerprint spoofing.
func (b *ProxyConfiguration) HTTPCloak(spec *HTTPCloakSpec) *ProxyConfiguration {
	b.params.HTTPCloak = spec
	return b
}

// WithProxyClient attaches the gateway connection (proxy endpoint and
// admin API). Required for BuildURL, BuildHTTPClient, Rotate, and the
// retry primitives.
func (b *ProxyConfiguration) WithProxyClient(c *ProxyClient) *ProxyConfiguration {
	b.client = c
	return b
}

// BuildUsername encodes the current configuration into a base64 username.
func (b *ProxyConfiguration) BuildUsername() (string, error) {
	return BuildUsername(b.params)
}

// MustBuildUsername is BuildUsername that panics on error.
func (b *ProxyConfiguration) MustBuildUsername() string {
	u, err := b.BuildUsername()
	if err != nil {
		panic("proxygatewayclient.MustBuildUsername: " + err.Error())
	}
	return u
}

// BuildURL builds the full proxy URL: http://<username>:x@<host>:<port>.
// Requires WithProxyClient with a configured proxy endpoint.
func (b *ProxyConfiguration) BuildURL() (string, error) {
	if b.client == nil {
		return "", errors.New("proxygatewayclient.ProxyConfiguration: BuildURL requires WithProxyClient")
	}
	if b.client.proxyHost == "" || b.client.proxyPort == 0 {
		return "", errors.New("proxygatewayclient.ProxyConfiguration: ProxyClient is missing proxy host:port")
	}
	username, err := b.BuildUsername()
	if err != nil {
		return "", err
	}
	u := &url.URL{
		Scheme: "http",
		User:   url.UserPassword(username, "x"),
		Host:   fmt.Sprintf("%s:%d", b.client.proxyHost, b.client.proxyPort),
	}
	return u.String(), nil
}

// MustBuildURL is BuildURL that panics on error.
func (b *ProxyConfiguration) MustBuildURL() string {
	u, err := b.BuildURL()
	if err != nil {
		panic("proxygatewayclient.MustBuildURL: " + err.Error())
	}
	return u
}

// BuildHTTPClient returns an *http.Client whose Transport routes requests
// through the gateway using this configuration's proxy URL.
func (b *ProxyConfiguration) BuildHTTPClient() (*http.Client, error) {
	urlStr, err := b.BuildURL()
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(parsed)},
	}, nil
}

// Rotate calls the gateway admin API to re-roll the rotation for the
// current username. The username itself does not change. Requires
// WithProxyClient with admin endpoint configured.
func (b *ProxyConfiguration) Rotate(ctx context.Context) (*SessionInfo, error) {
	if b.client == nil {
		return nil, errors.New("proxygatewayclient.ProxyConfiguration: Rotate requires WithProxyClient")
	}
	admin := b.client.adminClient()
	if admin == nil {
		return nil, errors.New("proxygatewayclient.ProxyConfiguration: Rotate requires admin endpoint configured on ProxyClient")
	}
	username, err := b.BuildUsername()
	if err != nil {
		return nil, err
	}
	return admin.RotateNow(ctx, username)
}
