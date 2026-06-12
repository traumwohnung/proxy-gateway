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
			Set:           set,
			SessionParams: map[string]any{},
		},
	}
}

// Clone returns a deep copy of the configuration. The session_params and
// session_meta maps are copied so further mutations on the clone do not
// affect the original. The bound *ProxyClient pointer is shared (it is
// immutable in practice).
func (b *ProxyConfiguration) Clone() *ProxyConfiguration {
	cp := &ProxyConfiguration{
		params: b.params,
		client: b.client,
	}
	if b.params.SessionParams != nil {
		cp.params.SessionParams = make(map[string]any, len(b.params.SessionParams))
		for k, v := range b.params.SessionParams {
			cp.params.SessionParams[k] = v
		}
	}
	if b.params.SessionMeta != nil {
		cp.params.SessionMeta = make(map[string]any, len(b.params.SessionMeta))
		for k, v := range b.params.SessionMeta {
			cp.params.SessionMeta[k] = v
		}
	}
	if b.params.Scripts != nil {
		cp.params.Scripts = append([]ScriptEntry(nil), b.params.Scripts...)
	}
	return cp
}

// Minutes sets the session duration (0 = new proxy per request,
// 1–1440 = sticky).
func (b *ProxyConfiguration) Minutes(n int) *ProxyConfiguration {
	b.params.Minutes = n
	return b
}

// SessionParams adds a key/value to the session_params map. Two
// configurations with the same set + same session_params share a session
// on the gateway (same upstream IP).
func (b *ProxyConfiguration) SessionParams(key string, value any) *ProxyConfiguration {
	if b.params.SessionParams == nil {
		b.params.SessionParams = map[string]any{}
	}
	b.params.SessionParams[key] = value
	return b
}

// SessionMeta adds a key/value to the session_meta map. Informational
// only — never affects session identity or IP selection; carried through
// to the analytics service for filtering/grouping.
func (b *ProxyConfiguration) SessionMeta(key string, value any) *ProxyConfiguration {
	if b.params.SessionMeta == nil {
		b.params.SessionMeta = map[string]any{}
	}
	b.params.SessionMeta[key] = value
	return b
}

// MITM enables MITM mode with default settings (chrome-latest httpcloak
// fingerprint, no scripts). Calling HTTPCloak or Scripts implicitly enables
// MITM as well — this method is the explicit form for the "plain default
// MITM" case.
func (b *ProxyConfiguration) MITM() *ProxyConfiguration {
	b.params.MITM = true
	return b
}

// NoMITM disables MITM and drops any previously configured HTTPCloak spec
// and Scripts chain together. Use it to revert a cloned configuration back
// to tunnel mode.
func (b *ProxyConfiguration) NoMITM() *ProxyConfiguration {
	b.params.MITM = false
	b.params.HTTPCloak = nil
	b.params.Scripts = nil
	return b
}

// HTTPCloak sets the TLS fingerprint spoofing spec and enables MITM.
func (b *ProxyConfiguration) HTTPCloak(spec *HTTPCloakSpec) *ProxyConfiguration {
	b.params.HTTPCloak = spec
	b.params.MITM = true
	return b
}

// Scripts appends to the ordered chain of Starlark scripts evaluated on
// the MITM'd response. Implicitly enables MITM. Entries are kept in the
// order added. Use ScriptRef or ScriptSource to construct entries:
//
//	cfg.Scripts(
//	    proxygatewayclient.ScriptRef("antibot"),
//	    proxygatewayclient.ScriptSource(`def response_bailing(r): return "x" if r.scan(b"BLOCK") >= 0 else None`),
//	)
func (b *ProxyConfiguration) Scripts(entries ...ScriptEntry) *ProxyConfiguration {
	b.params.Scripts = append(b.params.Scripts, entries...)
	b.params.MITM = true
	return b
}

// ScriptRef is a convenience for cfg.Scripts(ScriptRef(name)).
func (b *ProxyConfiguration) ScriptRef(name string) *ProxyConfiguration {
	return b.Scripts(ScriptRef(name))
}

// ScriptSource is a convenience for cfg.Scripts(ScriptSource(src)).
func (b *ProxyConfiguration) ScriptSource(src string) *ProxyConfiguration {
	return b.Scripts(ScriptSource(src))
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

// BuildURL builds the full proxy URL:
// http://<username>:<PROXY_PASSWORD>@<host>:<port>.
// Requires WithProxyClient with a configured proxy endpoint. The password is
// taken from the ProxyClient (seeded from PROXY_PASSWORD; see NewProxyClient)
// so the gateway's fail-closed PasswordAuth accepts the request (TRA-302).
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
		User:   url.UserPassword(username, b.client.proxyPassword),
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
