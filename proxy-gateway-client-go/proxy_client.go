package proxygatewayclient

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
)

// ProxyClient holds the connection details for a proxy-gateway deployment:
// the proxy endpoint (host:port) and optionally the admin endpoint + API
// key (required for rotation calls). Build one at startup and pass it to
// ProxyConfiguration.WithProxyClient — the configuration uses it to format
// proxy URLs, construct http.Client instances, and call the admin API for
// rotation.
type ProxyClient struct {
	proxyHost     string
	proxyPort     int
	proxyPassword string
	adminURL      string
	apiKey        string
	httpClient    *http.Client
}

// NewProxyClient returns a fresh ProxyClient. Configure via the fluent
// setters before use.
//
// The proxy password is seeded from the PROXY_PASSWORD environment variable
// so it matches the gateway's PasswordAuth (TRA-302). The gateway fails
// closed when its PROXY_PASSWORD is empty, so this must be set in any
// environment that routes traffic through the gateway. Override per-client
// via Password().
func NewProxyClient() *ProxyClient {
	return &ProxyClient{proxyPassword: os.Getenv("PROXY_PASSWORD")}
}

// Password sets the proxy password sent in the Proxy-Authorization credentials.
// Overrides the value seeded from PROXY_PASSWORD at construction.
func (c *ProxyClient) Password(pw string) *ProxyClient {
	c.proxyPassword = pw
	return c
}

// Proxy sets the proxy endpoint host:port.
func (c *ProxyClient) Proxy(host string, port int) *ProxyClient {
	c.proxyHost = host
	c.proxyPort = port
	return c
}

// ProxyAddr is a convenience for Proxy(host, port) that accepts a
// "host:port" string. Panics on malformed input.
func (c *ProxyClient) ProxyAddr(addr string) *ProxyClient {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Sprintf("proxygatewayclient.ProxyClient.ProxyAddr: %v", err))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Sprintf("proxygatewayclient.ProxyClient.ProxyAddr: %v", err))
	}
	return c.Proxy(host, port)
}

// Admin sets the admin API base URL and bearer token (required for Rotate).
func (c *ProxyClient) Admin(baseURL, apiKey string) *ProxyClient {
	c.adminURL = baseURL
	c.apiKey = apiKey
	return c
}

// HTTPClient sets the underlying http.Client used for admin API requests.
// Defaults to a client with a 10s timeout when unset.
func (c *ProxyClient) HTTPClient(hc *http.Client) *ProxyClient {
	c.httpClient = hc
	return c
}

// ProxyHost returns the configured proxy host.
func (c *ProxyClient) ProxyHost() string { return c.proxyHost }

// ProxyPort returns the configured proxy port.
func (c *ProxyClient) ProxyPort() int { return c.proxyPort }

// adminClient builds a typed admin Client for API calls. Returns nil if
// Admin was not configured on this ProxyClient.
func (c *ProxyClient) adminClient() *Client {
	if c.adminURL == "" {
		return nil
	}
	return New(ClientOptions{
		BaseURL:    c.adminURL,
		APIKey:     c.apiKey,
		HTTPClient: c.httpClient,
	})
}
