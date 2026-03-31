// Package proxygatewayclient provides a client for the proxy-gateway admin API,
// plus helpers for building and parsing proxy usernames.
package proxygatewayclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SessionInfo represents an active sticky session returned by the admin API.
type SessionInfo struct {
	// Internal session ID, assigned at creation (starts at 0, increments per session).
	SessionID uint64 `json:"session_id"`
	// The raw base64 username string used as the affinity key.
	Username string `json:"username"`
	// The proxy set name.
	ProxySet string `json:"proxy_set"`
	// The upstream proxy address (host:port).
	Upstream string `json:"upstream"`
	// Session creation time — never changes.
	CreatedAt time.Time `json:"created_at"`
	// When the current proxy assignment expires. Reset on ForceRotate.
	NextRotationAt time.Time `json:"next_rotation_at"`
	// When the proxy was last assigned — equals CreatedAt unless ForceRotate was called.
	LastRotationAt time.Time `json:"last_rotation_at"`
	// The decoded metadata object from the username JSON.
	Metadata map[string]any `json:"metadata"`
}

// APIError is returned by the server when a request fails.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("proxy-gateway %d: %s", e.StatusCode, e.Message)
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// BaseURL is the base URL of the proxy-gateway admin server, e.g. "http://proxy-gateway:9000".
	BaseURL string
	// APIKey is the Bearer token for authenticating with the admin API.
	APIKey string
	// HTTPClient is an optional custom HTTP client. Defaults to a client with a 10s timeout.
	HTTPClient *http.Client
}

// Client is a typed client for the proxy-gateway admin API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New creates a new Client with the given options.
func New(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(opts.BaseURL, "/"),
		apiKey:     opts.APIKey,
		httpClient: hc,
	}
}

// ---------------------------------------------------------------------------
// Usage types
// ---------------------------------------------------------------------------

// Granularity controls how usage rows are aggregated.
type Granularity string

const (
	GranularityHour     Granularity = "hour"     // raw per-hour buckets (default)
	GranularityDay      Granularity = "day"       // aggregate per UTC day
	GranularityProxyset Granularity = "proxyset"  // aggregate per proxy set
	GranularityTotal    Granularity = "total"     // single grand total
)

// UsageFilter describes the query parameters for QueryUsage.
type UsageFilter struct {
	// From/To filter by hour_ts (inclusive). Zero value means no bound.
	From time.Time
	To   time.Time
	// Proxyset filters to an exact proxy set name.
	Proxyset string
	// MetaContains is a JSON object string matched via JSONB @> containment.
	// E.g. `{"user":"alice"}` matches any row whose affinity_params contains that key/value.
	MetaContains string
	// Granularity controls the GROUP BY. Defaults to GranularityHour.
	Granularity Granularity
	// Page is the 1-indexed page number. Defaults to 1.
	Page int
	// PageSize is the number of rows per page. Defaults to 100, max 1000.
	PageSize int
}

// UsageRow is one row returned by QueryUsage.
// Which fields are populated depends on the Granularity.
type UsageRow struct {
	// HourTS is set for GranularityHour.
	HourTS *time.Time `json:"hour_ts,omitempty"`
	// Day is set for GranularityDay (UTC, truncated to midnight).
	Day *string `json:"day,omitempty"`
	// Proxyset is set for GranularityHour, GranularityDay, GranularityProxyset.
	Proxyset *string `json:"proxyset,omitempty"`
	// AffinityParams is set for GranularityHour — raw JSONB string.
	AffinityParams *string `json:"affinity_params,omitempty"`
	UploadBytes    int64   `json:"upload_bytes"`
	DownloadBytes  int64   `json:"download_bytes"`
	TotalBytes     int64   `json:"total_bytes"`
}

// UsageResponse is the envelope returned by QueryUsage.
type UsageResponse struct {
	Rows       []UsageRow `json:"rows"`
	TotalCount int64      `json:"total_count"`
	Page       int        `json:"page"`
	PageSize   int        `json:"page_size"`
	TotalPages int64      `json:"total_pages"`
}

// QueryUsage fetches aggregated bandwidth usage with optional filters.
func (c *Client) QueryUsage(ctx context.Context, f UsageFilter) (*UsageResponse, error) {
	params := url.Values{}
	if !f.From.IsZero() {
		params.Set("from", f.From.UTC().Format(time.RFC3339))
	}
	if !f.To.IsZero() {
		params.Set("to", f.To.UTC().Format(time.RFC3339))
	}
	if f.Proxyset != "" {
		params.Set("proxyset", f.Proxyset)
	}
	if f.MetaContains != "" {
		params.Set("meta", f.MetaContains)
	}
	if f.Granularity != "" {
		params.Set("granularity", string(f.Granularity))
	}
	if f.Page > 0 {
		params.Set("page", fmt.Sprintf("%d", f.Page))
	}
	if f.PageSize > 0 {
		params.Set("page_size", fmt.Sprintf("%d", f.PageSize))
	}

	path := "/api/usage"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var resp UsageResponse
	if err := c.get(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// Session methods
// ---------------------------------------------------------------------------

// ListSessions returns all active sticky sessions across all proxy sets.
// Sessions with 0 minutes (no affinity) are not tracked.
func (c *Client) ListSessions(ctx context.Context) ([]SessionInfo, error) {
	var sessions []SessionInfo
	if err := c.get(ctx, "/api/sessions", &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetSession returns the active session for the given base64 username.
// Returns nil, nil if no active session exists for that username.
func (c *Client) GetSession(ctx context.Context, username string) (*SessionInfo, error) {
	var info SessionInfo
	path := "/api/sessions/" + url.PathEscape(username)
	err := c.get(ctx, path, &info)
	if err != nil {
		var apiErr *APIError
		if isAPIError(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &info, nil
}

// ForceRotate force-rotates the upstream proxy for an existing session.
// It immediately reassigns the upstream proxy and resets the session TTL.
// Returns nil, nil if no active session exists for that username.
func (c *Client) ForceRotate(ctx context.Context, username string) (*SessionInfo, error) {
	var info SessionInfo
	path := "/api/sessions/" + url.PathEscape(username) + "/rotate"
	err := c.post(ctx, path, &info)
	if err != nil {
		var apiErr *APIError
		if isAPIError(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &info, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, out)
}

func (c *Client) post(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodPost, path, out)
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &apiErr)
		msg := apiErr.Error
		if msg == "" {
			msg = string(body)
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

func isAPIError(err error, target **APIError) bool {
	if e, ok := err.(*APIError); ok {
		*target = e
		return true
	}
	return false
}
