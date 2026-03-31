package proxygatewayclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
)

func newTestServer(t *testing.T, sessions []proxygatewayclient.SessionInfo) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions)
	})

	mux.HandleFunc("GET /api/sessions/{username}", func(w http.ResponseWriter, r *http.Request) {
		want := sessions[0].Username
		if r.PathValue("username") != want {
			http.Error(w, `{"error":"no active session"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sessions[0])
	})

	mux.HandleFunc("POST /api/sessions/{username}/rotate", func(w http.ResponseWriter, r *http.Request) {
		want := sessions[0].Username
		if r.PathValue("username") != want {
			http.Error(w, `{"error":"no active session"}`, http.StatusNotFound)
			return
		}
		updated := sessions[0]
		updated.LastRotationAt = time.Now().UTC()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})

	return httptest.NewServer(mux)
}

// newUsageTestServer starts a test server whose /api/usage handler captures the
// last received request so tests can inspect query parameters, and returns a
// configurable response.
type usageServerOpts struct {
	response proxygatewayclient.UsageResponse
	status   int // 0 → 200
}

func newUsageTestServer(t *testing.T, opts usageServerOpts) (*httptest.Server, *http.Request) {
	t.Helper()
	var captured *http.Request
	if opts.status == 0 {
		opts.status = http.StatusOK
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		captured = r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(opts.status)
		if opts.status == http.StatusOK {
			json.NewEncoder(w).Encode(opts.response)
		} else {
			w.Write([]byte(`{"error":"bad request"}`))
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, captured
}

var testSession = proxygatewayclient.SessionInfo{
	SessionID:      1,
	Username:       "eyJzZXQiOiJyZXNpZGVudGlhbCIsIm1pbnV0ZXMiOjYwfQ==",
	ProxySet:       "residential",
	Upstream:       "198.51.100.1:6658",
	CreatedAt:      time.Now().UTC(),
	NextRotationAt: time.Now().Add(time.Hour).UTC(),
	LastRotationAt: time.Now().UTC(),
	Metadata:       map[string]any{"platform": "myapp"},
}

func TestListSessions(t *testing.T) {
	srv := newTestServer(t, []proxygatewayclient.SessionInfo{testSession})
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})
	sessions, err := c.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].ProxySet != "residential" {
		t.Errorf("expected proxy_set=residential, got %q", sessions[0].ProxySet)
	}
}

func TestGetSession(t *testing.T) {
	srv := newTestServer(t, []proxygatewayclient.SessionInfo{testSession})
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})

	got, err := c.GetSession(context.Background(), testSession.Username)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got == nil {
		t.Fatal("expected session, got nil")
	}
	if got.Upstream != testSession.Upstream {
		t.Errorf("expected upstream %q, got %q", testSession.Upstream, got.Upstream)
	}

	// Non-existent username → nil, nil
	missing, err := c.GetSession(context.Background(), "notexist")
	if err != nil {
		t.Fatalf("GetSession (missing): %v", err)
	}
	if missing != nil {
		t.Error("expected nil for missing session")
	}
}

func TestForceRotate(t *testing.T) {
	srv := newTestServer(t, []proxygatewayclient.SessionInfo{testSession})
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})

	got, err := c.ForceRotate(context.Background(), testSession.Username)
	if err != nil {
		t.Fatalf("ForceRotate: %v", err)
	}
	if got == nil {
		t.Fatal("expected session after rotate, got nil")
	}

	// Non-existent username → nil, nil
	missing, err := c.ForceRotate(context.Background(), "notexist")
	if err != nil {
		t.Fatalf("ForceRotate (missing): %v", err)
	}
	if missing != nil {
		t.Error("expected nil for missing session")
	}
}

// ---------------------------------------------------------------------------
// QueryUsage tests
// ---------------------------------------------------------------------------

var testUsageResponse = proxygatewayclient.UsageResponse{
	Rows: []proxygatewayclient.UsageRow{
		{
			Proxyset:      strPtr("residential"),
			UploadBytes:   1024,
			DownloadBytes: 2048,
			TotalBytes:    3072,
		},
	},
	TotalCount: 1,
	Page:       1,
	PageSize:   100,
	TotalPages: 1,
}

func strPtr(s string) *string { return &s }

func TestQueryUsage_NoFilter(t *testing.T) {
	srv, _ := newUsageTestServer(t, usageServerOpts{response: testUsageResponse})

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL, APIKey: "test"})
	resp, err := c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if resp.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", resp.TotalCount)
	}
	if len(resp.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(resp.Rows))
	}
	if resp.Rows[0].UploadBytes != 1024 {
		t.Errorf("want upload=1024, got %d", resp.Rows[0].UploadBytes)
	}
}

func TestQueryUsage_SendsFromParam(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	from := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{From: from})

	if gotReq == nil {
		t.Fatal("no request received")
	}
	got := gotReq.URL.Query().Get("from")
	want := from.Format(time.RFC3339)
	if got != want {
		t.Errorf("from param: want %q, got %q", want, got)
	}
}

func TestQueryUsage_SendsToParam(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	to := time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC)
	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{To: to})

	got := gotReq.URL.Query().Get("to")
	want := to.Format(time.RFC3339)
	if got != want {
		t.Errorf("to param: want %q, got %q", want, got)
	}
}

func TestQueryUsage_SendsProxysetParam(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{Proxyset: "residential"})

	if gotReq.URL.Query().Get("proxyset") != "residential" {
		t.Errorf("proxyset param not sent correctly, got %q", gotReq.URL.Query().Get("proxyset"))
	}
}

func TestQueryUsage_SendsMetaParam(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{MetaContains: `{"user":"alice"}`})

	if gotReq.URL.Query().Get("meta") != `{"user":"alice"}` {
		t.Errorf("meta param not sent correctly, got %q", gotReq.URL.Query().Get("meta"))
	}
}

func TestQueryUsage_SendsGranularityParam(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{Granularity: proxygatewayclient.GranularityTotal})

	if gotReq.URL.Query().Get("granularity") != "total" {
		t.Errorf("granularity param not sent correctly, got %q", gotReq.URL.Query().Get("granularity"))
	}
}

func TestQueryUsage_SendsPaginationParams(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{Page: 3, PageSize: 50})

	q := gotReq.URL.Query()
	if q.Get("page") != "3" {
		t.Errorf("page param: want 3, got %q", q.Get("page"))
	}
	if q.Get("page_size") != "50" {
		t.Errorf("page_size param: want 50, got %q", q.Get("page_size"))
	}
}

func TestQueryUsage_OmitsZeroTimeParams(t *testing.T) {
	var gotReq *http.Request
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/usage", func(w http.ResponseWriter, r *http.Request) {
		gotReq = r
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(proxygatewayclient.UsageResponse{Rows: []proxygatewayclient.UsageRow{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{}) // all zero

	q := gotReq.URL.Query()
	for _, param := range []string{"from", "to", "proxyset", "meta", "granularity", "page", "page_size"} {
		if q.Has(param) {
			t.Errorf("param %q should be omitted when zero, but was sent as %q", param, q.Get(param))
		}
	}
}

func TestQueryUsage_ReturnsAPIError(t *testing.T) {
	srv, _ := newUsageTestServer(t, usageServerOpts{status: http.StatusBadRequest})

	c := proxygatewayclient.New(proxygatewayclient.ClientOptions{BaseURL: srv.URL})
	_, err := c.QueryUsage(context.Background(), proxygatewayclient.UsageFilter{})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	apiErr, ok := err.(*proxygatewayclient.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("want StatusCode=400, got %d", apiErr.StatusCode)
	}
}

func TestQueryUsage_AllGranularityConstants(t *testing.T) {
	cases := []struct {
		g    proxygatewayclient.Granularity
		want string
	}{
		{proxygatewayclient.GranularityHour, "hour"},
		{proxygatewayclient.GranularityDay, "day"},
		{proxygatewayclient.GranularityProxyset, "proxyset"},
		{proxygatewayclient.GranularityTotal, "total"},
	}
	for _, tc := range cases {
		if string(tc.g) != tc.want {
			t.Errorf("Granularity constant: want %q, got %q", tc.want, string(tc.g))
		}
	}
}
