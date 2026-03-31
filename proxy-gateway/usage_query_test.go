package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	db "proxy-gateway/db/gen"
)

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

func seedBucket(t *testing.T, q *db.Queries, hourTS time.Time, proxyset, affinityJSON string, upload, download int64) {
	t.Helper()
	err := q.UpsertUsageBucket(context.Background(), db.UpsertUsageBucketParams{
		HourTs:         pgtype.Timestamptz{Time: hourTS.UTC(), Valid: true},
		Proxyset:       proxyset,
		AffinityParams: []byte(affinityJSON),
		UploadBytes:    upload,
		DownloadBytes:  download,
	})
	if err != nil {
		t.Fatalf("seedBucket: %v", err)
	}
}

// fixed reference time: 2026-01-15 10:00:00 UTC (already truncated to hour)
var t0 = time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// QueryUsage — filter tests
// ---------------------------------------------------------------------------

func TestQueryUsage_NoFilter_ReturnsAllRows(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{}`, 100, 200)
	seedBucket(t, q, t0, "datacenter", `{}`, 300, 400)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 2 {
		t.Errorf("want TotalCount=2, got %d", res.TotalCount)
	}
	if len(res.Rows) != 2 {
		t.Errorf("want 2 rows, got %d", len(res.Rows))
	}
}

func TestQueryUsage_FilterByProxyset(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{}`, 100, 200)
	seedBucket(t, q, t0, "datacenter", `{}`, 300, 400)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{Proxyset: "residential"})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", res.TotalCount)
	}
	if *res.Rows[0].Proxyset != "residential" {
		t.Errorf("want proxyset=residential, got %q", *res.Rows[0].Proxyset)
	}
}

func TestQueryUsage_FilterByTimeRange_From(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0.Add(-2*time.Hour), "residential", `{}`, 10, 20) // before range
	seedBucket(t, q, t0, "residential", `{}`, 100, 200)                  // in range
	seedBucket(t, q, t0.Add(time.Hour), "residential", `{}`, 50, 60)     // in range

	from := t0
	res, err := q.QueryUsage(context.Background(), db.UsageFilter{From: &from})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 2 {
		t.Errorf("want TotalCount=2, got %d", res.TotalCount)
	}
}

func TestQueryUsage_FilterByTimeRange_To(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0.Add(-time.Hour), "residential", `{}`, 10, 20) // in range
	seedBucket(t, q, t0, "residential", `{}`, 100, 200)                // in range
	seedBucket(t, q, t0.Add(time.Hour), "residential", `{}`, 50, 60)   // after range

	to := t0
	res, err := q.QueryUsage(context.Background(), db.UsageFilter{To: &to})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 2 {
		t.Errorf("want TotalCount=2, got %d", res.TotalCount)
	}
}

func TestQueryUsage_FilterByTimeRange_FromTo(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0.Add(-time.Hour), "residential", `{}`, 1, 1) // before
	seedBucket(t, q, t0, "residential", `{}`, 100, 200)              // in window
	seedBucket(t, q, t0.Add(time.Hour), "residential", `{}`, 50, 50) // after

	from := t0
	to := t0
	res, err := q.QueryUsage(context.Background(), db.UsageFilter{From: &from, To: &to})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", res.TotalCount)
	}
	if res.Rows[0].UploadBytes != 100 {
		t.Errorf("want upload=100, got %d", res.Rows[0].UploadBytes)
	}
}

func TestQueryUsage_FilterByMeta_Containment(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{"user":"alice","platform":"ios"}`, 100, 0)
	seedBucket(t, q, t0, "residential", `{"user":"bob","platform":"ios"}`, 200, 0)
	seedBucket(t, q, t0, "residential", `{}`, 50, 0)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{MetaContains: `{"user":"alice"}`})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", res.TotalCount)
	}
	if res.Rows[0].UploadBytes != 100 {
		t.Errorf("want upload=100, got %d", res.Rows[0].UploadBytes)
	}
}

func TestQueryUsage_FilterByMeta_MultipleKeys(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{"user":"alice","platform":"ios"}`, 100, 0)
	seedBucket(t, q, t0, "residential", `{"user":"alice","platform":"android"}`, 200, 0)

	// Both keys must match
	res, err := q.QueryUsage(context.Background(), db.UsageFilter{MetaContains: `{"user":"alice","platform":"ios"}`})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", res.TotalCount)
	}
}

func TestQueryUsage_FilterCombined(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{"user":"alice"}`, 100, 0)
	seedBucket(t, q, t0, "datacenter", `{"user":"alice"}`, 200, 0)
	seedBucket(t, q, t0, "residential", `{"user":"bob"}`, 50, 0)

	from := t0
	res, err := q.QueryUsage(context.Background(), db.UsageFilter{
		From:         &from,
		Proxyset:     "residential",
		MetaContains: `{"user":"alice"}`,
	})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", res.TotalCount)
	}
	if res.Rows[0].UploadBytes != 100 {
		t.Errorf("want upload=100, got %d", res.Rows[0].UploadBytes)
	}
}

// ---------------------------------------------------------------------------
// QueryUsage — granularity tests
// ---------------------------------------------------------------------------

func TestQueryUsage_GranularityHour_DefaultShape(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{"user":"alice"}`, 100, 200)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{Granularity: db.GranularityHour})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(res.Rows))
	}
	row := res.Rows[0]
	if row.HourTS == nil {
		t.Error("GranularityHour: HourTS should be set")
	}
	if row.Proxyset == nil {
		t.Error("GranularityHour: Proxyset should be set")
	}
	if row.AffinityParams == nil {
		t.Error("GranularityHour: AffinityParams should be set")
	}
	if row.Day != nil {
		t.Error("GranularityHour: Day should be nil")
	}
}

func TestQueryUsage_GranularityDay_AggregatesAcrossHours(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	// Three hours on the same day, same proxyset — should collapse to 1 day row.
	seedBucket(t, q, t0, "residential", `{}`, 100, 200)
	seedBucket(t, q, t0.Add(time.Hour), "residential", `{}`, 50, 100)
	seedBucket(t, q, t0.Add(2*time.Hour), "residential", `{}`, 25, 50)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{Granularity: db.GranularityDay})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", res.TotalCount)
	}
	row := res.Rows[0]
	if row.Day == nil {
		t.Error("GranularityDay: Day should be set")
	}
	if row.UploadBytes != 175 {
		t.Errorf("want upload=175, got %d", row.UploadBytes)
	}
	if row.DownloadBytes != 350 {
		t.Errorf("want download=350, got %d", row.DownloadBytes)
	}
}

func TestQueryUsage_GranularityDay_SeparatesByProxyset(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{}`, 100, 0)
	seedBucket(t, q, t0, "datacenter", `{}`, 200, 0)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{Granularity: db.GranularityDay})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 2 {
		t.Errorf("want TotalCount=2 (one per proxyset), got %d", res.TotalCount)
	}
}

func TestQueryUsage_GranularityProxyset_CollapsesAllTime(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	// Multiple hours, multiple days — all collapsed per proxyset.
	seedBucket(t, q, t0, "residential", `{}`, 100, 0)
	seedBucket(t, q, t0.Add(24*time.Hour), "residential", `{}`, 200, 0)
	seedBucket(t, q, t0, "datacenter", `{}`, 50, 0)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{Granularity: db.GranularityProxyset})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 2 {
		t.Errorf("want 2 proxyset rows, got %d", res.TotalCount)
	}
	for _, row := range res.Rows {
		if row.HourTS != nil || row.Day != nil {
			t.Error("GranularityProxyset: HourTS and Day should be nil")
		}
		if row.Proxyset == nil {
			t.Error("GranularityProxyset: Proxyset should be set")
		}
		if *row.Proxyset == "residential" && row.UploadBytes != 300 {
			t.Errorf("residential: want upload=300, got %d", row.UploadBytes)
		}
	}
}

func TestQueryUsage_GranularityTotal_SingleRow(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	seedBucket(t, q, t0, "residential", `{}`, 100, 200)
	seedBucket(t, q, t0, "datacenter", `{}`, 300, 400)
	seedBucket(t, q, t0.Add(24*time.Hour), "residential", `{}`, 50, 50)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{Granularity: db.GranularityTotal})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("GranularityTotal: want 1 row, got %d", len(res.Rows))
	}
	row := res.Rows[0]
	if row.UploadBytes != 450 {
		t.Errorf("want total upload=450, got %d", row.UploadBytes)
	}
	if row.DownloadBytes != 650 {
		t.Errorf("want total download=650, got %d", row.DownloadBytes)
	}
	if row.HourTS != nil || row.Day != nil || row.Proxyset != nil {
		t.Error("GranularityTotal: all dimension fields should be nil")
	}
}

func TestQueryUsage_InvalidGranularity_ReturnsError(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	_, err := q.QueryUsage(context.Background(), db.UsageFilter{Granularity: "weekly"})
	if err == nil {
		t.Fatal("expected error for invalid granularity")
	}
}

// ---------------------------------------------------------------------------
// QueryUsage — pagination tests
// ---------------------------------------------------------------------------

func TestQueryUsage_Pagination_DefaultPageSize(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	// Seed 5 rows across 5 different hours
	for i := 0; i < 5; i++ {
		seedBucket(t, q, t0.Add(time.Duration(i)*time.Hour), "residential", `{}`, int64(i*10), 0)
	}

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{PageSize: 2, Page: 1})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 5 {
		t.Errorf("want TotalCount=5, got %d", res.TotalCount)
	}
	if len(res.Rows) != 2 {
		t.Errorf("want 2 rows on page 1, got %d", len(res.Rows))
	}
	if res.Page != 1 {
		t.Errorf("want Page=1, got %d", res.Page)
	}
}

func TestQueryUsage_Pagination_Page2(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	for i := 0; i < 5; i++ {
		seedBucket(t, q, t0.Add(time.Duration(i)*time.Hour), "residential", `{}`, int64(i*10), 0)
	}

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{PageSize: 2, Page: 2})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if len(res.Rows) != 2 {
		t.Errorf("want 2 rows on page 2, got %d", len(res.Rows))
	}
}

func TestQueryUsage_Pagination_LastPagePartial(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	for i := 0; i < 5; i++ {
		seedBucket(t, q, t0.Add(time.Duration(i)*time.Hour), "residential", `{}`, int64(i*10), 0)
	}

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{PageSize: 2, Page: 3})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Errorf("want 1 row on last partial page, got %d", len(res.Rows))
	}
}

func TestQueryUsage_Pagination_EmptyTable(t *testing.T) {
	pool := newTestDB(t)
	q := db.New(pool)

	res, err := q.QueryUsage(context.Background(), db.UsageFilter{})
	if err != nil {
		t.Fatalf("QueryUsage: %v", err)
	}
	if res.TotalCount != 0 {
		t.Errorf("want TotalCount=0, got %d", res.TotalCount)
	}
	if len(res.Rows) != 0 {
		t.Errorf("want 0 rows, got %d", len(res.Rows))
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests
// ---------------------------------------------------------------------------

func newUsageServer(t *testing.T) (*db.Queries, *httptest.Server) {
	t.Helper()
	pool := newTestDB(t)
	q := db.New(pool)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/usage", handleQueryUsage(q))
	return q, httptest.NewServer(mux)
}

func getUsage(t *testing.T, srv *httptest.Server, query string) *http.Response {
	t.Helper()
	url := srv.URL + "/api/usage"
	if query != "" {
		url += "?" + query
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET /api/usage: %v", err)
	}
	return resp
}

func decodeUsageResponse(t *testing.T, resp *http.Response) apiUsageResponse {
	t.Helper()
	defer resp.Body.Close()
	var out apiUsageResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func decodeAPIError(t *testing.T, resp *http.Response) apiError {
	t.Helper()
	defer resp.Body.Close()
	var out apiError
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return out
}

func TestHTTP_Usage_EmptyReturns200(t *testing.T) {
	_, srv := newUsageServer(t)
	defer srv.Close()

	resp := getUsage(t, srv, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 0 {
		t.Errorf("want TotalCount=0, got %d", body.TotalCount)
	}
	if body.TotalPages != 1 {
		t.Errorf("want TotalPages=1 for empty result, got %d", body.TotalPages)
	}
}

func TestHTTP_Usage_ReturnsRows(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 100, 200)

	resp := getUsage(t, srv, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200, got %d", resp.StatusCode)
	}
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", body.TotalCount)
	}
	row := body.Rows[0]
	if row.UploadBytes != 100 {
		t.Errorf("want upload=100, got %d", row.UploadBytes)
	}
	if row.DownloadBytes != 200 {
		t.Errorf("want download=200, got %d", row.DownloadBytes)
	}
	if row.TotalBytes != 300 {
		t.Errorf("want total=300, got %d", row.TotalBytes)
	}
	if row.HourTS == nil {
		t.Error("hour_ts should be present")
	}
}

func TestHTTP_Usage_FilterProxyset(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 100, 0)
	seedBucket(t, q, t0, "datacenter", `{}`, 200, 0)

	resp := getUsage(t, srv, "proxyset=datacenter")
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", body.TotalCount)
	}
	if *body.Rows[0].Proxyset != "datacenter" {
		t.Errorf("want proxyset=datacenter, got %q", *body.Rows[0].Proxyset)
	}
}

func TestHTTP_Usage_FilterFromTo(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0.Add(-2*time.Hour), "residential", `{}`, 1, 0)
	seedBucket(t, q, t0, "residential", `{}`, 100, 0)
	seedBucket(t, q, t0.Add(2*time.Hour), "residential", `{}`, 1, 0)

	query := "from=" + t0.Format(time.RFC3339) + "&to=" + t0.Format(time.RFC3339)
	resp := getUsage(t, srv, query)
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", body.TotalCount)
	}
}

func TestHTTP_Usage_FilterMeta(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{"user":"alice"}`, 100, 0)
	seedBucket(t, q, t0, "residential", `{"user":"bob"}`, 200, 0)

	resp := getUsage(t, srv, `meta={"user":"alice"}`)
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 1 {
		t.Errorf("want TotalCount=1, got %d", body.TotalCount)
	}
}

func TestHTTP_Usage_GranularityTotal(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 100, 200)
	seedBucket(t, q, t0, "datacenter", `{}`, 300, 400)

	resp := getUsage(t, srv, "granularity=total")
	body := decodeUsageResponse(t, resp)
	if len(body.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(body.Rows))
	}
	if body.Rows[0].UploadBytes != 400 {
		t.Errorf("want upload=400, got %d", body.Rows[0].UploadBytes)
	}
	if body.Rows[0].TotalBytes != 1000 {
		t.Errorf("want total=1000, got %d", body.Rows[0].TotalBytes)
	}
}

func TestHTTP_Usage_GranularityDay(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 100, 0)
	seedBucket(t, q, t0.Add(time.Hour), "residential", `{}`, 50, 0)

	resp := getUsage(t, srv, "granularity=day")
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 1 {
		t.Errorf("want 1 day row, got %d", body.TotalCount)
	}
	if body.Rows[0].Day == nil {
		t.Error("day field should be set for granularity=day")
	}
	if body.Rows[0].HourTS != nil {
		t.Error("hour_ts should not be set for granularity=day")
	}
}

func TestHTTP_Usage_GranularityProxyset(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 100, 0)
	seedBucket(t, q, t0.Add(24*time.Hour), "residential", `{}`, 200, 0)
	seedBucket(t, q, t0, "datacenter", `{}`, 50, 0)

	resp := getUsage(t, srv, "granularity=proxyset")
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 2 {
		t.Errorf("want 2 proxyset rows, got %d", body.TotalCount)
	}
	for _, row := range body.Rows {
		if row.Proxyset == nil {
			t.Error("proxyset field should be set")
		}
		if *row.Proxyset == "residential" && row.UploadBytes != 300 {
			t.Errorf("residential upload want 300, got %d", row.UploadBytes)
		}
	}
}

func TestHTTP_Usage_Pagination(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		seedBucket(t, q, t0.Add(time.Duration(i)*time.Hour), "residential", `{}`, int64(i), 0)
	}

	resp := getUsage(t, srv, "page=1&page_size=2")
	body := decodeUsageResponse(t, resp)
	if body.TotalCount != 5 {
		t.Errorf("want TotalCount=5, got %d", body.TotalCount)
	}
	if len(body.Rows) != 2 {
		t.Errorf("want 2 rows, got %d", len(body.Rows))
	}
	if body.TotalPages != 3 {
		t.Errorf("want TotalPages=3, got %d", body.TotalPages)
	}
	if body.Page != 1 {
		t.Errorf("want Page=1, got %d", body.Page)
	}
	if body.PageSize != 2 {
		t.Errorf("want PageSize=2, got %d", body.PageSize)
	}
}

func TestHTTP_Usage_InvalidFrom_Returns400(t *testing.T) {
	_, srv := newUsageServer(t)
	defer srv.Close()

	resp := getUsage(t, srv, "from=not-a-date")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
	body := decodeAPIError(t, resp)
	if body.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestHTTP_Usage_InvalidTo_Returns400(t *testing.T) {
	_, srv := newUsageServer(t)
	defer srv.Close()

	resp := getUsage(t, srv, "to=not-a-date")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestHTTP_Usage_InvalidGranularity_Returns400(t *testing.T) {
	_, srv := newUsageServer(t)
	defer srv.Close()

	resp := getUsage(t, srv, "granularity=weekly")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
	body := decodeAPIError(t, resp)
	if body.Error == "" {
		t.Error("expected non-empty error message")
	}
}

func TestHTTP_Usage_InvalidPage_Returns400(t *testing.T) {
	_, srv := newUsageServer(t)
	defer srv.Close()

	resp := getUsage(t, srv, "page=0")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestHTTP_Usage_InvalidPageSize_Returns400(t *testing.T) {
	_, srv := newUsageServer(t)
	defer srv.Close()

	resp := getUsage(t, srv, "page_size=-1")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("want 400, got %d", resp.StatusCode)
	}
}

func TestHTTP_Usage_HourTSFormattedAsRFC3339(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 1, 1)

	resp := getUsage(t, srv, "")
	body := decodeUsageResponse(t, resp)
	if len(body.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(body.Rows))
	}
	if body.Rows[0].HourTS == nil {
		t.Fatal("hour_ts should be set")
	}
	if _, err := time.Parse(time.RFC3339, *body.Rows[0].HourTS); err != nil {
		t.Errorf("hour_ts not RFC3339: %q: %v", *body.Rows[0].HourTS, err)
	}
}

func TestHTTP_Usage_DayFormattedAsDate(t *testing.T) {
	q, srv := newUsageServer(t)
	defer srv.Close()

	seedBucket(t, q, t0, "residential", `{}`, 1, 1)

	resp := getUsage(t, srv, "granularity=day")
	body := decodeUsageResponse(t, resp)
	if len(body.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(body.Rows))
	}
	if body.Rows[0].Day == nil {
		t.Fatal("day should be set")
	}
	if _, err := time.Parse("2006-01-02", *body.Rows[0].Day); err != nil {
		t.Errorf("day not YYYY-MM-DD: %q: %v", *body.Rows[0].Day, err)
	}
}
