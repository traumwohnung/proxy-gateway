package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"proxy-kit/utils"
	db "proxy-gateway/db/gen"
)

// ---------------------------------------------------------------------------
// API response types — match the TS client's expected schema
// ---------------------------------------------------------------------------

type apiError struct {
	Error string `json:"error"`
}

type apiSessionInfo struct {
	SessionID      uint64                 `json:"session_id"`
	Username       string                 `json:"username"`
	ProxySet       string                 `json:"proxy_set"`
	Upstream       string                 `json:"upstream"`
	CreatedAt      string                 `json:"created_at"`
	NextRotationAt string                 `json:"next_rotation_at"`
	LastRotationAt string                 `json:"last_rotation_at"`
	Metadata       map[string]interface{} `json:"metadata"`
}

func toAPISessionInfo(info *utils.SessionInfo) *apiSessionInfo {
	u, _ := ParseUsername(info.Label)

	set := ""
	meta := map[string]interface{}{}
	if u != nil {
		set = u.Affinity.Set
		if u.Affinity.Meta != nil {
			meta = u.Affinity.Meta
		}
	}

	return &apiSessionInfo{
		SessionID:      info.ID,
		Username:       base64.StdEncoding.EncodeToString([]byte(info.Label)),
		ProxySet:       set,
		Upstream:       info.Upstream,
		CreatedAt:      info.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		NextRotationAt: info.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		LastRotationAt: info.LastRotationAt.UTC().Format("2006-01-02T15:04:05Z"),
		Metadata:       meta,
	}
}

// ---------------------------------------------------------------------------
// Middleware & helpers
// ---------------------------------------------------------------------------

func bearerAuth(apiKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token != apiKey {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "Invalid or missing API key"})
			return
		}
		next(w, r)
	}
}

func decodeBase64Username(encoded string) (*Username, error) {
	// The URL parameter is the base64 username produced by the client.
	// ParseUsername already handles base64 → JSON decoding.
	return ParseUsername(encoded)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func handleListSessions(sessions *utils.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := sessions.ListEntries()
		out := make([]apiSessionInfo, 0, len(entries))
		for _, e := range entries {
			out = append(out, *toAPISessionInfo(&e))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func handleGetSession(sessions *utils.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := decodeBase64Username(chi.URLParam(r, "username"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid username"})
			return
		}
		info := sessions.GetSession(u.Affinity.Seed())
		if info == nil {
			writeJSON(w, http.StatusNotFound, apiError{Error: "no active session"})
			return
		}
		writeJSON(w, http.StatusOK, toAPISessionInfo(info))
	}
}

func handleForceRotate(sessions *utils.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := decodeBase64Username(chi.URLParam(r, "username"))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid username"})
			return
		}
		info, err := sessions.ForceRotate(u.Affinity.Seed())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}
		if info == nil {
			writeJSON(w, http.StatusNotFound, apiError{Error: "no active session"})
			return
		}
		writeJSON(w, http.StatusOK, toAPISessionInfo(info))
	}
}

// ---------------------------------------------------------------------------
// Usage query handler
// ---------------------------------------------------------------------------

type apiUsageRow struct {
	HourTS         *string `json:"hour_ts,omitempty"`
	Day            *string `json:"day,omitempty"`
	Proxyset       *string `json:"proxyset,omitempty"`
	AffinityParams *string `json:"affinity_params,omitempty"`
	UploadBytes    int64   `json:"upload_bytes"`
	DownloadBytes  int64   `json:"download_bytes"`
	TotalBytes     int64   `json:"total_bytes"`
}

type apiUsageResponse struct {
	Rows       []apiUsageRow `json:"rows"`
	TotalCount int64         `json:"total_count"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int64         `json:"total_pages"`
}

func handleQueryUsage(queries *db.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		var filter db.UsageFilter
		var parseErr string

		if s := q.Get("from"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				parseErr = fmt.Sprintf("invalid 'from': %v", err)
			} else {
				filter.From = &t
			}
		}
		if s := q.Get("to"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				parseErr = fmt.Sprintf("invalid 'to': %v", err)
			} else {
				filter.To = &t
			}
		}
		if parseErr != "" {
			writeJSON(w, http.StatusBadRequest, apiError{Error: parseErr})
			return
		}

		filter.Proxyset = q.Get("proxyset")
		filter.MetaContains = q.Get("meta")

		if s := q.Get("granularity"); s != "" {
			switch db.Granularity(s) {
			case db.GranularityHour, db.GranularityDay, db.GranularityProxyset, db.GranularityTotal:
				filter.Granularity = db.Granularity(s)
			default:
				writeJSON(w, http.StatusBadRequest, apiError{Error: fmt.Sprintf("invalid granularity %q (valid: hour, day, proxyset, total)", s)})
				return
			}
		}

		if s := q.Get("page"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid 'page': must be a positive integer"})
				return
			}
			filter.Page = n
		}
		if s := q.Get("page_size"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid 'page_size': must be a positive integer"})
				return
			}
			filter.PageSize = n
		}

		result, err := queries.QueryUsage(r.Context(), filter)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
			return
		}

		rows := make([]apiUsageRow, 0, len(result.Rows))
		for _, row := range result.Rows {
			ar := apiUsageRow{
				Proxyset:       row.Proxyset,
				AffinityParams: row.AffinityParams,
				UploadBytes:    row.UploadBytes,
				DownloadBytes:  row.DownloadBytes,
				TotalBytes:     row.UploadBytes + row.DownloadBytes,
			}
			if row.HourTS != nil {
				s := row.HourTS.UTC().Format(time.RFC3339)
				ar.HourTS = &s
			}
			if row.Day != nil {
				s := row.Day.UTC().Format("2006-01-02")
				ar.Day = &s
			}
			rows = append(rows, ar)
		}

		totalPages := (result.TotalCount + int64(result.PageSize) - 1) / int64(result.PageSize)
		if totalPages == 0 {
			totalPages = 1
		}

		writeJSON(w, http.StatusOK, apiUsageResponse{
			Rows:       rows,
			TotalCount: result.TotalCount,
			Page:       result.Page,
			PageSize:   result.PageSize,
			TotalPages: totalPages,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
