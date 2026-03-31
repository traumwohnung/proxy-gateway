package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"proxy-kit/utils"
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
