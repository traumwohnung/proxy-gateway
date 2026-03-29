// Package gateway provides HTTP and SOCKS5 proxy servers that delegate
// proxy resolution to a core.Handler pipeline.
//
// The gateway only extracts raw credentials from the transport protocol
// (Basic auth username+password, SOCKS5 username+password) and puts them
// into Request.RawUsername and Request.RawPassword. It does NOT interpret
// the username format — that's the responsibility of middleware.
package gateway

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"proxy-gateway/core"
)

// Run starts an HTTP proxy server on addr and blocks.
func Run(addr string, handler core.Handler) error {
	slog.Info("HTTP proxy gateway listening", "addr", addr)
	return http.ListenAndServe(addr, HTTPHandler(handler))
}

// HTTPHandler returns an http.Handler that serves HTTP proxy requests.
func HTTPHandler(handler core.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		// Extract raw credentials from Basic auth — no parsing.
		rawUsername, rawPassword, err := extractBasicAuth(r.Header.Get("Proxy-Authorization"))
		if err != nil {
			slog.Warn("auth error", "method", r.Method, "uri", r.RequestURI, "client", clientIP, "err", err)
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy-gateway"`)
			http.Error(w, err.Error(), http.StatusProxyAuthRequired)
			return
		}

		req := &core.Request{
			RawUsername: rawUsername,
			RawPassword: rawPassword,
			Target:      r.Host,
		}

		proxy, err := handler.Resolve(r.Context(), req)
		if err != nil {
			slog.Warn("resolve error", "client", clientIP, "err", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if proxy == nil {
			http.Error(w, "no proxy available", http.StatusServiceUnavailable)
			return
		}

		slog.Info("routing",
			"method", r.Method,
			"uri", r.RequestURI,
			"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
			"upstream_proto", proxy.GetProtocol(),
			"client", clientIP,
		)

		var handle core.ConnHandle
		if tracker, ok := handler.(core.ConnectionTracker); ok {
			handle, err = tracker.OpenConnection(req.Sub)
			if err != nil {
				slog.Warn("connection rejected", "sub", req.Sub, "err", err)
				http.Error(w, err.Error(), http.StatusTooManyRequests)
				return
			}
		}

		if r.Method == http.MethodConnect {
			serveConnect(w, r, proxy, handle)
		} else {
			serveHTTP(w, r, proxy, handle)
		}
	})
}

// extractBasicAuth decodes "Basic <b64>" into raw username and password
// without interpreting the username content at all.
func extractBasicAuth(headerVal string) (username, password string, err error) {
	b64, ok := strings.CutPrefix(headerVal, "Basic ")
	if !ok {
		return "", "", fmt.Errorf("Proxy-Authorization must use Basic scheme")
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 in Proxy-Authorization")
	}
	raw := string(decoded)
	colonIdx := strings.LastIndex(raw, ":")
	if colonIdx < 0 {
		return raw, "", nil
	}
	return raw[:colonIdx], raw[colonIdx+1:], nil
}

// ---------------------------------------------------------------------------
// HTTP CONNECT
// ---------------------------------------------------------------------------

func serveConnect(w http.ResponseWriter, r *http.Request, proxy *core.Proxy, handle core.ConnHandle) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	defer clientConn.Close()

	upstreamConn, err := dialUpstream(proxy, r.Host)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	sent, received := relay(clientConn, upstreamConn, handle)
	if handle != nil {
		handle.Close(sent, received)
	}
}

// ---------------------------------------------------------------------------
// Plain HTTP forwarding
// ---------------------------------------------------------------------------

func serveHTTP(w http.ResponseWriter, r *http.Request, proxy *core.Proxy, handle core.ConnHandle) {
	var headers []string
	for name, values := range r.Header {
		if isHopByHop(name) {
			continue
		}
		for _, v := range values {
			headers = append(headers, name+": "+v)
		}
	}
	uri := r.RequestURI
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		uri = "http://" + r.Host + uri
	}

	raw, err := ForwardHTTP(r.Method, uri, headers, r.Body, proxy)

	if handle != nil {
		var reqBytes int64
		if r.ContentLength > 0 {
			reqBytes = r.ContentLength
		}
		respBytes := int64(len(raw))
		handle.RecordTraffic(true, reqBytes, func() {})
		handle.RecordTraffic(false, respBytes, func() {})
		handle.Close(reqBytes, respBytes)
	}

	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeRawResponse(w, raw)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeRawResponse(w http.ResponseWriter, raw []byte) {
	headerEnd := len(raw)
	for i := 0; i+4 <= len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			headerEnd = i
			break
		}
	}
	bodyStart := headerEnd + 4
	if bodyStart > len(raw) {
		bodyStart = len(raw)
	}
	lines := strings.Split(string(raw[:headerEnd]), "\r\n")
	if len(lines) == 0 {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	statusCode := http.StatusBadGateway
	if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			statusCode = code
		}
	}
	for _, line := range lines[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok {
			w.Header().Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(raw[bodyStart:])
}

func hostPort(host string, port uint16) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func isHopByHop(header string) bool {
	switch http.CanonicalHeaderKey(header) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}
