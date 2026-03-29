package core

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

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

func writeHTTPResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		defer resp.Body.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}
}

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
