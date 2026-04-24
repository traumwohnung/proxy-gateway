package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
	httpcloakdns "github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	httpcloaktransport "github.com/sardanioss/httpcloak/transport"
	utls "github.com/sardanioss/utls"
	"github.com/ua-parser/uap-go/uaparser"

	proxykit "proxy-kit"
)

var uaParser = uaparser.NewFromSaved()

// ---------------------------------------------------------------------------
// HTTPCloakSpec — the "httpcloak" field in the username JSON
// ---------------------------------------------------------------------------

// HTTPCloakSpec is a union type: either a named preset or a custom fingerprint.
//
// Named preset (JSON string):
//
//	"chrome-latest"
//
// Custom fingerprint (JSON object):
//
//	{"preset":"chrome-latest","ja3":"771,4865-...","akamai":"1:65536|..."}
//
// All fields of the object form are optional; Preset defaults to "chrome-latest"
// when not specified.
type HTTPCloakSpec struct {
	// Preset is the base httpcloak browser preset.
	// For the string form this is the entire value.
	// For the object form it defaults to "chrome-latest".
	Preset string `json:"preset"`

	// Custom TLS (JA3) fingerprint. Overrides the preset's TLS stack.
	// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
	// Example: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
	JA3 string `json:"ja3"`

	// Custom HTTP/2 Akamai fingerprint.
	// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
	// Example: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	Akamai string `json:"akamai"`

	// ALPN overrides the preset's ALPN protocol list.
	// Example: ["h2", "http/1.1"]
	ALPN []string `json:"alpn"`

	// SignatureAlgorithms overrides the preset's TLS signature algorithms.
	// Valid values: "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", etc.
	SignatureAlgorithms []string `json:"sig_algs"`

	// CertCompression overrides the preset's cert compression algorithms.
	// Valid values: "brotli", "zlib", "zstd"
	CertCompression []string `json:"cert_compression"`

	// PermuteExtensions randomises the TLS extension order.
	PermuteExtensions bool `json:"permute_extensions"`

	// ECH controls Encrypted Client Hello (hides SNI from network observers):
	//   nil/true — auto-fetch ECH config from target's DNS (default)
	//   false    — disable ECH (SNI visible in plaintext)
	//   "domain" — fetch ECH config from this domain instead of the target
	ECH any `json:"ech,omitempty"`

	// UserAgent controls how the User-Agent header is handled:
	//   "ignore"  — pass through the client's User-Agent unchanged (default)
	//   "preset"  — replace with the preset's User-Agent
	//   "check"   — reject if the client's User-Agent doesn't match the preset's browser family
	UserAgent string `json:"user_agent"`
}

// ParseHTTPCloakSpec decodes a raw JSON value that is either:
//   - a JSON string  → treated as a preset name (e.g. "chrome-latest")
//   - a JSON object  → parsed as an HTTPCloakSpec struct
//
// Returns (nil, nil) when raw is empty or JSON null.
func ParseHTTPCloakSpec(raw json.RawMessage) (*HTTPCloakSpec, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// null
	if string(raw) == "null" {
		return nil, nil
	}
	// Try string first (named preset shorthand)
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, nil
		}
		return &HTTPCloakSpec{Preset: s}, nil
	}
	// Try object (custom fingerprint)
	var spec HTTPCloakSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("httpcloak must be a preset string or a fingerprint object: %w", err)
	}
	if spec.Preset == "" {
		spec.Preset = "chrome-latest"
	}
	switch spec.UserAgent {
	case "", "ignore", "preset", "check":
		// valid
	default:
		return nil, fmt.Errorf("httpcloak user_agent must be \"ignore\", \"preset\", or \"check\", got %q", spec.UserAgent)
	}
	// Validate ECH field: nil, bool, or string.
	if spec.ECH != nil {
		switch spec.ECH.(type) {
		case bool, string:
			// valid
		case float64:
			// JSON numbers — reject
			return nil, fmt.Errorf("httpcloak ech must be true, false, or a domain string")
		default:
			return nil, fmt.Errorf("httpcloak ech must be true, false, or a domain string, got %T", spec.ECH)
		}
	}
	return &spec, nil
}

// IsZero reports whether the spec is empty / unset.
func (s *HTTPCloakSpec) IsZero() bool {
	return s == nil || s.Preset == ""
}

// transportOptions builds the httpcloak.SessionOption slice for this spec,
// scoped to transport-level concerns only. Used with httpcloak.NewTransport
// — session-level behaviors (cookie jar, redirect follower, retry loop) are
// never applied, so the `WithoutRedirects` / `WithoutRetry` / `ClearCookies`
// workarounds that used to be necessary against httpcloak.Session are gone.
// The proxy is transparent for cookies and redirects by construction.
func (s *HTTPCloakSpec) transportOptions(proxyURL string, insecure bool) []httpcloak.SessionOption {
	opts := []httpcloak.SessionOption{
		httpcloak.WithSessionTimeout(30 * time.Second),
	}
	if proxyURL != "" {
		opts = append(opts, httpcloak.WithSessionProxy(proxyURL))
	}
	if insecure {
		opts = append(opts, httpcloak.WithInsecureSkipVerify())
	}
	// ECH control.
	switch v := s.ECH.(type) {
	case bool:
		if !v {
			opts = append(opts, httpcloak.WithDisableECH())
		}
	case string:
		if v != "" {
			opts = append(opts, httpcloak.WithECHFrom(v))
		}
	}
	// Apply custom fingerprint when any custom field is set.
	if s.JA3 != "" || s.Akamai != "" || len(s.ALPN) > 0 || len(s.SignatureAlgorithms) > 0 || len(s.CertCompression) > 0 || s.PermuteExtensions {
		opts = append(opts, httpcloak.WithCustomFingerprint(httpcloak.CustomFingerprint{
			JA3:                s.JA3,
			Akamai:             s.Akamai,
			ALPN:               s.ALPN,
			SignatureAlgorithms: s.SignatureAlgorithms,
			CertCompression:    s.CertCompression,
			PermuteExtensions:  s.PermuteExtensions,
		}))
	}
	return opts
}

// applyUserAgentPolicy modifies or validates the User-Agent header based on
// the spec's UserAgent mode.
func (s *HTTPCloakSpec) applyUserAgentPolicy(headers map[string][]string) error {
	switch s.UserAgent {
	case "preset":
		preset := fingerprint.Get(s.Preset)
		if preset.UserAgent != "" {
			headers["User-Agent"] = []string{preset.UserAgent}
		}
	case "check":
		preset := fingerprint.Get(s.Preset)
		ua := ""
		for k, vs := range headers {
			if strings.EqualFold(k, "user-agent") && len(vs) > 0 {
				ua = vs[0]
				break
			}
		}
		if ua == "" {
			return fmt.Errorf("user_agent=check: no User-Agent header provided")
		}
		if !userAgentMatchesPreset(ua, preset.UserAgent) {
			return fmt.Errorf("user_agent=check: User-Agent %q is not consistent with preset %q", ua, s.Preset)
		}
	}
	// "ignore" or "": pass through unchanged
	return nil
}

// userAgentMatchesPreset checks if a User-Agent string is consistent with the
// preset's browser family. It parses both the client UA and the preset's UA
// using ua-parser and compares browser families.
func userAgentMatchesPreset(clientUA, presetUA string) bool {
	if presetUA == "" {
		return true // no preset UA to compare against
	}
	clientParsed := uaParser.Parse(clientUA)
	presetParsed := uaParser.Parse(presetUA)

	clientFamily := strings.ToLower(clientParsed.UserAgent.Family)
	presetFamily := strings.ToLower(presetParsed.UserAgent.Family)

	if clientFamily == "" || presetFamily == "" {
		return true // can't determine, allow
	}
	return clientFamily == presetFamily
}

// ---------------------------------------------------------------------------
// TLSFingerprintSpoofing — static MITM middleware (preset-only)
// ---------------------------------------------------------------------------

// TLSFingerprintSpoofing returns MITM middleware that forwards decrypted
// requests using httpcloak, making the upstream TLS handshake look like a
// real browser instead of Go's crypto/tls.
//
// Usage:
//
//	ca, _ := proxykit.NewCA()
//	pipeline := utils.TLSFingerprintSpoofing(ca, "chrome-latest", inner)
//
// Preset examples: "chrome-latest", "firefox-latest", "safari-latest"
func TLSFingerprintSpoofing(ca tls.Certificate, preset string, inner proxykit.Handler) proxykit.Handler {
	return TLSFingerprintSpoofingWithOptions(ca, preset, false, inner)
}

func TLSFingerprintSpoofingWithOptions(ca tls.Certificate, preset string, insecure bool, inner proxykit.Handler) proxykit.Handler {
	certs, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("tls_fingerprint_spoofing: %v", err))
	}
	return proxykit.MITM(certs, &tlsFingerprintInterceptor{
		spec:     &HTTPCloakSpec{Preset: preset},
		insecure: insecure,
	}, inner)
}

// ---------------------------------------------------------------------------
// tlsFingerprintInterceptor
// ---------------------------------------------------------------------------

// tlsFingerprintInterceptor implements proxykit.Interceptor using httpcloak
// to spoof the upstream TLS fingerprint as a real browser or custom spec.
type tlsFingerprintInterceptor struct {
	spec     *HTTPCloakSpec
	insecure bool // skip upstream TLS cert verification (for testing only)
}

// RoundTrip forwards a single decrypted request through the httpcloak session.
//
// There is deliberately no silent retry here. Any error — pooled tunnel
// closed by upstream, CONNECT rejected, dial failure — is surfaced to the
// caller as-is. Transparently reconnecting would open a fresh CONNECT to the
// residential proxy, which performs a new sticky-session lookup and may land
// on a different exit IP. For flows whose state is IP-bound (auth tokens,
// cookie-bound CSRF, OAuth state), a "successful" reconnect is worse than
// a hard failure because it silently invalidates downstream state.
//
// Request body handling: the MITM's http.ReadRequest hands us a *http.body
// whose lifetime is entangled with the keep-alive loop's bufio.Reader. At
// least one path through that machinery closes the body before httpcloak's
// writer finishes reading it, producing
// "http: invalid Read on closed Body" mid-request. We dodge the whole class
// by fully buffering the request body here and handing httpcloak a
// self-contained *bytes.Reader — which also lets httpcloak type-detect
// Content-Length (http.NewRequestWithContext has a switch on *bytes.Reader)
// instead of falling back to chunked transfer-encoding, which some upstream
// APIs reject as malformed.
func (f *tlsFingerprintInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *proxykit.Proxy) (*http.Response, error) {
	proxyURL := proxyToURL(proxy)
	start := time.Now()
	seed := GetTopLevelSeed(ctx)

	// Increment B: one upstream TLS connection per (tunnel, target host,
	// preset, upstream proxy). Lives as long as the MITM tunnel. Bypasses
	// the transport pool so sticky-IP affinity at the upstream proxy is
	// structurally stable — no pool slot death, no silent fresh-CONNECT
	// that re-runs sticky-session lookup.
	//
	// Requires a TunnelScope in ctx (normal MITM path). Without one we
	// cannot own a conn beyond this single request, so fall back to the
	// per-request Transport path for tests / direct use.
	scope := proxykit.GetTunnelScope(ctx)
	if scope == nil {
		return f.roundTripFallback(ctx, httpReq, host, proxyURL, seed, start)
	}

	// httpReq.Host carries the client's Host: header, which for MITM is the
	// authoritative target (may include a non-443 port). Fall back to the
	// CONNECT host with :443 if Host is missing (old clients).
	hostPort := httpReq.Host
	if hostPort == "" {
		hostPort = host + ":443"
	} else if _, _, err := net.SplitHostPort(hostPort); err != nil {
		hostPort = hostPort + ":443"
	}

	slog.Debug("mitm.request.begin",
		"host", host,
		"method", httpReq.Method,
		"path", httpReq.URL.RequestURI(),
		"seed", seed,
		"transport", "owned-conn",
		"upstream_proxy", redactProxyURL(proxyURL),
		"preset", f.spec.Preset)

	// Buffer the request body — bytes.Reader lets httpcloak's request
	// builder type-assert for Content-Length rather than falling back to
	// chunked encoding that some upstream APIs reject.
	reqBody, bodyLen, err := bufferRequestBody(httpReq, host)
	if err != nil {
		return nil, err
	}

	oc, err := f.acquireOwnedConn(ctx, scope, hostPort, proxy, proxyURL)
	if err != nil {
		f.emitRequestEvent(host, httpReq, seed, "owned-conn", bodyLen, nil, time.Since(start), err)
		return nil, fmt.Errorf("acquiring owned conn for %s: %w", hostPort, err)
	}

	treq := &httpcloaktransport.Request{
		Method:     httpReq.Method,
		URL:        f.buildTargetURL(httpReq, host),
		Headers:    filterRequestHeaders(httpReq.Header),
		BodyReader: reqBody,
	}
	if err := f.spec.applyUserAgentPolicy(treq.Headers); err != nil {
		return nil, err
	}

	resp, err := f.doOwnedConnRoundTrip(ctx, oc, treq)
	elapsed := time.Since(start)
	httpResp := f.buildHTTPResponseFromTransport(resp)

	f.emitRequestEvent(host, httpReq, seed, "owned-conn-"+oc.proto, bodyLen, httpResp, elapsed, err)
	if err != nil {
		return nil, fmt.Errorf("httpcloak %s: %w", treq.URL, err)
	}
	return httpResp, nil
}

// roundTripFallback is the per-request Transport path used when no
// TunnelScope is available (tests, direct use). Does not own a connection
// beyond this call. Kept so that non-MITM use of the interceptor still
// works; production MITM always goes through the owned-conn path above.
func (f *tlsFingerprintInterceptor) roundTripFallback(
	ctx context.Context,
	httpReq *http.Request,
	host, proxyURL string,
	seed uint64,
	start time.Time,
) (*http.Response, error) {
	opts := f.spec.transportOptions(proxyURL, f.insecure)
	tr, err := httpcloak.NewTransport(f.spec.Preset, opts...)
	if err != nil {
		return nil, fmt.Errorf("building transport: %w", err)
	}
	defer tr.Close()

	reqBody, bodyLen, err := bufferRequestBody(httpReq, host)
	if err != nil {
		return nil, err
	}

	headers := filterRequestHeaders(httpReq.Header)
	if err := f.spec.applyUserAgentPolicy(headers); err != nil {
		return nil, err
	}
	treq := &httpcloaktransport.Request{
		Method:     httpReq.Method,
		URL:        f.buildTargetURL(httpReq, host),
		Headers:    headers,
		BodyReader: reqBody,
	}

	resp, err := tr.Do(ctx, treq)
	elapsed := time.Since(start)
	httpResp := f.buildHTTPResponseFromTransport(resp)

	f.emitRequestEvent(host, httpReq, seed, "fresh", bodyLen, httpResp, elapsed, err)
	if err != nil {
		return nil, fmt.Errorf("httpcloak %s: %w", treq.URL, err)
	}
	return httpResp, nil
}

// bufferRequestBody reads the MITM client request body into memory and
// returns a *bytes.Reader (type-detected by httpcloak for Content-Length).
// Safe for replay; caller discards the original body.
func bufferRequestBody(httpReq *http.Request, host string) (io.Reader, int, error) {
	if httpReq.Body == nil || httpReq.Method == http.MethodGet || httpReq.Method == http.MethodHead {
		return nil, 0, nil
	}
	bodyBytes, err := io.ReadAll(httpReq.Body)
	httpReq.Body.Close()
	if err != nil {
		slog.Warn("MITM request body buffering failed",
			"host", host, "method", httpReq.Method, "path", httpReq.URL.RequestURI(),
			"err", err)
		return nil, 0, fmt.Errorf("buffering request body: %w", err)
	}
	if len(bodyBytes) == 0 {
		return nil, 0, nil
	}
	return bytes.NewReader(bodyBytes), len(bodyBytes), nil
}

// filterRequestHeaders strips hop-by-hop proxy headers that must not be
// forwarded to the target server.
func filterRequestHeaders(in http.Header) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, vs := range in {
		lower := strings.ToLower(k)
		if lower == "connection" || lower == "proxy-authorization" || lower == "proxy-connection" {
			continue
		}
		out[k] = vs
	}
	return out
}

// buildTargetURL constructs the full https URL we hand to the upstream
// roundtripper, preferring httpReq.Host (which preserves non-standard
// ports like :8443) over the MITM-stripped host.
func (f *tlsFingerprintInterceptor) buildTargetURL(httpReq *http.Request, host string) string {
	urlHost := httpReq.Host
	if urlHost == "" {
		urlHost = host
	}
	return fmt.Sprintf("https://%s%s", urlHost, httpReq.URL.RequestURI())
}

// buildHTTPResponseFromTransport converts a transport.Response into the
// *http.Response the MITM handler writes back to the client.  Transport
// already decompresses per Content-Encoding, so those framing headers are
// stripped before the response is re-serialised by the MITM loop.
func (f *tlsFingerprintInterceptor) buildHTTPResponseFromTransport(resp *httpcloaktransport.Response) *http.Response {
	if resp == nil {
		return nil
	}
	data, err := resp.Bytes()
	if err != nil {
		// Body read failure surfaces at the caller via the error return
		// path; return a minimal shell so the event emitter can still log
		// the status code.
		return &http.Response{
			StatusCode: resp.StatusCode,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}
	}
	httpResp := &http.Response{
		StatusCode:    resp.StatusCode,
		Status:        fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			httpResp.Header.Add(k, v)
		}
	}
	httpResp.Header.Del("Content-Encoding")
	httpResp.Header.Del("Content-Length")
	httpResp.Header.Del("Transfer-Encoding")
	return httpResp
}

// emitRequestEvent writes the unified `mitm.request` structured event
// shared across success and failure paths. Fields and levels are kept
// identical to Increment A so existing log pipelines do not break.
func (f *tlsFingerprintInterceptor) emitRequestEvent(
	host string,
	httpReq *http.Request,
	seed uint64,
	transportSource string,
	bodyLen int,
	resp *http.Response,
	elapsed time.Duration,
	err error,
) {
	event := MITMRequestEvent{
		Host:       host,
		Seed:       seed,
		Preset:     f.spec.Preset,
		SessionSrc: transportSource,
		Method:     httpReq.Method,
		Path:       httpReq.URL.RequestURI(),
		BodyLen:    bodyLen,
		Elapsed:    elapsed,
	}
	if resp != nil {
		event.Status = resp.StatusCode
		event.ContentLen = resp.ContentLength
	}
	if err != nil {
		event.Err = err
		event.ErrKind = ClassifyError(err)
		slog.Warn("mitm.request",
			"host", event.Host,
			"method", event.Method,
			"path", event.Path,
			"seed", event.Seed,
			"preset", event.Preset,
			"transport", event.SessionSrc,
			"body_len", event.BodyLen,
			"status", event.Status,
			"elapsed_ms", event.Elapsed.Milliseconds(),
			"err_kind", string(event.ErrKind),
			"err", event.Err,
			"retryable", event.ErrKind.IsSafeToRetry())
		return
	}
	slog.Debug("mitm.request",
		"host", event.Host,
		"method", event.Method,
		"path", event.Path,
		"seed", event.Seed,
		"preset", event.Preset,
		"transport", event.SessionSrc,
		"body_len", event.BodyLen,
		"status", event.Status,
		"content_length", event.ContentLen,
		"elapsed_ms", event.Elapsed.Milliseconds())
}

// redactProxyURL returns the proxy URL with password stripped — the username
// contains sticky-session identifiers which ARE useful for correlation, so we
// keep those.
func redactProxyURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	j := strings.Index(u[i+3:], "@")
	if j < 0 {
		return u
	}
	authPart := u[i+3 : i+3+j]
	colon := strings.Index(authPart, ":")
	if colon < 0 {
		return u
	}
	return u[:i+3] + authPart[:colon] + ":<redacted>" + u[i+3+j:]
}

// DialTLS implements proxykit.WebSocketDialer. It dials the target with a
// browser-like TLS fingerprint using utls, optionally through an upstream
// proxy. target is "host:port".
func (f *tlsFingerprintInterceptor) DialTLS(ctx context.Context, target string, proxy *proxykit.Proxy) (net.Conn, error) {
	tlsConn, err := f.dialUpstreamTLS(ctx, target, proxy)
	if err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// dialUpstreamTLS dials target through proxy (or direct if proxy.Host is
// empty) with the preset's TCP + TLS fingerprint applied, completes the TLS
// handshake, and returns a post-handshake *utls.UConn. Callers can inspect
// ConnectionState().NegotiatedProtocol to dispatch between HTTP/1.1 and
// HTTP/2 framers on the returned conn.
//
// This is the lowest-level upstream primitive in this package. It owns no
// pool and has no retry — the caller owns the returned conn's lifecycle.
// WebSocket upgrade (DialTLS) and owned-conn MITM roundtrip both build on
// this.
func (f *tlsFingerprintInterceptor) dialUpstreamTLS(ctx context.Context, target string, proxy *proxykit.Proxy) (*utls.UConn, error) {
	preset := fingerprint.Get(f.spec.Preset)
	host, _, _ := net.SplitHostPort(target)

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	httpcloaktransport.SetDialerControl(dialer, &preset.TCPFingerprint)

	var rawConn net.Conn
	var err error
	if proxy.Host == "" {
		rawConn, err = dialer.DialContext(ctx, "tcp", target)
	} else {
		rawConn, err = dialThroughProxy(ctx, dialer, proxy, target)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: f.insecure,
	}

	// Fetch ECH config unless disabled.
	if echDisabled, ok := f.spec.ECH.(bool); !ok || echDisabled != false {
		echDomain := host
		if domain, ok := f.spec.ECH.(string); ok && domain != "" {
			echDomain = domain
		}
		if echConfig, err := httpcloakdns.FetchECHConfigs(ctx, echDomain); err == nil && echConfig != nil {
			tlsConfig.EncryptedClientHelloConfigList = echConfig
		}
	}

	tlsConn := utls.UClient(rawConn, tlsConfig, preset.ClientHelloID)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake %s: %w", host, err)
	}
	return tlsConn, nil
}

// dialThroughProxy establishes a CONNECT tunnel through an upstream HTTP proxy
// and returns the raw tunnel connection.
func dialThroughProxy(ctx context.Context, dialer *net.Dialer, proxy *proxykit.Proxy, target string) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy %s: %w", addr, err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.Username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(proxy.Username + ":" + proxy.Password))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"

	if _, err := fmt.Fprint(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending CONNECT: %w", err)
	}

	// Read response.
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var respBuf []byte
	tmp := make([]byte, 1024)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			respBuf = append(respBuf, tmp[:n]...)
		}
		if readErr != nil {
			conn.Close()
			return nil, fmt.Errorf("reading CONNECT response: %w", readErr)
		}
		if containsCRLFCRLF(respBuf) {
			break
		}
	}
	conn.SetDeadline(time.Time{})

	resp := string(respBuf)
	if len(resp) < 12 || (resp[:12] != "HTTP/1.1 200" && resp[:12] != "HTTP/1.0 200") {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT: %s", resp)
	}
	return conn, nil
}

func containsCRLFCRLF(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// proxyToURL
// ---------------------------------------------------------------------------

// proxyToURL converts a proxykit.Proxy to a URL string for httpcloak.
// Returns "" when proxy.Host is empty, meaning a direct connection (no upstream proxy).
func proxyToURL(proxy *proxykit.Proxy) string {
	if proxy.Host == "" {
		return ""
	}
	var scheme string
	switch proxy.Proto() {
	case proxykit.ProtocolSOCKS5:
		scheme = "socks5"
	default:
		scheme = "http"
	}
	if proxy.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", scheme, proxy.Username, proxy.Password, proxy.Host, proxy.Port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, proxy.Host, proxy.Port)
}

// ---------------------------------------------------------------------------
// ConditionalFingerprintMITM
// ---------------------------------------------------------------------------

// ConditionalFingerprintMITM returns a Handler that activates MITM + httpcloak
// fingerprint spoofing only when getSpec returns a non-nil, non-zero spec.
// When getSpec returns nil the request is forwarded unchanged through inner.
//
// getSpec is typically wired to a context getter set by credential-parsing
// middleware (e.g. getHTTPCloakSpec from proxy-gateway's username.go).
//
// The CA certificate is used to forge per-host TLS certificates for MITM.
// All forged certificates share a single cert cache for efficiency.
//
// Set PROXY_MITM_INSECURE_UPSTREAM=true to skip upstream TLS cert verification
// (useful when testing against servers with self-signed certificates).
func ConditionalFingerprintMITM(ca tls.Certificate, getSpec func(context.Context) *HTTPCloakSpec, inner proxykit.Handler) proxykit.Handler {
	certs, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("ConditionalFingerprintMITM: %v", err))
	}
	insecure := os.Getenv("PROXY_MITM_INSECURE_UPSTREAM") == "true"
	return &conditionalMITMHandler{
		certs:    certs,
		getSpec:  getSpec,
		inner:    inner,
		insecure: insecure,
	}
}

type conditionalMITMHandler struct {
	certs    *proxykit.ForgedCertProvider
	getSpec  func(context.Context) *HTTPCloakSpec
	inner    proxykit.Handler
	insecure bool
}

func (h *conditionalMITMHandler) Resolve(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
	spec := h.getSpec(ctx)
	if spec.IsZero() {
		return h.inner.Resolve(ctx, req)
	}
	interceptor := &tlsFingerprintInterceptor{spec: spec, insecure: h.insecure}
	mitmHandler := proxykit.MITM(h.certs, interceptor, h.inner)
	return mitmHandler.Resolve(ctx, req)
}
