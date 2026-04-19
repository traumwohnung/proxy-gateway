package proxygatewayclient_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
)

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

type testEnv struct {
	// Addresses
	gatewayHTTPAddr   string
	gatewaySOCKS5Addr string
	adminAddr         string
	echoAddr          string

	// Go client
	client *proxygatewayclient.Client

	// Cleanup
	cleanup func()
}

// startTestEnv spins up:
//  1. N upstream HTTP proxy servers (plain CONNECT forwarders)
//  2. An HTTP echo server
//  3. The proxy-gateway binary pointing at those upstreams
//
// It returns a testEnv with all addresses wired up.
func startTestEnv(t *testing.T, numUpstreamProxies int, proxyPassword string) *testEnv {
	t.Helper()

	// --- echo server ---
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	echoAddr := echoLn.Addr().String()
	echoSrv := &http.Server{Handler: echoHandler()}
	go echoSrv.Serve(echoLn) //nolint:errcheck

	// --- N upstream HTTP proxy servers ---
	upstreamAddrs := make([]string, numUpstreamProxies)
	upstreamSrvs := make([]*http.Server, numUpstreamProxies)
	for i := 0; i < numUpstreamProxies; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("upstream proxy listen: %v", err)
		}
		upstreamAddrs[i] = ln.Addr().String()
		srv := &http.Server{Handler: upstreamProxyHandler()}
		upstreamSrvs[i] = srv
		go srv.Serve(ln) //nolint:errcheck
	}

	// --- proxy-gateway config ---
	tmpDir := t.TempDir()

	// Write proxy list file(s): one file per upstream
	var proxyLines []string
	for _, addr := range upstreamAddrs {
		proxyLines = append(proxyLines, addr) // host:port, no auth
	}
	proxyFile := filepath.Join(tmpDir, "proxies.txt")
	if err := os.WriteFile(proxyFile, []byte(strings.Join(proxyLines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write proxies file: %v", err)
	}

	// Pick free ports for gateway
	gatewayHTTPAddr := freeAddr(t)
	gatewaySOCKS5Addr := freeAddr(t)
	adminAddr := freeAddr(t)

	cfg := fmt.Sprintf(`
bind_addr   = %q
socks5_addr = %q
admin_addr  = %q
log_level   = "warn"

[[proxy_set]]
name        = "test"
source_type = "static_file"

[proxy_set.static_file]
proxies_file = %q
`, gatewayHTTPAddr, gatewaySOCKS5Addr, adminAddr, proxyFile)

	cfgFile := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- build & start proxy-gateway binary ---
	binPath := filepath.Join(tmpDir, "proxy-gateway-server")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = filepath.Join(repoRoot(t), "proxy-gateway")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build proxy-gateway: %v", err)
	}

	env := os.Environ()
	env = append(env, "API_KEY=test-api-key")
	if proxyPassword != "" {
		env = append(env, "PROXY_PASSWORD="+proxyPassword)
	}

	cmd := exec.Command(binPath, cfgFile)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy-gateway: %v", err)
	}

	// Wait for all ports to be ready
	waitReady(t, gatewayHTTPAddr, 5*time.Second)
	waitReady(t, gatewaySOCKS5Addr, 5*time.Second)
	waitReady(t, adminAddr, 5*time.Second)

	client := proxygatewayclient.New(proxygatewayclient.ClientOptions{
		BaseURL: "http://" + adminAddr,
		APIKey:  "test-api-key",
	})

	cleanup := func() {
		cmd.Process.Kill()   //nolint:errcheck
		echoSrv.Close()      //nolint:errcheck
		for _, s := range upstreamSrvs {
			s.Close() //nolint:errcheck
		}
	}

	return &testEnv{
		gatewayHTTPAddr:   gatewayHTTPAddr,
		gatewaySOCKS5Addr: gatewaySOCKS5Addr,
		adminAddr:         adminAddr,
		echoAddr:          echoAddr,
		client:            client,
		cleanup:           cleanup,
	}
}

// ---------------------------------------------------------------------------
// HTTP echo server
// ---------------------------------------------------------------------------

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{}
		for k, vs := range r.Header {
			headers[strings.ToLower(k)] = strings.Join(vs, ", ")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method":          r.Method,
			"path":            r.URL.Path,
			"remote_addr":     r.RemoteAddr,
			"x-forwarded-via": r.Header.Get("X-Forwarded-Via"),
			"headers":         headers,
		})
	})
}

// ---------------------------------------------------------------------------
// Upstream HTTP proxy server (simple CONNECT forwarder)
// ---------------------------------------------------------------------------

func upstreamProxyHandler() http.Handler {
	var selfAddr atomic.Value
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Context().Value(http.LocalAddrContextKey); a != nil && selfAddr.Load() == nil {
			selfAddr.Store(fmt.Sprintf("%v", a))
		}
		addr, _ := selfAddr.Load().(string)

		if r.Method == http.MethodConnect {
			targetConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				http.Error(w, "dial failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			defer targetConn.Close()

			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			clientConn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			defer clientConn.Close()

			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(targetConn, clientConn) }() //nolint:errcheck
			go func() { defer wg.Done(); io.Copy(clientConn, targetConn) }() //nolint:errcheck
			wg.Wait()
			return
		}

		r.Header.Set("X-Forwarded-Via", addr)
		r.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	})
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

func mustBuildUsername(t *testing.T, set string, minutes int, meta map[string]any) string {
	t.Helper()
	u, err := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
		Set:     set,
		Minutes: minutes,
		Meta:    meta,
	})
	if err != nil {
		t.Fatalf("BuildUsername: %v", err)
	}
	return u
}

func doHTTPConnectToEcho(t *testing.T, gatewayAddr, echoAddr, username, password string) map[string]any {
	t.Helper()
	body, err := httpConnectToEcho(gatewayAddr, echoAddr, username, password)
	if err != nil {
		t.Fatalf("httpConnectToEcho: %v", err)
	}
	return body
}

func tryHTTPConnect(t *testing.T, gatewayAddr, echoAddr, username, password string) error {
	t.Helper()
	_, err := httpConnectToEcho(gatewayAddr, echoAddr, username, password)
	return err
}

func httpConnectToEcho(gatewayAddr, echoAddr, username, password string) (map[string]any, error) {
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	conn, err := net.DialTimeout("tcp", gatewayAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		echoAddr, echoAddr, creds)

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading status line: %w", err)
	}
	if !strings.Contains(statusLine, "200") {
		return nil, fmt.Errorf("CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("draining headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr)

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading echo response: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading echo body: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing echo body %q: %w", body, err)
	}
	return result, nil
}

func doSOCKS5ToEcho(t *testing.T, gatewayAddr, echoAddr, username, password string) map[string]any {
	t.Helper()

	conn, err := net.DialTimeout("tcp", gatewayAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 gateway: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := socks5Handshake(conn, username, password, echoAddr); err != nil {
		t.Fatalf("SOCKS5 handshake: %v", err)
	}

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading SOCKS5 echo response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parsing SOCKS5 echo body %q: %v", body, err)
	}
	return result
}

func socks5Handshake(conn net.Conn, user, pass, target string) error {
	conn.Write([]byte{0x05, 0x01, 0x02})
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if choice[1] == 0xFF {
		return fmt.Errorf("server rejected all auth methods")
	}
	if choice[1] == 0x02 {
		ub, pb := []byte(user), []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		conn.Write(msg)
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			return fmt.Errorf("auth resp: %w", err)
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("auth failed (0x%02x)", ar[1])
		}
	}
	host, portStr, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT refused (0x%02x)", reply[1])
	}
	return nil
}

func doPlainHTTP(t *testing.T, gatewayAddr, targetURL, username, password string) (int, map[string]any) {
	t.Helper()
	pu, _ := url.Parse("http://" + gatewayAddr)
	pu.User = url.UserPassword(username, password)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("plain HTTP via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result) //nolint:errcheck
	return resp.StatusCode, result
}

// ---------------------------------------------------------------------------
// Infrastructure helpers
// ---------------------------------------------------------------------------

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready after %v", addr, timeout)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "proxy-gateway", "main.go")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", dir)
		}
		dir = parent
	}
}

// ---------------------------------------------------------------------------
// TLS / crypto helpers
// ---------------------------------------------------------------------------

func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// bufConn wraps a net.Conn with a bufio.Reader to drain buffered bytes first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(conn net.Conn, r *bufio.Reader) *bufConn {
	return &bufConn{Conn: conn, r: r}
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// ---------------------------------------------------------------------------
// WebSocket frame helpers
// ---------------------------------------------------------------------------

func computeWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5DC11BE65"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsWriteTextFrame(w io.Writer, payload []byte) {
	frame := []byte{0x81} // FIN + text opcode
	if len(payload) < 126 {
		frame = append(frame, byte(len(payload)))
	} else {
		frame = append(frame, 126, byte(len(payload)>>8), byte(len(payload)))
	}
	frame = append(frame, payload...)
	w.Write(frame) //nolint:errcheck
}

func wsReadFrame(t *testing.T, r *bufio.Reader) (opcode byte, payload []byte) {
	t.Helper()
	op, p, err := wsReadFrameRaw(r)
	if err != nil {
		t.Fatalf("reading websocket frame: %v", err)
	}
	return op, p
}

func wsReadFrameRaw(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	opcode = b0 & 0x0F

	b1, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	masked := b1&0x80 != 0
	length := int(b1 & 0x7F)

	if length == 126 {
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, nil, err
		}
		length = int(buf[0])<<8 | int(buf[1])
	} else if length == 127 {
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, nil, err
		}
		length = int(buf[4])<<24 | int(buf[5])<<16 | int(buf[6])<<8 | int(buf[7])
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}
