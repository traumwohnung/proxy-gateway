package proxygatewayclient_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestE2E_HTTPCloak_WebSocket_MITM(t *testing.T) {
	wsAddr := startWebSocketEchoServer(t)

	gatewayHTTPAddr, stopGW := startMITMGateway(t)
	defer stopGW()

	usernameJSON := `{"set":"direct","httpcloak":"chrome-latest"}`
	username := base64.StdEncoding.EncodeToString([]byte(usernameJSON))
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":x"))

	// 1. CONNECT to proxy-gateway
	gwConn, err := net.DialTimeout("tcp", gatewayHTTPAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer gwConn.Close()
	gwConn.SetDeadline(time.Now().Add(15 * time.Second))

	fmt.Fprintf(gwConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		wsAddr, wsAddr, creds)

	br := bufio.NewReader(gwConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("draining CONNECT headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// 2. TLS handshake (MITM will intercept)
	tlsConn := tls.Client(newBufConn(gwConn, br), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         "localhost",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// 3. Send WebSocket upgrade request
	wsKey := base64.StdEncoding.EncodeToString([]byte("test-websocket-key!"))
	fmt.Fprintf(tlsConn, "GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", wsAddr, wsKey)

	// 4. Read upgrade response
	tlsBr := bufio.NewReader(tlsConn)
	upgradeStatus, err := tlsBr.ReadString('\n')
	if err != nil {
		t.Fatalf("reading upgrade status: %v", err)
	}
	if !strings.Contains(upgradeStatus, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", strings.TrimSpace(upgradeStatus))
	}
	t.Logf("upgrade response: %s", strings.TrimSpace(upgradeStatus))
	for {
		line, err := tlsBr.ReadString('\n')
		if err != nil {
			t.Fatalf("draining upgrade headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// 5. Send a WebSocket text frame and read the echo
	message := []byte("hello from proxy-gateway e2e test")
	wsWriteTextFrame(tlsConn, message)

	opcode, payload := wsReadFrame(t, tlsBr)
	if opcode != 1 {
		t.Fatalf("expected text frame (opcode 1), got opcode %d", opcode)
	}
	if string(payload) != string(message) {
		t.Fatalf("expected echo %q, got %q", message, payload)
	}
	t.Logf("WebSocket echo OK: %q", payload)
}

// startWebSocketEchoServer starts a TLS server that accepts WebSocket upgrades
// and echoes back any received frames. Returns the host:port address.
func startWebSocketEchoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws echo listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	certPEM, keyPEM := generateSelfSignedCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsLn, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		t.Fatalf("ws echo tls listen: %v", err)
	}

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go handleWebSocketConn(conn)
		}
	}()
	t.Cleanup(func() { tlsLn.Close() })
	return addr
}

func handleWebSocketConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	accept := computeWebSocketAccept(key)

	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n"+
		"\r\n", accept)

	for {
		opcode, payload, err := wsReadFrameRaw(br)
		if err != nil {
			return
		}
		if opcode == 8 {
			return
		}
		wsWriteTextFrame(conn, payload)
		_ = opcode
	}
}
