package proxygatewayclient_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestE2E_HTTPCloak_H2_MITM(t *testing.T) {
	echoURL, stopEcho := startFingerprintEchoServer(t)
	defer stopEcho()

	gatewayHTTPAddr, stopGW := startMITMGateway(t)
	defer stopGW()

	usernameJSON := `{"set":"direct","httpcloak":"chrome-latest"}`
	username := base64.StdEncoding.EncodeToString([]byte(usernameJSON))

	proxyRawURL := "http://" + gatewayHTTPAddr
	pu, _ := url.Parse(proxyRawURL)
	pu.User = url.UserPassword(username, "x")

	transport := &http.Transport{
		Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		t.Fatalf("configure h2 transport: %v", err)
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	resp, err := httpClient.Get(echoURL + "/")
	if err != nil {
		t.Fatalf("H2 request through gateway: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("response proto: %s", resp.Proto)
	if resp.ProtoMajor != 2 {
		t.Errorf("expected HTTP/2 on client side, got %s", resp.Proto)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	var result fingerprintEchoResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parsing response %q: %v", body, err)
	}

	if result.Fingerprint.JA3Hash == "" {
		t.Fatalf("expected non-empty ja3_hash (full response: %s)", body)
	}
	t.Logf("ja3_hash=%s  ja4=%s", result.Fingerprint.JA3Hash, result.Fingerprint.JA4)
}
