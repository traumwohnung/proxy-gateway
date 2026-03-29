package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
)

// stubUpstream for testing — never actually dials.
type stubUpstream struct{}

func (stubUpstream) Dial(_ context.Context, _ *Proxy, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("stub: not dialing")
}

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.Certificate) == 0 {
		t.Fatal("expected certificate")
	}
	if ca.PrivateKey == nil {
		t.Fatal("expected private key")
	}
}

func TestMITMPassesThroughWhenNoConn(t *testing.T) {
	ca, _ := GenerateCA()
	called := false
	inner := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		called = true
		return ProxyResult(&Proxy{Host: "upstream", Port: 8080}), nil
	})

	h := MITM(ca, stubUpstream{}, inner)
	req := &Request{RawUsername: "user", Target: "example.com:80"}
	result, err := h.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("inner should be called for non-CONNECT")
	}
	if result == nil || result.Proxy == nil || result.Proxy.Host != "upstream" {
		t.Fatal("should return inner's proxy")
	}
}

func TestMITMPassesThroughWhenTLSAlreadyBroken(t *testing.T) {
	ca, _ := GenerateCA()
	called := false
	inner := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		called = true
		return ProxyResult(&Proxy{Host: "upstream", Port: 8080}), nil
	})

	h := MITM(ca, stubUpstream{}, inner)
	ctx := WithTLSState(context.Background(), TLSState{Broken: true})
	req := &Request{Target: "example.com:443"}
	h.Resolve(ctx, req)
	if !called {
		t.Fatal("inner should be called when TLS already broken")
	}
}

func TestBlockingMiddlewareWorksWithHTTPRequest(t *testing.T) {
	blocker := HandlerFunc(func(_ context.Context, req *Request) (*Result, error) {
		if req.HTTPRequest != nil && req.HTTPRequest.URL.Host == "blocked.com" {
			return nil, fmt.Errorf("blocked")
		}
		return ProxyResult(&Proxy{Host: "upstream", Port: 8080}), nil
	})

	httpReq, _ := http.NewRequest("GET", "https://blocked.com/page", nil)
	req := &Request{HTTPRequest: httpReq}
	ctx := WithTLSState(context.Background(), TLSState{Broken: true})
	_, err := blocker.Resolve(ctx, req)
	if err == nil {
		t.Fatal("expected block error")
	}

	httpReq2, _ := http.NewRequest("GET", "https://allowed.com/page", nil)
	req2 := &Request{HTTPRequest: httpReq2}
	result, err := blocker.Resolve(ctx, req2)
	if err != nil || result == nil || result.Proxy == nil {
		t.Fatal("should pass for allowed domain")
	}
}

func TestResponseHookOnResult(t *testing.T) {
	// ResponseHook is now on Result, not Request.
	result := &Result{
		Proxy: &Proxy{Host: "upstream", Port: 8080},
		ResponseHook: func(resp *http.Response) *http.Response {
			resp.Header.Set("X-Hooked", "yes")
			return resp
		},
	}

	resp := &http.Response{Header: http.Header{}}
	result.ResponseHook(resp)
	if resp.Header.Get("X-Hooked") != "yes" {
		t.Fatal("hook should fire")
	}
}
