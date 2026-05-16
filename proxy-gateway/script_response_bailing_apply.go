// Bail-phase dispatch — drives an ordered chain of *Script against a
// streaming upstream response, calling each script's bail(r) in turn until
// one bails or the chain runs out.
//
// Other phases (future request_modify / response_modify) will live in
// their own files alongside this one and consume the same chain.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const (
	// DefaultChunkBytes is how many additional body bytes the gateway pulls
	// between bail() invocations.
	DefaultChunkBytes = 8 * 1024

	// DefaultReleaseCapBytes is the cumulative cap on bytes the gateway will
	// buffer before releasing the response to the client unconditionally
	// (with the bail chain disabled for the remaining stream).
	DefaultReleaseCapBytes = 1024 * 1024

	// HeaderResponseBailingOutput carries the script's bail string when one in
	// the chain returned one before any body was forwarded to the client.
	HeaderResponseBailingOutput = "X-Script-Response-Bailing-Output"

	// HeaderResponseBailingError carries the script's runtime error message when
	// it raised before any body was forwarded to the client. The header is
	// prefixed with the script name when more than one script is chained.
	HeaderResponseBailingError = "X-Script-Response-Bailing-Error"
)

// ApplyResponseBailing runs each script's bail(r) in chain order against the streaming
// upstream response and returns a (possibly transformed) *http.Response.
// Status code is always preserved.
//
// Per-phase rules:
//
//   - First script that returns a non-empty string wins; subsequent
//     scripts' bail() are NOT called (short-circuit).
//   - A script that raises is marked disabled for this request; later
//     scripts continue to be polled.
//   - When the buffered body reaches releaseCap or upstream EOFs without
//     any script bailing, the chain stops and the response streams as-is.
//
// chunkSize and releaseCap default to DefaultChunkBytes /
// DefaultReleaseCapBytes when zero is passed.
func ApplyResponseBailing(ctx context.Context, chain []*Script, resp *http.Response, chunkSize, releaseCap int) *http.Response {
	if resp == nil || resp.Body == nil || len(chain) == 0 {
		return resp
	}
	// Filter the chain to scripts that actually define bail().
	active := make([]*Script, 0, len(chain))
	for _, s := range chain {
		if s.HasResponseBailing() {
			active = append(active, s)
		}
	}
	if len(active) == 0 {
		return resp
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkBytes
	}
	if releaseCap <= 0 {
		releaseCap = DefaultReleaseCapBytes
	}

	bb := newBufferedBody(resp.Body, releaseCap)
	headers := map[string][]string(resp.Header)

	// Track which scripts have errored — they stay disabled for the rest
	// of the request. Indexed parallel to `active`.
	disabled := make([]bool, len(active))
	scriptErrors := make([]string, 0, 1)

	// Run the chain once now (headers visible, body empty).
	reason, bailedBy, errMsg := callChain(ctx, active, disabled, resp.StatusCode, headers, bb.Peek)
	if errMsg != "" {
		scriptErrors = append(scriptErrors, errMsg)
	}
	if reason != "" {
		_ = bb.Close()
		return bailResponse(resp, bb, reason, bailedBy, scriptErrors)
	}

	// Stream-and-poll until any bail / cap / EOF.
	for {
		if bb.Len() >= releaseCap {
			break
		}
		_, pullErr := bb.Pull(chunkSize)
		if pullErr == io.EOF {
			reason, bailedBy, errMsg = callChain(ctx, active, disabled, resp.StatusCode, headers, bb.Peek)
			if errMsg != "" {
				scriptErrors = append(scriptErrors, errMsg)
			}
			if reason != "" {
				_ = bb.Close()
				return bailResponse(resp, bb, reason, bailedBy, scriptErrors)
			}
			break
		}
		if pullErr != nil {
			break // upstream error; let copyResponse surface it
		}
		reason, bailedBy, errMsg = callChain(ctx, active, disabled, resp.StatusCode, headers, bb.Peek)
		if errMsg != "" {
			scriptErrors = append(scriptErrors, errMsg)
		}
		if reason != "" {
			_ = bb.Close()
			return bailResponse(resp, bb, reason, bailedBy, scriptErrors)
		}
	}

	// Passthrough. Re-attach wrapper + surface any script errors via header.
	resp.Body = bb
	if len(scriptErrors) > 0 {
		resp.Header.Set(HeaderResponseBailingError, truncateForHeader(strings.Join(scriptErrors, " | ")))
	}
	return resp
}

// callChain runs bail() on every still-enabled script in order. Returns:
//   - reason: first non-empty bail string, or ""
//   - bailedBy: name of the script that bailed (empty if none)
//   - errMsg: joined error messages from scripts that raised THIS round,
//             with "script_name: msg" formatting (empty if none)
//
// Scripts that raise are marked disabled in the parallel `disabled` slice.
func callChain(ctx context.Context, scripts []*Script, disabled []bool, status int, headers map[string][]string, peek PeekFunc) (reason, bailedBy, errMsg string) {
	var errs []string
	for i, s := range scripts {
		if disabled[i] {
			continue
		}
		r, err := s.CallResponseBailing(ctx, status, headers, peek)
		if err != nil {
			disabled[i] = true
			errs = append(errs, fmt.Sprintf("%s: %s", s.name, err.Error()))
			slog.Warn("response_bailing script disabled for request after error",
				"script", s.name, "err", err)
			continue
		}
		if r != "" {
			return r, s.name, joinErrs(errs)
		}
	}
	return "", "", joinErrs(errs)
}

func joinErrs(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	return strings.Join(errs, " | ")
}

func bailResponse(orig *http.Response, bb *bufferedBody, reason, bailedBy string, scriptErrors []string) *http.Response {
	out := cloneRespShallow(orig)
	out.Header = cloneHeadersWithoutEncoding(orig.Header)
	out.Header.Set(HeaderResponseBailingOutput, reason)
	if bailedBy != "" {
		out.Header.Set("X-Script-Response-Bailing-Name", bailedBy)
	}
	if len(scriptErrors) > 0 {
		out.Header.Set(HeaderResponseBailingError, truncateForHeader(strings.Join(scriptErrors, " | ")))
	}
	body := append([]byte(nil), bb.buf...)
	out.Body = io.NopCloser(bytesReader(body))
	out.ContentLength = int64(len(body))
	out.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return out
}

// ── bufferedBody ───────────────────────────────────────────────────────────

// bufferedBody wraps an io.ReadCloser and exposes Peek + Pull semantics for
// the bail-script loop. After the loop releases, the wrapper behaves like a
// normal io.ReadCloser that drains the buffered prefix first then continues
// from upstream.
type bufferedBody struct {
	upstream io.ReadCloser
	buf      []byte
	cap      int
	readPos  int
	closed   bool
	eof      bool
}

func newBufferedBody(upstream io.ReadCloser, cap int) *bufferedBody {
	if cap <= 0 {
		cap = DefaultReleaseCapBytes
	}
	return &bufferedBody{upstream: upstream, cap: cap}
}

func (b *bufferedBody) Peek(n int) []byte {
	if n < 0 || n >= len(b.buf) {
		return b.buf
	}
	return b.buf[:n]
}

func (b *bufferedBody) Pull(n int) (int, error) {
	if b.eof {
		return 0, io.EOF
	}
	if n <= 0 {
		return 0, nil
	}
	if remaining := b.cap - len(b.buf); n > remaining {
		n = remaining
	}
	if n <= 0 {
		return 0, errors.New("buffer cap reached")
	}
	chunk := make([]byte, n)
	m, err := b.upstream.Read(chunk)
	if m > 0 {
		b.buf = append(b.buf, chunk[:m]...)
	}
	if err == io.EOF {
		b.eof = true
	}
	return m, err
}

func (b *bufferedBody) Len() int { return len(b.buf) }

func (b *bufferedBody) Read(p []byte) (int, error) {
	if b.readPos < len(b.buf) {
		n := copy(p, b.buf[b.readPos:])
		b.readPos += n
		return n, nil
	}
	if b.closed || b.eof {
		return 0, io.EOF
	}
	return b.upstream.Read(p)
}

func (b *bufferedBody) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	return b.upstream.Close()
}

// ── small helpers ─────────────────────────────────────────────────────────

func cloneRespShallow(r *http.Response) *http.Response {
	cp := *r
	return &cp
}

func cloneHeadersWithoutEncoding(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Content-Encoding") ||
			strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		out[k] = v
	}
	return out
}

func truncateForHeader(s string) string {
	const maxHeaderValue = 512
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > maxHeaderValue {
		s = s[:maxHeaderValue-1] + "…"
	}
	return s
}

type bytesReadCloser struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReadCloser { return &bytesReadCloser{data: data} }

func (b *bytesReadCloser) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

func (b *bytesReadCloser) Close() error { return nil }
