// Bail-script dispatch — glue that drives a *BailScript against a streaming
// upstream response.
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
	// (with the script disabled for the remaining stream). Configurable per
	// proxy_set.
	DefaultReleaseCapBytes = 1024 * 1024

	// HeaderBailScriptOutput carries the script's bail string when it
	// returned one before any body was forwarded to the client.
	HeaderBailScriptOutput = "X-Bail-Script-Output"

	// HeaderBailScriptError carries the script's runtime error message when
	// it raised before any body was forwarded to the client.
	HeaderBailScriptError = "X-Bail-Script-Error"
)

// Apply runs the bail script against the streaming upstream response and
// returns a (possibly transformed) *http.Response. Status code is always
// preserved. Behaviour by outcome (decided before headers go to the client):
//
//   - Bail (script returned string): close upstream, attach
//     X-Bail-Script-Output header, body = bytes buffered up to the bail point.
//   - Script error (script raised / timed out / blew step budget): attach
//     X-Bail-Script-Error header, body = buffered prefix + remaining
//     upstream streamed normally; script does not run again for this request.
//   - Cap reached without decision: release as-is, no headers added, script
//     no longer runs for this request.
//   - No bail, no error (script returned None on every chunk through EOF):
//     body streams through unchanged.
//
// chunkSize and releaseCap default to DefaultChunkBytes / DefaultReleaseCapBytes
// when zero is passed.
func Apply(ctx context.Context, script *BailScript, resp *http.Response, chunkSize, releaseCap int) *http.Response {
	if resp == nil || resp.Body == nil || script == nil {
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

	// Initial call: headers only, empty buffer.
	reason, err := script.Call(ctx, resp.StatusCode, headers, bb.Peek)
	if err != nil {
		return scriptErroredResponse(resp, bb, err)
	}
	if reason != "" {
		_ = bb.Close()
		return bailResponse(resp, bb, reason)
	}

	// Stream-and-poll until bail / script error / cap / EOF.
	for {
		if bb.Len() >= releaseCap {
			break // cap reached without decision; release as-is
		}
		_, pullErr := bb.Pull(chunkSize)
		if pullErr == io.EOF {
			// Final call so script sees the complete body.
			reason, err = script.Call(ctx, resp.StatusCode, headers, bb.Peek)
			if err != nil {
				return scriptErroredResponse(resp, bb, err)
			}
			if reason != "" {
				_ = bb.Close()
				return bailResponse(resp, bb, reason)
			}
			break
		}
		if pullErr != nil {
			break // upstream error — let copyResponse surface it as-is
		}
		reason, err = script.Call(ctx, resp.StatusCode, headers, bb.Peek)
		if err != nil {
			return scriptErroredResponse(resp, bb, err)
		}
		if reason != "" {
			_ = bb.Close()
			return bailResponse(resp, bb, reason)
		}
	}

	// No bail, no error: passthrough. Re-attach the wrapper so the
	// buffered prefix is delivered before continuing from upstream.
	resp.Body = bb
	return resp
}

func bailResponse(orig *http.Response, bb *bufferedBody, reason string) *http.Response {
	out := cloneRespShallow(orig)
	out.Header = cloneHeadersWithoutEncoding(orig.Header)
	out.Header.Set(HeaderBailScriptOutput, reason)
	body := append([]byte(nil), bb.buf...)
	out.Body = io.NopCloser(bytesReader(body))
	out.ContentLength = int64(len(body))
	out.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return out
}

func scriptErroredResponse(orig *http.Response, bb *bufferedBody, err error) *http.Response {
	slog.Warn("bail script disabled for request after error", "err", err)
	orig.Header.Set(HeaderBailScriptError, truncateForHeader(err.Error()))
	orig.Body = bb
	return orig
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

// Pull reads up to n more bytes from upstream into the buffer. Returns the
// number of bytes appended and io.EOF on upstream exhaustion. Short returns
// are fine — the script loop just calls Pull again next round.
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

// ── small helpers (shared by both bail_apply and script_regex) ─────────────

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

// bytesReadCloser is a single-allocation wrapper that lets a byte slice be
// re-read as an io.ReadCloser without dragging in bytes.Reader's seek surface.
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
