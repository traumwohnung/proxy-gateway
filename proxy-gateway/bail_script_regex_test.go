package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ── regex() compile + script-init use ─────────────────────────────────────

func TestRegex_CompiledAtInitAndUsedInBail(t *testing.T) {
	src := `
DD = regex(rb'geo\.captcha-delivery\.com')

def bail(r):
    if DD.test(r.peek()):
        return 'datadome'
    return None
`
	reason, err := runCall(t, src, []byte("hello geo.captcha-delivery.com world"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if reason != "datadome" {
		t.Fatalf("reason=%q", reason)
	}
}

func TestRegex_NoMatch_ReturnsContinue(t *testing.T) {
	src := `
P = regex(rb'BLOCK')
def bail(r):
    if P.test(r.peek()):
        return 'block'
    return None
`
	reason, err := runCall(t, src, []byte("clean payload"))
	if err != nil || reason != "" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

func TestRegex_AcceptsStringPattern(t *testing.T) {
	src := `
P = regex('foo|bar')
def bail(r):
    return 'hit' if P.test(r.peek()) else None
`
	reason, _ := runCall(t, src, []byte("the bar is open"))
	if reason != "hit" {
		t.Fatalf("reason=%q", reason)
	}
}

func TestRegex_BadPatternFailsAtCompile(t *testing.T) {
	src := `
P = regex(rb'(unclosed')
def bail(r): return None
`
	_, err := Compile(t.Name(), src)
	if err == nil || !strings.Contains(err.Error(), "regex") {
		t.Fatalf("want regex compile error, got %v", err)
	}
}

func TestRegex_OversizedPatternFailsAtCompile(t *testing.T) {
	big := strings.Repeat("a", MaxRegexPatternSize+1)
	src := "P = regex(b'" + big + "')\ndef bail(r): return None\n"
	_, err := Compile(t.Name(), src)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("want size error, got %v", err)
	}
}

// ── .search ────────────────────────────────────────────────────────────────

func TestRegex_SearchReturnsOffset(t *testing.T) {
	src := `
P = regex(rb'needle')
def bail(r):
    idx = P.search(r.peek())
    return str(idx)
`
	reason, _ := runCall(t, src, []byte("haystack with needle inside"))
	if reason != "14" {
		t.Fatalf("offset=%q want 14", reason)
	}
}

func TestRegex_SearchReturnsMinus1OnMiss(t *testing.T) {
	src := `
P = regex(rb'absent')
def bail(r):
    return str(P.search(r.peek()))
`
	reason, _ := runCall(t, src, []byte("nothing here"))
	if reason != "-1" {
		t.Fatalf("got %q", reason)
	}
}

func TestRegex_SearchHonoursStart(t *testing.T) {
	src := `
P = regex(rb'aa')
def bail(r):
    # first match at 0, but we skip it
    return str(P.search(r.peek(), 1))
`
	reason, _ := runCall(t, src, []byte("aaXaa"))
	if reason != "3" {
		t.Fatalf("got %q, want 3", reason)
	}
}

// ── .find / .find_all ──────────────────────────────────────────────────────

func TestRegex_FindReturnsMatchedBytes(t *testing.T) {
	src := `
P = regex(rb'"id":"[A-Z]+"')
def bail(r):
    m = P.find(r.peek())
    if m == None:
        return None
    # return length so we don't depend on bytes→str conversion idioms
    return 'len=' + str(len(m))
`
	reason, _ := runCall(t, src, []byte(`prefix {"id":"FOO"} tail`))
	if reason != `len=10` {
		t.Fatalf("got %q want len=10", reason)
	}
}

func TestRegex_FindReturnsNoneOnMiss(t *testing.T) {
	src := `
P = regex(rb'absent')
def bail(r):
    m = P.find(r.peek())
    return 'none' if m == None else 'hit'
`
	reason, _ := runCall(t, src, []byte("nothing"))
	if reason != "none" {
		t.Fatalf("got %q", reason)
	}
}

func TestRegex_FindAllReturnsList(t *testing.T) {
	src := `
P = regex(rb'\d+')
def bail(r):
    ms = P.find_all(r.peek())
    return str(len(ms))
`
	reason, _ := runCall(t, src, []byte("a1 b22 c333"))
	if reason != "3" {
		t.Fatalf("got %q want 3", reason)
	}
}

// ── multi-call: pattern matches on later chunk ─────────────────────────────

func TestApply_RegexBailOnLaterChunk(t *testing.T) {
	chunk1 := strings.Repeat("clean ", 1000)
	chunk2 := "trigger __UFRN_LIFECYCLE_SERVERREQUEST__ here"
	full := chunk1 + chunk2

	resp := &http.Response{
		StatusCode: 200, Header: http.Header{},
		Body: io.NopCloser(bytes.NewReader([]byte(full))),
	}
	src := `
MARKER = regex(rb'__UFRN_LIFECYCLE_SERVERREQUEST__')
def bail(r):
    if MARKER.test(r.peek()):
        return 'have_blob'
    return None
`
	s, _ := Compile("late", src)
	got := Apply(context.Background(), s, resp, 4096, 0)
	if got.Header.Get(HeaderBailScriptOutput) != "have_blob" {
		t.Fatalf("header=%q", got.Header.Get(HeaderBailScriptOutput))
	}
}

// ── safety: RE2 can't blow up on pathological input ────────────────────────

func TestRegex_NoCatastrophicBacktracking(t *testing.T) {
	// Pattern + haystack that would explode under PCRE backtracking. RE2
	// linear-time guarantee means this completes quickly.
	src := `
P = regex(rb'(a+)+b')
def bail(r):
    return 'hit' if P.test(r.peek()) else 'miss'
`
	hay := bytes.Repeat([]byte("a"), 5000)
	reason, err := runCall(t, src, hay)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if reason != "miss" {
		t.Fatalf("reason=%q", reason)
	}
}
