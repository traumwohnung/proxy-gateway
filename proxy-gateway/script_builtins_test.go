package main

import (
	"strings"
	"testing"
)

// runReturn compiles a script whose response_bailing returns whatever the
// script computes (so we can assert on it via the reason channel).
func runReturn(t *testing.T, src string) string {
	t.Helper()
	r, err := runCall(t, src, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return r
}

// ── json_decode / json_encode ────────────────────────────────────────────

func TestBuiltin_JsonDecode_Object(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    d = Json.decode(b'{"a":1,"b":"hi","c":true,"d":null,"e":[1,2]}')
    if d["a"] != 1: fail("a")
    if d["b"] != "hi": fail("b")
    if d["c"] != True: fail("c")
    if d["d"] != None: fail("d")
    if len(d["e"]) != 2: fail("e")
    return "ok"
`)
	if got != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_JsonDecode_Malformed_ReturnsNone(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    return "none" if Json.decode(b"{not json") == None else "parsed"
`)
	if got != "none" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_JsonDecode_Float(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    v = Json.decode(b'3.14')
    return str(v)
`)
	if got != "3.14" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_JsonDecode_AcceptsString(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    return str(Json.decode('[1,2,3]'))
`)
	if got != "[1, 2, 3]" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_JsonEncode_RoundTrip(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    payload = {"k": [1, 2, "x"], "b": True}
    encoded = Json.encode(payload)
    decoded = Json.decode(encoded)
    return "ok" if decoded["k"] == [1, 2, "x"] and decoded["b"] == True else "fail"
`)
	if got != "ok" {
		t.Fatalf("got %q", got)
	}
}

// ── base64_decode / base64_encode ────────────────────────────────────────

func TestBuiltin_Base64Encode(t *testing.T) {
	got := runReturn(t, `def response_bailing(r): return Base64.encode(b"hello")`)
	if got != "aGVsbG8=" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Base64Decode(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    v = Base64.decode("aGVsbG8=")
    return str(len(v))
`)
	if got != "5" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Base64Decode_AcceptsURLSafe(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    v = Base64.decode("YS1iX2M-ZA==")  # url-safe alphabet
    return "ok" if v != None else "fail"
`)
	if got != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Base64Decode_Malformed_None(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    return "none" if Base64.decode("####not_base64") == None else "parsed"
`)
	if got != "none" {
		t.Fatalf("got %q", got)
	}
}

// ── url_decode / url_encode ──────────────────────────────────────────────

func TestBuiltin_UrlEncode(t *testing.T) {
	got := runReturn(t, `def response_bailing(r): return Url.encode("hello world & more")`)
	if got != "hello+world+%26+more" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_UrlDecode(t *testing.T) {
	got := runReturn(t, `def response_bailing(r): return Url.decode("hello%20world%21")`)
	if got != "hello world!" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_UrlDecode_Malformed_None(t *testing.T) {
	got := runReturn(t, `
def response_bailing(r):
    return "none" if Url.decode("%ZZ") == None else "parsed"
`)
	if got != "none" {
		t.Fatalf("got %q", got)
	}
}

// ── xpath ────────────────────────────────────────────────────────────────

func TestBuiltin_Xpath_QueryTitle(t *testing.T) {
	src := `
TITLE = Xpath.new("//title")
def response_bailing(r):
    nodes = TITLE.query(b"<html><head><title>hello</title></head></html>")
    if len(nodes) != 1: fail("count")
    return str(nodes[0])
`
	got := runReturn(t, src)
	if got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Xpath_TestShorthand(t *testing.T) {
	src := `
P = Xpath.new('//div[@class="captcha"]')
def response_bailing(r):
    if P.test(b'<html><body><div class="captcha">x</div></body></html>'):
        return "match"
    return "miss"
`
	if got := runReturn(t, src); got != "match" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Xpath_NoMatch_ReturnsEmpty(t *testing.T) {
	src := `
P = Xpath.new("//missing")
def response_bailing(r):
    nodes = P.query(b"<html></html>")
    return str(len(nodes))
`
	if got := runReturn(t, src); got != "0" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Xpath_TolerantOfPartialHTML(t *testing.T) {
	// Truncated mid-tag — htmlquery should still parse what it can.
	src := `
TITLE = Xpath.new("//title")
def response_bailing(r):
    nodes = TITLE.query(b"<html><head><title>blocked</title><script>incomplete")
    return str(len(nodes))
`
	if got := runReturn(t, src); got != "1" {
		t.Fatalf("got %q", got)
	}
}

func TestBuiltin_Xpath_BadExpression_CompileError(t *testing.T) {
	_, err := Compile("bad", `BAD = Xpath.new("//[invalid")
def response_bailing(r): return None`)
	if err == nil || !strings.Contains(err.Error(), "xpath") {
		t.Fatalf("want xpath compile error, got %v", err)
	}
}

func TestBuiltin_Xpath_OversizedExpression_CompileError(t *testing.T) {
	big := "//x[contains(., '" + strings.Repeat("a", MaxXPathExprSize) + "')]"
	src := "BAD = Xpath.new(\"" + big + "\")\ndef response_bailing(r): return None\n"
	_, err := Compile("oversize", src)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("want size error, got %v", err)
	}
}

// ── end-to-end inside a bail decision ────────────────────────────────────

func TestBuiltin_JsonBail_RealisticBody(t *testing.T) {
	src := `
def response_bailing(r):
    parsed = Json.decode(r.peek())
    if parsed != None and parsed.get("status") == "blocked":
        return parsed.get("reason", "blocked")
    return None
`
	got, err := runCall(t, src, []byte(`{"status":"blocked","reason":"rate_limit"}`))
	if err != nil || got != "rate_limit" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestBuiltin_XpathBail_FindsAntibotMarker(t *testing.T) {
	src := `
CAPTCHA = Xpath.new('//div[contains(@class,"captcha") or contains(@id,"captcha")]')

def response_bailing(r):
    if CAPTCHA.test(r.peek()):
        return "captcha"
    return None
`
	html := []byte(`<html><body><div id="captcha-frame">…</div></body></html>`)
	got, err := runCall(t, src, html)
	if err != nil || got != "captcha" {
		t.Fatalf("got %q err=%v", got, err)
	}
}
