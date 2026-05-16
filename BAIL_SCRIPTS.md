# Bail scripts

Server-side response filters for the proxy-gateway. A bail script is a short
Starlark program that runs **inside the gateway** against each MITM'd
response and answers one question:

> "Should we close the upstream connection now?"

That's it. It can't transform the body, rewrite headers, or change the
status code. The only side effect of a bail decision is: stop reading from
upstream, deliver to the client whatever bytes were already received, and
add one informational response header.

Use cases that fit:

- Stop downloading multi-MiB anti-bot challenge pages once you recognise
  them (DataDome, Cloudflare, PerimeterX challenge bundles).
- Stop reading once a known marker has been seen, saving the rest of a
  page that you'd discard anyway (e.g. an HTML expose where the JSON
  payload is mid-document and the trailing scripts are dead weight).
- Cap downloads of unexpectedly large bodies based on Content-Length, body
  shape, or status-code patterns.

If you need to **transform** the response (rewrite a header, replace bytes
in the body, generate a synthetic response), bail scripts can't help and a
different mechanism is needed.

## Prerequisites

- The request must opt into MITM by including `httpcloak` in its username.
  Bail scripts can only see plaintext, and the gateway is a CONNECT tunnel
  without `httpcloak`. The gateway rejects `bail_script` set without
  `httpcloak` at parse time.
- Scripts can be attached **per request** (in the username) or **per
  proxy-set** (in `config.toml`). Per-request wins; per-set fills in
  otherwise; otherwise no script runs.

## Lifecycle

1. Upstream returns response headers + starts producing body.
2. Gateway invokes `bail(r)` once with headers visible and the body buffer
   still empty.
3. If `bail` returned `None`, gateway pulls the next chunk (8 KiB by
   default) and invokes `bail(r)` again with the accumulated buffer.
4. Loop continues until any of:
   - `bail` returns a string → close upstream, finalise response, add
     `X-Bail-Script-Output: <string>` header. Body delivered to client is
     whatever was buffered.
   - `bail` raises → log the error, attach
     `X-Bail-Script-Error: <message>` header, **do not call the script
     again** for this request, continue streaming normally.
   - Cumulative buffer reaches the release cap (default 1 MiB) → release
     as-is, no headers added, script no longer runs for this request.
   - Upstream reaches EOF → final call to `bail(r)` with the complete body
     so it has one last chance to bail. Then release.

## Where the script comes from

### Per-request (in the proxy username JSON)

```json
{
  "set": "proxyingio-residential-high",
  "minutes": 1,
  "session_params": { "platform": "immowelt", "usecase": "scraping" },
  "session_meta":   { "action": "scrape_expose" },
  "httpcloak":      { "preset": "chrome-latest" },
  "bail_script": "def bail(r):\n    if r.scan(b'datadome') >= 0:\n        return 'datadome'\n"
}
```

Inline source, ≤ 32 KiB. Compiled at username-parse time, so syntax errors
fail the **request**, not the response.

### Per-proxy-set (in `config.toml`)

```toml
[[proxy_set]]
name = "proxyingio-residential-high"
provider = "proxyingio"
bail_script = """
DD = regex(rb'(?:geo\\.captcha-delivery\\.com|datadome\\.cid)')

def bail(r):
    if DD.test(r.peek()):
        return 'datadome'
"""
```

Compiled at config load, so bad scripts fail the gateway at **boot**.

Resolution order per request: username override > per-set default > no script.

## The `r` argument

| Attribute / call           | Returns                          | Notes                                              |
| -------------------------- | -------------------------------- | -------------------------------------------------- |
| `r.status`                 | `int`                            | Upstream status code                               |
| `r.headers`                | `dict[str → list[str]]`          | Keys lower-cased                                   |
| `r.peek(n=None)`           | `bytes`                          | Buffered body so far (`None` = all)                |
| `r.scan(needle, start=0)`  | `int` (-1 if not found)          | Byte-substring search; convenience over `peek`     |

## Return contract

| Return value                       | Effect                                                                                         |
| ---------------------------------- | ---------------------------------------------------------------------------------------------- |
| `None` (or no return)              | Continue. Gateway pulls next chunk and calls `bail(r)` again.                                  |
| Non-empty `str`                    | Bail. Close upstream. Add `X-Bail-Script-Output: <string>`.                                    |
| Empty `""`                         | Same as `None` (continue).                                                                     |
| Any other type (int, list, bytes…) | Treated as continue. A warning is logged on the gateway.                                       |
| Raised exception (`fail(...)`, …)  | Add `X-Bail-Script-Error: <msg>`. Script disabled for the rest of this request. Stream as-is. |

## Predeclared host builtins

### `regex(pattern)`

Compile a regex once (typically as a module-level constant so it lands in
frozen globals). RE2-based — no backreferences, no lookarounds, but
linear-time guaranteed.

```python
DD = regex(rb'geo\.captcha-delivery\.com')

def bail(r):
    if DD.test(r.peek()):
        return 'datadome'
```

Returned object methods:

| Call                                | Returns                          |
| ----------------------------------- | -------------------------------- |
| `pat.test(haystack)`                | `bool`                           |
| `pat.search(haystack, start=0)`     | `int` (-1 if no match)           |
| `pat.find(haystack, start=0)`       | `bytes` or `None`                |
| `pat.find_all(haystack)`            | `list[bytes]`                    |

Inputs accept both `bytes` and `str`. Patterns capped at 4 KiB.

## Recipes

### Anti-bot detection

```python
ANTIBOT = regex(rb'(?:geo\.captcha-delivery\.com|datadome\.cid|__cf_bm|<title>\s*Just a moment)')

def bail(r):
    if ANTIBOT.test(r.peek()):
        return 'antibot'
```

### Bail on 4xx without reading the body

```python
def bail(r):
    if 400 <= r.status < 500:
        return 'client_error'
```

### Bail on huge Content-Length before reading anything

```python
def bail(r):
    cl = int(r.headers.get('content-length', ['0'])[0])
    if cl > 5_000_000:
        return 'too_big'
```

### Bail once a needed JSON blob has appeared

```python
END = regex(rb'window\["__UFRN_LIFECYCLE_SERVERREQUEST__"\]=JSON\.parse\("[^"]*"\)')

def bail(r):
    if END.test(r.peek()):
        return 'have_blob'
```

The client receives all bytes up to and including the blob; the trailing
markup (often hundreds of KiB of analytics scripts) is never downloaded.

### Bail only on specific header values

```python
def bail(r):
    if r.headers.get('x-blocked-by', []) == ['datadome']:
        return 'datadome_via_header'
```

### Search for multiple markers and report which one matched

```python
MARKERS = {
    'datadome':    regex(rb'geo\.captcha-delivery\.com'),
    'cloudflare':  regex(rb'__cf_bm|<title>\s*Just a moment'),
    'perimeterx':  regex(rb'PerimeterX'),
}

def bail(r):
    buf = r.peek()
    for name, pat in MARKERS.items():
        if pat.test(buf):
            return name
```

## What you can't do

- Modify the status, headers, or body content. The script is read-only by
  design.
- Decide based on time elapsed, the proxy IP, the upstream domain, the
  request path/method/headers, or other request-side data. None of that is
  exposed today.
- Keep per-call state inside the script (globals freeze after init). State
  across calls of the same request comes only from the buffer growing.
- Use `import`, `print`, network, files, time, random, `while`, or
  recursion — all forbidden by the Starlark sandbox.
- Use PCRE features (backreferences, lookarounds). RE2 only.
- Bail with a very large reason string. Anything > 512 bytes is truncated
  in the header.

## Operational limits

| Limit                                       | Default       | Where it lives                       |
| ------------------------------------------- | ------------- | ------------------------------------ |
| Inline script source size                   | 32 KiB        | `MaxScriptSize`                      |
| Starlark execution steps per `bail()` call  | 100 000       | `MaxExecSteps`                       |
| Wall-clock per `bail()` call                | 50 ms         | `MaxWallClock`                       |
| Chunk size pulled between calls             | 8 KiB         | `DefaultChunkBytes`                  |
| Release cap (buffer ceiling per request)    | 1 MiB         | `DefaultReleaseCapBytes`             |
| Regex pattern size                          | 4 KiB         | `MaxRegexPatternSize`                |

Hitting the step or wall-clock limit raises an error, which disables the
script for the rest of that request (same as any other script error) and
attaches `X-Bail-Script-Error`.

## Bytes accounting

Single-direction: the gateway's existing `download_bytes` counter records
exactly what was pulled from upstream. Bail at the first call after 8 KiB →
analytics shows 8 KiB. Never bail → analytics shows the full body. No new
fields, no schema changes; the script's effect is naturally visible as a
drop in the existing metric.

## Debugging a script

- Compile errors land in the response of the failing request — fix and
  retry. Inspect the error string for the Starlark line/column.
- Runtime errors show up as `X-Bail-Script-Error: <msg>` on the response.
  The same message is logged by the gateway with the script name.
- Unexpected return types (int, list, bytes) produce a `bail script
  returned unexpected type, treating as continue` warning log on the
  gateway.
- To verify a script bails on the request you expect, watch the
  proxy-gateway-analytics dashboard for the `X-Bail-Script-Output` value
  shown on the request's `session_meta.action` row, or check the response
  headers your backend receives.

## Future scripts

The engine layer (`script_engine.go`, `script_regex.go`) is type-agnostic.
Request-modification scripts (`request_modify(r)`) and response-
modification scripts (`response_modify(r)`) will plug in alongside
`BailScript` using the same Compile / Run plumbing. Until they exist,
bail-only is the entire surface.
