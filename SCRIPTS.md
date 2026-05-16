# Scripts

Server-side hooks for the proxy-gateway, written in Starlark. A request can
carry an ordered **chain** of scripts; each script is a small Starlark
module that may define one or more known entry-point functions. Today the
only recognised entry point is `response_bailing(r)`. Future ones (e.g.
`request_modify(req)`, `response_modify(resp)`) will land alongside it.

This guide focuses on bail — the current capability.

## What bail can do

`response_bailing(r)` answers one question after the gateway has buffered each new
chunk of upstream data on a MITM'd response:

> "Should we close the upstream connection now?"

It can't transform the body, rewrite headers, or change the status code.
The only side effect of a bail is: stop reading from upstream, deliver
whatever was already received, add one informational response header.

## Prerequisites

- The request must opt into MITM by including `httpcloak` in its username.
  Scripts can only see plaintext; the gateway is a CONNECT tunnel without
  `httpcloak`. A `scripts` array set without `httpcloak` fails at username
  parse.
- Scripts can be attached **per request** (in the username's `scripts`
  array) or **per proxy-set** (in `config.toml` via `default_scripts`).
  Per-request REPLACES the per-set chain when present.

## Defining named scripts in config

Top-level `[[script]]` table entries define named, reusable scripts.

```toml
[[script]]
name = "antibot"
source = """
DD = regex(rb'(?:geo\\.captcha-delivery\\.com|datadome\\.cid)')

def response_bailing(r):
    if DD.test(r.peek()):
        return 'datadome'
"""

[[script]]
name = "skip_large"
source = """
def response_bailing(r):
    cl = int(r.headers.get('content-length', ['0'])[0])
    if cl > 1_000_000:
        return 'too_big'
"""

[[proxy_set]]
name = "residential"
provider = "proxyingio"
default_scripts = ["antibot", "skip_large"]
```

- All `[[script]]` entries are compiled at config load. Bad source → boot fail.
- A script that defines no recognised entry point (e.g. `bail`) is rejected
  at compile time. This catches typos like `def ball(r): ...`.
- `default_scripts` lists names. Unknown names → boot fail.
- Order in `default_scripts` is the order they're invoked.

## Per-request script chain in the username

```json
{
  "set": "residential",
  "minutes": 1,
  "session_params": { "platform": "immowelt", "usecase": "scraping" },
  "session_meta":   { "action": "scrape_expose" },
  "httpcloak":      { "preset": "chrome-latest" },
  "scripts": [
    "antibot",
    { "kind": "source", "source": "def response_bailing(r):\n    if r.scan(b'<title>') >= 0:\n        return 'has_title'" },
    { "kind": "ref", "name": "skip_large" }
  ]
}
```

Each entry is one of:

| Form                          | Meaning                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| `"name"`                      | Reference to a `[[script]]` named `name` in config             |
| `{ "kind": "ref", "name": "name" }`             | Same as above, just explicit                                   |
| `{ "kind": "source", "source": "def response_bailing(r): …" }`| Inline Starlark, compiled at username parse                    |

- Inline source ≤ 32 KiB, same compile rules as named scripts.
- Refs require a registry — username parsing fails if a ref appears with
  no `[[script]]` entries on the gateway.
- Setting `scripts` REPLACES the per-set `default_scripts`. To extend a
  per-set chain, include the named refs explicitly:
  `"scripts": ["antibot", "skip_large", { "kind": "source", "source": "..." }]`.

## Lifecycle of the bail chain

1. Upstream returns response headers + starts producing body.
2. For each script in the chain, in order, invoke its `response_bailing(r)` with
   headers visible and the body buffer still empty.
3. If any script returns a string → close upstream, finalise response,
   attach `X-Script-Response-Bailing-Output: <string>` and `X-Script-Response-Bailing-Name: <name>`.
4. If any script raises → log, attach error to `X-Script-Response-Bailing-Error`,
   mark **only that script** disabled for the rest of the request.
   Subsequent scripts in the chain continue to run.
5. If no script bails in this round, pull the next chunk (8 KiB default)
   and repeat from step 2.
6. Loop ends when: a script bails / cumulative buffer hits the release cap
   (1 MiB default) / upstream EOFs. On cap-reached and EOF without bail
   the response streams through unchanged.

**Short-circuit rule for v1**: as soon as one script bails, no further
scripts' `bail()` runs (for this request). Future modify phases will run
all scripts in order regardless of bail.

## The `r` argument

| Attribute / call           | Returns                          | Notes                                              |
| -------------------------- | -------------------------------- | -------------------------------------------------- |
| `r.status`                 | `int`                            | Upstream status code                               |
| `r.headers`                | `dict[str → list[str]]`          | Keys lower-cased                                   |
| `r.peek(n=None)`           | `bytes`                          | Buffered body so far (`None` = all)                |
| `r.scan(needle, start=0)`  | `int` (-1 if not found)          | Byte-substring search; convenience over `peek`     |

## Return contract for `response_bailing(r)`

| Return value                       | Effect                                                                                         |
| ---------------------------------- | ---------------------------------------------------------------------------------------------- |
| `None` (or no return)              | Continue. Next script in chain runs. If last, gateway pulls next chunk.                        |
| Non-empty `str`                    | Bail. Close upstream. Add `X-Script-Response-Bailing-Output: <string>` + `X-Script-Response-Bailing-Name: <script>`.   |
| Empty `""`                         | Same as `None` (continue).                                                                     |
| Any other type (int, list, bytes…) | Treated as continue. A warning is logged on the gateway.                                       |
| Raised exception (`fail(...)`, …)  | Add to `X-Script-Response-Bailing-Error`. Script disabled for the rest of this request. Chain continues.   |

## Predeclared host builtins

### `regex(pattern)`

Compile a regex once (typically as a module-level constant so it lands in
frozen globals). RE2-based — no backreferences, no lookarounds, linear-time
guaranteed.

```python
DD = regex(rb'geo\.captcha-delivery\.com')

def response_bailing(r):
    if DD.test(r.peek()):
        return 'datadome'
```

Methods on the returned object:

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

def response_bailing(r):
    if ANTIBOT.test(r.peek()):
        return 'antibot'
```

### Bail on 4xx without reading the body

```python
def response_bailing(r):
    if 400 <= r.status < 500:
        return 'client_error'
```

### Bail on huge Content-Length before reading anything

```python
def response_bailing(r):
    cl = int(r.headers.get('content-length', ['0'])[0])
    if cl > 5_000_000:
        return 'too_big'
```

### Bail once a needed JSON blob has appeared

```python
END = regex(rb'window\["__UFRN_LIFECYCLE_SERVERREQUEST__"\]=JSON\.parse\("[^"]*"\)')

def response_bailing(r):
    if END.test(r.peek()):
        return 'have_blob'
```

### Search multiple markers, report which one matched

```python
MARKERS = {
    'datadome':    regex(rb'geo\.captcha-delivery\.com'),
    'cloudflare':  regex(rb'__cf_bm|<title>\s*Just a moment'),
    'perimeterx':  regex(rb'PerimeterX'),
}

def response_bailing(r):
    buf = r.peek()
    for name, pat in MARKERS.items():
        if pat.test(buf):
            return name
```

## Chain composition examples

### Chain a cheap filter before an expensive one

```toml
[[script]]
name = "skip_4xx"
source = "def response_bailing(r): return 'client_error' if 400 <= r.status < 500 else None"

[[script]]
name = "antibot_full_html_scan"
source = """
ANTIBOT = regex(rb'(?:datadome|cf-chl-bypass|PerimeterX){1,3}')
def response_bailing(r):
    if ANTIBOT.test(r.peek()):
        return 'antibot'
"""

[[proxy_set]]
name = "residential"
provider = "proxyingio"
default_scripts = ["skip_4xx", "antibot_full_html_scan"]
```

The cheap `skip_4xx` filter runs first on every chunk; if a status check
bails, the heavier regex scan never runs.

### Per-request: stack a global filter with a one-off rule

```json
"scripts": [
  "antibot",
  { "kind": "source", "source": "def response_bailing(r):\n    if r.scan(b'<error>') >= 0:\n        return 'error_marker'" }
]
```

## What you can't do

- Modify the status, headers, or body content. Bail is read-only.
- Decide based on time elapsed, the proxy IP, the upstream domain, the
  request path/method/headers, or other request-side data. None of that is
  exposed today.
- Keep mutable per-call state inside one script (globals freeze after
  init). State across calls of the same request comes only from the buffer
  growing.
- Use `import`, `print`, network, files, time, random, `while`, or
  recursion — all forbidden by the Starlark sandbox.
- Use PCRE features (backreferences, lookarounds). RE2 only.
- Bail with a very large reason string — anything > 512 bytes is truncated
  in the response header.

## Response headers added by the gateway

| Header                    | When                                                                              |
| ------------------------- | --------------------------------------------------------------------------------- |
| `X-Script-Response-Bailing-Output`    | Some script in the chain returned a non-empty string.                             |
| `X-Script-Response-Bailing-Name`      | Name of the script that bailed (matches the `[[script]]` `name` or `username[N]`).|
| `X-Script-Response-Bailing-Error`     | One or more scripts raised before the response was released. Format: `name: msg`, joined by ` \| ` when multiple errored. |

## Operational limits

| Limit                                       | Default       | Where it lives                       |
| ------------------------------------------- | ------------- | ------------------------------------ |
| Inline script source size                   | 32 KiB        | `MaxScriptSize`                      |
| Starlark execution steps per `bail()` call  | 100 000       | `MaxExecSteps`                       |
| Wall-clock per `bail()` call                | 50 ms         | `MaxWallClock`                       |
| Chunk size pulled between calls             | 8 KiB         | `DefaultChunkBytes`                  |
| Release cap (buffer ceiling per request)    | 1 MiB         | `DefaultReleaseCapBytes`             |
| Regex pattern size                          | 4 KiB         | `MaxRegexPatternSize`                |

Limits are per-script per-call: a chain of 5 scripts all running on the
same chunk each get their own 100 000-step / 50 ms budget.

## Bytes accounting

Single-direction: the gateway's `download_bytes` counter records exactly
what was pulled from upstream. Bail at the first call after 8 KiB →
analytics shows 8 KiB. Never bail → analytics shows the full body. No new
fields, no schema changes; the chain's effect appears as a drop in the
existing metric.

## Future scripts

The engine layer (`script_engine.go`, `script_regex.go`) is type-agnostic.
Future request-modification scripts (`request_modify(req)`) and
response-modification scripts (`response_modify(resp)`) will plug in by:

1. Adding the entry name to `recognisedEntryPoints`.
2. Adding a typed field on `*Script` (e.g. `responseModify`).
3. Adding a `Call*` method that interprets that entry's return value.
4. Adding a phase dispatcher analogous to `Apply` for bail.

Until they exist, bail is the entire surface. A single script can define
multiple entry-point functions; they're independent and only the ones the
gateway recognises will be invoked.
