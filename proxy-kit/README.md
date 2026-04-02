# Proxy Kit — Go Proxy Framework

A composable, multi-protocol proxy gateway framework written in Go. It routes client requests through pools of upstream proxies with pluggable authentication, session affinity, rate limiting, MITM interception, and TLS fingerprint spoofing.

```
import "proxy-kit"          // package proxykit — core types & middleware
import "proxy-kit/utils"    // reusable utilities, providers, SessionManager
```

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Concepts](#core-concepts)
   - [Gateway](#gateway)
   - [Handler Pipeline](#handler-pipeline)
   - [Downstream (Listeners)](#downstream-listeners)
   - [Upstream (Dialers)](#upstream-dialers)
   - [Request & Result](#request--result)
   - [Context Values](#context-values)
3. [Middleware](#middleware)
   - [Auth](#auth)
   - [SessionSeed](#sessionseed)
   - [SessionManager](#sessionmanager)
   - [Rate Limiting](#rate-limiting)
   - [MITM Interception](#mitm-interception)
   - [TLS Fingerprint Spoofing](#tls-fingerprint-spoofing)
4. [Proxy Sources](#proxy-sources)
   - [Static File](#static-file)
   - [Bottingtools](#bottingtools)
   - [ProxyingIO](#proxyingio)
   - [Webshare](#webshare)
   - [Geonode](#geonode)
   - [Writing Your Own Source](#writing-your-own-source)
5. [Utilities](#utilities)
   - [CountingPool](#countingpool)
   - [Proxy Format Parsing](#proxy-format-parsing)
6. [Package Layout](#package-layout)

---

## Architecture Overview

```
                          ┌─────────────────────────────────────────────┐
                          │              Gateway                        │
                          │                                             │
Client ──HTTP CONNECT──→  │  HTTPDownstream ─┐                          │
Client ──Plain HTTP───→   │                  ├─→ Handler Pipeline ──→ Upstream ──→ Target
Client ──SOCKS5──────→    │  SOCKS5Downstream┘   (Auth → Session       │
                          │                       → RateLimit → Source) │
                          └─────────────────────────────────────────────┘
```

The framework separates concerns into three layers:

- **Downstream** — accepts client connections (HTTP proxy, SOCKS5)
- **Handler Pipeline** — a chain of middleware that resolves each request to an upstream proxy
- **Upstream** — dials the target through the resolved proxy (HTTP CONNECT or SOCKS5)

Every layer is defined by a Go interface, making each piece independently testable and replaceable.

---

## Core Concepts

All core types live in the `proxykit` package (`import "proxy-kit"`).

### Gateway

`Gateway` is the top-level orchestrator. It wires multiple downstream listeners to a single handler pipeline:

```go
gw := proxykit.New(pipeline,
    proxykit.Listen(&proxykit.HTTPDownstream{}, ":8100"),
    proxykit.Listen(&proxykit.SOCKS5Downstream{}, ":1080"),
    proxykit.WithUpstream(proxykit.AutoUpstream()),
)
gw.ListenAndServe()
```

**Options:**
| Function | Purpose |
|---|---|
| `Listen(downstream, addr)` | Add a listener on `addr` using the given downstream protocol |
| `WithUpstream(u)` | Set the upstream dialer (default: `AutoUpstream()`) |

The gateway injects the `Upstream` into any `Downstream` that implements `UpstreamAware`, then starts all listeners concurrently. It blocks until the first listener returns an error.

### Handler Pipeline

The central abstraction. Every middleware and proxy source implements:

```go
type Handler interface {
    Resolve(ctx context.Context, req *Request) (*Result, error)
}
```

Handlers compose like HTTP middleware — each one does its work, then calls `next.Resolve(ctx, req)`:

```go
proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
    return proxykit.Resolved(&proxykit.Proxy{Host: "1.2.3.4", Port: 8080}), nil
})
```

### Downstream (Listeners)

A `Downstream` accepts client connections and dispatches them through the handler:

```go
type Downstream interface {
    Serve(addr string, handler Handler) error
}
```

Built-in implementations:

| Type | Protocol | Details |
|---|---|---|
| `HTTPDownstream` | HTTP proxy | Handles both `CONNECT` (tunneling) and plain HTTP forwarding. Extracts `Proxy-Authorization` Basic auth. |
| `SOCKS5Downstream` | SOCKS5 | Full RFC 1928 + RFC 1929 implementation. Username/password auth or no-auth. |

Both implement `UpstreamAware` so the `Gateway` can inject the upstream dialer.

Convenience functions are also provided for standalone use:

```go
proxykit.ListenHTTP(":8100", handler)
proxykit.ListenSOCKS5(":1080", handler)
```

### Upstream (Dialers)

An `Upstream` dials a target host through an upstream proxy:

```go
type Upstream interface {
    Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)
}
```

Built-in implementations:

| Type | Protocol | How it works |
|---|---|---|
| `HTTPUpstream` | HTTP CONNECT | Sends `CONNECT target HTTP/1.1` with optional Basic auth |
| `SOCKS5Upstream` | SOCKS5 | Uses `golang.org/x/net/proxy` (RFC 1928/1929) |
| `AutoUpstream()` | Auto-detect | Dispatches to HTTP or SOCKS5 based on `proxy.Protocol` |

`AutoUpstream()` is the default when no upstream is explicitly configured.

### Request & Result

**`Request`** carries everything the downstream extracted from the client:

```go
type Request struct {
    RawUsername  string        // From Basic auth or SOCKS5 handshake
    RawPassword  string        // From Basic auth or SOCKS5 handshake
    Target       string        // Destination host:port
    Conn         net.Conn      // Raw client connection (CONNECT/SOCKS5)
    HTTPRequest  *http.Request // Decoded HTTP request (plain HTTP or MITM)
}
```

**`Result`** carries the pipeline's decision:

```go
type Result struct {
    Proxy        *Proxy        // Upstream proxy to use (nil = handled/rejected)
    ConnTracker  ConnTracker   // Tracks bytes/connections for rate limiting
    ResponseHook func(*http.Response) *http.Response  // Modify response before sending
    HTTPResponse *http.Response // Synthetic response (blocking, caching)
    UpstreamConn net.Conn      // Pre-dialed connection (MITM)
}
```

The `Proxy` struct is the resolved upstream endpoint:

```go
type Proxy struct {
    Host     string
    Port     uint16
    Username string
    Password string
    Protocol Protocol  // "http" or "socks5"
}
```

### Context Values

The framework uses typed context keys to pass data between pipeline stages:

| Function | Purpose |
|---|---|
| `WithSessionSeed(ctx, seed)` / `GetSessionSeed(ctx)` | Deterministic seed for source decisions (set by SessionManager) |
| `WithIdentity(ctx, id)` / `Identity(ctx)` | Caller's identity (optional, for auth middleware) |
| `WithCredential(ctx, cred)` / `Credential(ctx)` | Caller's credential (optional, for auth middleware) |
| `WithTLSState(ctx, state)` / `GetTLSState(ctx)` | TLS interception state (MITM) |

---

## Middleware

### Auth

Validates `Identity(ctx)` and `Credential(ctx)` against an `Authenticator`:

```go
type Authenticator interface {
    Authenticate(identity, credential string) error
}

pipeline := proxykit.Auth(myAuthenticator, next)
```

This is a generic building block — the server binary can choose to use it or implement its own auth (e.g. checking `req.RawPassword` directly).

### SessionSeed

`SessionSeed` is the core primitive for deterministic session behavior. It's a `*proxykit.SessionSeed` stored in context — sources read it to make reproducible choices.

```go
type SessionSeed struct { /* opaque uint64 */ }

func (s *SessionSeed) Pick(n int) int                              // Deterministic index in [0, n)
func (s *SessionSeed) DeriveStringKey(charset string, length int) string  // Deterministic string
func (s *SessionSeed) Value() uint64                               // Raw value
```

A `nil` seed in context means no session affinity. Sources decide what nil means for their domain — randomize, refuse, etc.

Seeds are computed from a top-level seed (uint64, derived from affinity params) mixed with a rotation counter:

```go
seed := proxykit.NewSessionSeed(topLevelSeed, rotation)  // deterministic
proxykit.TopLevelSeed("alice\x00residential")             // string → uint64 hash
```

Same top-level seed + same rotation → same SessionSeed → same source choices. Bumping rotation produces a completely different seed.

### SessionManager

`SessionManager` (in `proxy-kit/utils`) is Handler middleware that manages the full session lifecycle on top of `SessionSeed`:

```go
sm := utils.NewSessionManager(next)
```

It reads `utils.GetTopLevelSeed(ctx)` and `utils.GetSeedTTL(ctx)` from context and:

- **TTL > 0**: looks up its cache. On hit, returns the cached proxy. On miss, computes a `SessionSeed`, stores it in context, calls next, and caches the result.
- **TTL = 0 or zero seed**: passes through with no seed (nil). Sources randomize.

**Force rotation:**

```go
sm.ForceRotate(topLevelSeed)  // Bumps rotation counter → new seed → new proxy
```

**Introspection:**

```go
sm.GetSession(topLevelSeed)   // SessionInfo for one session
sm.ListEntries()              // All active sessions
```

Context helpers for callers:

```go
ctx = utils.WithTopLevelSeed(ctx, seed)    // uint64 from affinity params
ctx = utils.WithSeedTTL(ctx, 5*time.Minute) // how long to cache
ctx = utils.WithSessionLabel(ctx, label)    // opaque label for introspection
```

### Rate Limiting

`RateLimit` enforces per-key limits on connections and bandwidth:

```go
limiter := proxykit.RateLimit(
    func(ctx context.Context) string { return "user-alice" },
    next,
    proxykit.StaticLimits([]proxykit.RateLimitRule{
        {Type: proxykit.LimitConcurrentConnections, Timeframe: proxykit.Realtime, Max: 100},
        {Type: proxykit.LimitTotalBytes, Timeframe: proxykit.Daily, Max: 10 * 1024 * 1024 * 1024},
    }),
)
```

**Limit types:**

| Type | Description |
|---|---|
| `LimitConcurrentConnections` | Max simultaneous open connections |
| `LimitTotalConnections` | Total connections in a time window |
| `LimitUploadBytes` | Upload bandwidth cap |
| `LimitDownloadBytes` | Download bandwidth cap |
| `LimitTotalBytes` | Combined bandwidth cap |

**Timeframes:** `Realtime`, `Secondly`, `Minutely`, `Hourly`, `Daily`, `Weekly`, `Monthly`

The `Window` multiplier allows custom durations (e.g., `Hourly` with `Window: 6` = 6-hour rolling window).

Traffic counting is integrated via `ConnTracker` — a per-connection interface that gets `RecordTraffic` calls on every read, with a `cancel` function to kill the connection when limits are exceeded:

```go
type ConnTracker interface {
    RecordTraffic(upstream bool, delta int64, cancel func())
    Close(sentTotal, receivedTotal int64)
}
```

Multiple trackers can be chained with `ChainTrackers(a, b)`.

### MITM Interception

`MITM` terminates the client's TLS inside a CONNECT tunnel, allowing full HTTP request/response inspection and modification:

```go
ca, _ := proxykit.NewCA()
pipeline := proxykit.MITM(certProvider, interceptor, inner)

// Or the quick shortcut:
pipeline := proxykit.QuickMITM(ca, upstream, inner)
```

**Key components:**

| Interface | Purpose |
|---|---|
| `CertProvider` | Provides TLS certificates for each hostname |
| `Interceptor` | Performs the actual upstream request |

**Built-in cert providers:**
- `ForgedCertProvider` — generates per-host certificates signed by your CA, with an LRU cache
- `StaticCertProvider` — uses a single certificate for all hosts

**Built-in interceptors:**
- `StandardInterceptor` — dials upstream via the resolved proxy, does a real TLS handshake to the target, and forwards the decrypted request

The MITM flow:
1. Client sends `CONNECT example.com:443`
2. Pipeline resolves to an upstream proxy
3. MITM accepts the client's TLS using a forged cert for `example.com`
4. Client sends decrypted HTTP requests over the TLS connection
5. Interceptor forwards each request through the upstream proxy to the target
6. Responses flow back through the same path

### TLS Fingerprint Spoofing

Builds on MITM to make upstream connections look like a real browser:

```go
ca, _ := proxykit.NewCA()
pipeline := utils.TLSFingerprintSpoofing(ca, "chrome-latest", inner)
```

This uses [httpcloak](https://github.com/sardanioss/httpcloak) to spoof the TLS fingerprint. The `preset` controls which browser to impersonate (`"chrome-latest"`, `"firefox-latest"`, `"safari-latest"`).

Under the hood, it's just a custom `Interceptor` plugged into `proxykit.MITM`.

---

## Proxy Sources

A proxy source is just a `Handler` that returns a `Result` with a `Proxy`. Sources receive a `*proxykit.SessionSeed` via context — they use it for deterministic choices when non-nil, and fall back to their own randomization when nil.

The framework ships five sources in `proxy-kit/utils`:

### Static File

Loads proxies from a text file at startup, serves them via `CountingPool` (least-used rotation):

```go
source, _ := utils.LoadStaticFileSource("proxies.txt", utils.ProxyFormatHostPortUserPass)
```

**Seed behavior:**
- `nil` seed → least-used with random tie-breaking
- non-nil seed → least-used with deterministic tie-breaking (same seed picks same proxy among equally-used entries)

Supports multiple line formats:
- `host:port:user:pass` (default)
- `user:pass@host:port`
- `user:pass:host:port`

Comments (`#`) and blank lines are ignored.

### Bottingtools

Connects to the Bottingtools proxy API. Supports residential (low/high quality), ISP, and datacenter products with country targeting.

**Seed behavior:**
- `nil` seed → random session ID and random country pick on every `Resolve()`
- non-nil seed → deterministic session ID (`seed.DeriveStringKey(hex, 16)`) and deterministic country pick (`seed.Pick(len(countries))`)

### ProxyingIO

Connects to the proxying.io gateway. Supports `http` and `socks5` upstream protocols. The upstream username stays fixed; sticky requests encode `session-*` and `lifetime-*` into the upstream password, while non-sticky requests omit both. Country targeting and `quality-high` are optional password suffixes, and multiple countries are encoded as a comma-separated list like `country-AQ,AD`.

**Seed behavior:**
- `nil` seed → no `session-*` / `lifetime-*`
- non-nil seed → deterministic session ID
- `GetSeedTTL(ctx)` overrides the password `lifetime-*` segment for sticky requests; otherwise the source uses `default_lifetime` (default: `60`)
- `high_quality = true` appends `_quality-high`; omitted means no quality filter
- `protocol = "http"` is the default and uses port `8080`; `protocol = "socks5"` defaults to port `1080`

### Webshare

Generates a fixed Webshare proxy pool from `username-1` through `username-N` on `p.webshare.io:80`, using a shared password from `password_env`.

**Seed behavior:**
- `nil` seed → least-used rotation with random tie-breaking across the generated pool
- non-nil seed → least-used rotation with deterministic tie-breaking, so the same seed picks the same generated username when counts are equal

### Geonode

Connects to Geonode's proxy gateway. Supports rotating and sticky sessions, HTTP and SOCKS5, multiple gateway locations (FR, US, SG), and country targeting.

**Seed behavior:** same as Bottingtools — deterministic session ID and country with a seed, random without.

### Writing Your Own Source

Implement `proxykit.Handler` and read the seed from context:

```go
type MySource struct { /* ... */ }

func (s *MySource) Resolve(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
    seed := proxykit.GetSessionSeed(ctx)

    // Deterministic with seed, random without
    country := countries[rand.Intn(len(countries))]
    sessionID := randomHex(16)
    if seed != nil {
        country = countries[seed.Pick(len(countries))]
        sessionID = seed.DeriveStringKey("0123456789abcdef", 16)
    }

    proxy := &proxykit.Proxy{
        Host: "proxy.example.com", Port: 8080,
        Username: fmt.Sprintf("user_session-%s_country-%s", sessionID, country),
        Password: "pass",
    }
    return proxykit.Resolved(proxy), nil
}
```

---

## Utilities

### CountingPool

A generic, lock-free pool with least-used selection:

```go
pool := utils.NewCountingPool([]proxykit.Proxy{p1, p2, p3})

proxy := pool.Next()                // Least-used, random tie-break
proxy := pool.NextWithSeed(seed)    // Least-used, seed-deterministic tie-break (nil = random)
proxy := pool.NextExcluding(fn)     // Exclude entries (e.g., a failed proxy)
```

Uses atomic counters — no mutex contention. `NextWithSeed(nil)` is equivalent to `Next()`.

### Proxy Format Parsing

Parse proxy strings in various formats:

```go
proxy, err := utils.ParseProxyLine("1.2.3.4:8080:user:pass", utils.ProxyFormatHostPortUserPass)
proxy, err := utils.ParseProxyLine("user:pass@1.2.3.4:8080", utils.ProxyFormatUserPassAtHostPort)
proxy, err := utils.ParseProxyLine("user:pass:1.2.3.4:8080", utils.ProxyFormatUserPassHostPort)
```

Handles IPv6 (bracketed notation), optional credentials, and protocol prefixes (`http://`, `socks5://`).

---

## Package Layout

```
proxy-kit/
├── *.go                           # Package proxykit — core types & middleware
│   ├── handler.go                 # Handler, Request, Result
│   ├── proxy.go                   # Proxy struct
│   ├── protocol.go                # Protocol type (http, socks5)
│   ├── transport.go               # Downstream, Upstream, UpstreamAware interfaces
│   ├── context.go                 # Context keys (Identity, Credential, TLSState)
│   ├── session_seed.go            # SessionSeed, TopLevelSeed, DeriveStringKey, Pick
│   ├── gateway.go                 # Gateway orchestrator
│   ├── http_downstream.go         # HTTP proxy listener (CONNECT + plain)
│   ├── socks5_downstream.go       # SOCKS5 listener
│   ├── http_upstream.go           # HTTP CONNECT dialer
│   ├── socks5_upstream.go         # SOCKS5 dialer
│   ├── upstream.go                # AutoUpstream (protocol dispatcher)
│   ├── auth.go                    # Auth middleware
│   ├── ratelimit.go               # Rate limiting middleware (rolling windows)
│   ├── conn_tracker.go            # Connection lifecycle tracking
│   ├── mitm.go                    # MITM TLS interception
│   ├── forward.go                 # Plain HTTP forwarding
│   ├── relay.go                   # Bidirectional byte relay with counting
│   └── net_helpers.go             # hostPort helper (IPv6-aware)
│
└── utils/                         # Reusable utilities & proxy source implementations
    ├── session_manager.go         # SessionManager middleware (TTL, rotation, caching)
    ├── counting_pool.go           # CountingPool (least-used generic pool, seed-aware)
    ├── seed_helpers.go            # Shared nil-seed helpers (pickCountry, deriveSessionID)
    ├── proxy_format.go            # Proxy line parsing (multiple formats)
    ├── auth_map.go                # MapAuth (map-based authenticator)
    ├── meta.go                    # Meta context (arbitrary request metadata)
    ├── country.go                 # Country code type
    ├── cheap_random.go            # Fast xorshift64 RNG
    ├── tls_fingerprint_spoofing.go # TLS fingerprint spoofing via httpcloak
    ├── provider_static_file.go    # Static file proxy source (seed-aware pool selection)
    ├── provider_bottingtools.go   # Bottingtools proxy source (seed-aware session IDs)
    ├── provider_proxyingio.go     # proxying.io source (session data encoded in password)
    ├── provider_webshare.go       # Webshare generated pool source
    └── provider_geonode.go        # Geonode proxy source (seed-aware session IDs)
```

### Design Principles

- **Interfaces over implementations** — `Handler`, `Downstream`, `Upstream`, `Authenticator`, `ConnTracker`, `CertProvider`, `Interceptor` are all interfaces. Swap any piece without touching the rest.
- **Context is the data bus** — middleware communicates via typed context values, not struct fields. This keeps the `Handler` signature universal.
- **nil means "not applicable"** — `SessionSeed` is a pointer. Present = deterministic, nil = source decides. No sentinel values.
- **Core vs. utils** — `proxykit` is the minimal framework (interfaces, middleware, transports). `utils` is batteries-included (session management, providers, pools). You can use core without utils.
- **Middleware composes** — `Auth(auth, SessionManager(RateLimit(keyFn, source)))`. Each middleware is a handler wrapping another handler.
