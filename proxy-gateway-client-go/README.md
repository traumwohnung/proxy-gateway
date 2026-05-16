# proxy-gateway-client-go

Go client for the [proxy-gateway](https://github.com/traumwohnung/proxy-gateway), plus fluent builders for proxy connections and configurations.

## Installation

```bash
go get github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go
```

## Usage

```go
import proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"

// 1. Configure the gateway connection once.
client := proxygatewayclient.NewProxyClient().
    Proxy("proxy-gateway", 8100).
    Admin("http://proxy-gateway:9000", "mysecretkey")

// 2. Build a proxy configuration. Same configuration → same username forever,
//    so sessions stay stable across processes and call sites.
cfg := proxygatewayclient.NewProxyConfiguration("residential").
    Minutes(60).
    SessionParams("user", "alice").        // identity → drives upstream IP
    SessionMeta("tenant", "acme").         // informational → carried to analytics
    WithProxyClient(client)

// 3a. Get a full proxy URL (http://user:x@host:port)
proxyURL, _ := cfg.BuildURL()

// 3b. Or get an *http.Client wired to route through the proxy
hc, _ := cfg.BuildHTTPClient()

// 4. Re-roll the rotation without changing the username.
_, _ = cfg.Rotate(ctx)
```

### Per-call cloning

Clone a base configuration to add request-specific identity without mutating the shared template:

```go
base := proxygatewayclient.NewProxyConfiguration("residential").Minutes(60).WithProxyClient(client)
perUser := base.Clone().SessionParams("user", email).SessionMeta("request_id", reqID)
url, _ := perUser.BuildURL()
```

### Retry primitive

```go
result, err := proxygatewayclient.RetryN(ctx, cfg, 8, func(i int) (Response, bool) {
    res, err := doRequest(cfg.MustBuildURL())
    if err != nil || res.StatusCode >= 500 {
        return Response{}, false // ask for rotation + retry
    }
    return res, true
})
```

Closure returns `(value, ok)`. `ok=false` → configuration rotates, closure runs again. `ok=true` → loop ends. `RetryN` caps the loop at `maxRetries`; `Retry` is unbounded (closure tracks its own give-up logic).

## API

### `ProxyClient`

| Method | Description |
|--------|-------------|
| `NewProxyClient()` | Start a new client builder |
| `.Proxy(host, port)` | Gateway HTTP proxy endpoint |
| `.ProxyAddr("host:port")` | Same as `.Proxy` but parses a single string |
| `.Admin(baseURL, apiKey)` | Gateway admin API endpoint |
| `.HTTPClient(hc)` | Override the `*http.Client` used for admin calls |

### `ProxyConfiguration`

| Method | Description |
|--------|-------------|
| `NewProxyConfiguration(set)` | Start a configuration for the given proxy set |
| `.Minutes(n)` | Session duration (0 = per-request, 1–1440 = sticky) |
| `.SessionParams(k, v)` | Add a key/value to session_params (drives upstream IP) |
| `.SessionMeta(k, v)` | Add a key/value to session_meta (informational, for analytics) |
| `.MITM()` | Enable MITM mode with default chrome-latest httpcloak |
| `.HTTPCloak(spec)` | Set TLS fingerprint spec (implies MITM) |
| `.Scripts(entries…)` / `.ScriptRef(name)` / `.ScriptSource(src)` | Append to the script chain (implies MITM) |
| `.NoMITM()` | Disable MITM and drop any httpcloak/scripts |
| `.WithProxyClient(c)` | Attach gateway connection (required for URL/HTTPClient/Rotate) |
| `.Clone()` | Deep-copy (session_params + session_meta copied, client pointer shared) |
| `.BuildUsername()` / `.MustBuildUsername()` | Encode the current config to base64 |
| `.BuildURL()` / `.MustBuildURL()` | Full `http://user:x@host:port` URL |
| `.BuildHTTPClient()` | `*http.Client` whose Transport routes through the gateway |
| `.Rotate(ctx)` | Re-roll rotation for the current username via admin API |

### Username helpers

| Function | Description |
|----------|-------------|
| `BuildUsername(UsernameParams)` | Encode params into a base64 proxy username |
| `ParseUsername(string)` | Decode a base64 username back to its params |

### Admin client (low-level)

| Method | Description |
|--------|-------------|
| `ListSessions(ctx)` | List all active sticky sessions |
| `GetSession(ctx, username)` | Get a session by base64 username (nil if not found) |
| `RotateNow(ctx, username)` | Re-roll rotation — gateway picks a new upstream (nil if not found) |

### Retry

| Function | Description |
|----------|-------------|
| `Retry(ctx, cfg, fn)` | Run `fn(attempt)` until it returns `ok=true`, rotating between failed attempts |
| `RetryN(ctx, cfg, max, fn)` | Same as `Retry` but capped at `max` attempts |
