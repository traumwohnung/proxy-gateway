# proxy-rotator

A Rust HTTP proxy server that load-balances requests across pools of upstream proxies with round-robin rotation and optional session affinity.

## Architecture

```
Client ──HTTP/CONNECT──→ proxy-rotator ──→ upstream proxy pool ──→ Destination
```

- **No TLS termination** — raw bytes are relayed through CONNECT tunnels. The client's own TLS handshake reaches the destination untouched.
- Multiple **proxy sets** — each with its own pool of upstream proxies, rotation strategy, and optional credentials.
- **Session affinity** — optionally pin a client IP to the same upstream proxy for a configurable duration.
- **Round-robin** — when no affinity is active, requests rotate through the pool.

## Configuration

All configuration lives in a TOML file (default: `config.toml`):

```toml
bind_addr = "127.0.0.1:8100"
log_level = "info"

[[proxy_set]]
name = "residential"
proxies_file = "proxies/residential.txt"
session_affinity_secs = 300         # same client IP → same proxy for 5 min
upstream_username = "user123"       # optional: sent to upstream proxies
upstream_password = "pass456"       # optional: sent to upstream proxies

[[proxy_set]]
name = "datacenter"
proxies_file = "proxies/datacenter.txt"
session_affinity_secs = 0           # pure round-robin
```

### Proxy list files

One proxy per line, `host:port` format. Comments (`#`) and blank lines are ignored:

```
# US datacenter proxies
dc1.proxy.example.com:3128
dc2.proxy.example.com:3128
dc3.proxy.example.com:8080
```

## Usage

```bash
# Build
cargo build --release

# Run (uses ./config.toml by default)
./target/release/proxy-rotator

# Or specify a config file
./target/release/proxy-rotator /path/to/config.toml
```

### Client usage

Clients select a proxy set via the `Proxy-Authorization` header. The **username** is the proxy set name, and the **password** is empty (unused):

```bash
# Use the "residential" proxy set
curl -x http://127.0.0.1:8100 \
  --proxy-user "residential:" \
  https://httpbin.org/ip

# Use the "datacenter" proxy set
curl -x http://127.0.0.1:8100 \
  --proxy-user "datacenter:" \
  https://httpbin.org/ip

# If only one proxy set is configured, auth can be omitted
curl -x http://127.0.0.1:8100 https://httpbin.org/ip
```

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level (overrides config) | from config |

## How It Works

1. Client connects and sends an HTTP request or CONNECT tunnel request
2. The proxy set is selected from `Proxy-Authorization: Basic base64(set_name:)`
3. An upstream proxy is chosen via round-robin (or session affinity if configured)
4. For **CONNECT**: a tunnel is established through the upstream proxy, then raw bytes are relayed bidirectionally — no TLS breaking
5. For **plain HTTP**: the request is forwarded through the upstream proxy with the absolute URI

### Session Affinity

When `session_affinity_secs > 0`, the first request from a client IP gets assigned an upstream proxy via round-robin. Subsequent requests from the same IP reuse the same upstream proxy until the affinity window expires. Expired entries are cleaned up every 60 seconds.

## Docker

```bash
docker build -t proxy-rotator .
docker run -p 8100:8100 \
  -v ./config.toml:/app/config.toml:ro \
  -v ./proxies:/app/proxies:ro \
  proxy-rotator
```

## Building

```bash
cargo build --release
```

No special dependencies — pure Rust with tokio/hyper.

## License

MIT
