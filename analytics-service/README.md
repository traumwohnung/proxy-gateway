# analytics-service

Receives observability events from `proxy-gateway` via gRPC, persists them
in DuckDB, and serves a server-rendered Astro dashboard.

## Stack

- Bun (runtime + package manager)
- Connect-RPC over h2c (HTTP/2 cleartext) — speaks plain gRPC, so a standard
  Go `grpc.Dial` client (the gateway) can connect.
- DuckDB via `waddler/duckdb-neo`; schema managed by a hand-rolled
  append-only migration runner (`src/db/migrations.ts`)
- Astro SSR + React (filter island only) + Tailwind + shadcn primitives

## Layout

```
proto/ingest/v1/ingest.proto   # gateway depends on this only
src/server/                    # gRPC ingest + Astro entry boot
src/db/                        # schema, client, migrations, query.ts
src/web/                       # Astro app (mostly server components)
```

## Environment

| Var                       | Default                  | Purpose                          |
| ------------------------- | ------------------------ | -------------------------------- |
| `ANALYTICS_DB_URL`        | `file:./analytics.duckdb`| DuckDB file path or `:memory:`. Must NOT point at a SQLite file — DuckDB will silently attach it via the sqlite extension and writes go nowhere persistent. |
| `INGEST_TOKEN`            | (unset = no auth)        | Required bearer for ingest gRPC  |
| `INGEST_PORT`             | `50051`                  | gRPC listener                    |
| `DASHBOARD_PORT`          | `4321`                   | Astro HTTP listener              |
| `DASHBOARD_HOST`          | `127.0.0.1`              | Bind address for dashboard       |

The dashboard is **unauthenticated**. Bind it private (`127.0.0.1` or a
reverse proxy) — never expose it publicly.

## Development

```sh
bun install
bun run db:migrate          # apply migrations
bun run build:web           # build Astro
bun run dev                 # boot ingest + dashboard
```

Regenerate proto stubs after editing `proto/ingest/v1/ingest.proto`:

```sh
bunx buf generate
# also regenerate Go stubs into ../proxy-gateway/analytics/gen
(cd .. && protoc \
   --proto_path=analytics-service/proto \
   --go_out=proxy-gateway/analytics/gen --go_opt=paths=source_relative \
   --go-grpc_out=proxy-gateway/analytics/gen --go-grpc_opt=paths=source_relative \
   analytics-service/proto/ingest/v1/ingest.proto)
```

## Wire protocol

`Ingest.RecordEvents` is a single client-streaming RPC carrying one of three
event variants (`ConnectionClosed`, `EpochTransition`, `DropReport`). Each
event has an `event_id` that the server uses as an idempotency key, so
gateway retries are safe.

The gateway is **hash-free**: it ships canonical (sorted-keys, no-whitespace)
JSON for `session_params` and `session_meta`. The ingester computes
`session_hash = sha256[:16](session_params)` and `meta_hash = sha256[:16](session_meta)`
on receipt — there is one hash function, defined exactly once, in
`src/server/ingest.ts`. Empty / `"{}"` JSON maps to empty-string hash
("no value supplied"); the dim tables have no row in that case.

`EpochTransition` carries `session_params` and is emitted by the gateway on
every IP-binding change for a logical session (`first_bind`, `ttl`, `forced`).
Epochs are keyed only by `session_params` — changing `session_meta` never
rotates the IP or forks a session.

## Schema

Four tables, each with one job:

| Table                | Key                       | Purpose |
| -------------------- | ------------------------- | ------- |
| `connection_closed`  | `event_id`                | per-connection facts (bytes, duration, close reason, ip, epoch) + `session_hash` (FK → params dim) + `meta_hash` (FK → meta dim) |
| `session_epoch`      | `(session_hash, epoch)`   | IP-binding generations for a session; params-only by construction |
| `session_params_dim` | `hash`                    | dedup'd canonical `session_params` JSON; one row per distinct identity |
| `session_meta_dim`   | `hash`                    | dedup'd canonical `session_meta` JSON; one row per distinct meta payload |
| `raw_events`         | `event_id`                | source-of-truth event log (one row per accepted event, all variants) |

Separate hash spaces because `session_meta` is per-request enrichment that
can vary inside a session (e.g. `request_id`); folding it into the
`session_params` identity would falsely fork sessions, and folding it onto
the params dim row would force last-write-wins. Both dims dedupe
independently and degrade gracefully (~1 row per connection in the worst
case where every meta payload is unique).

`raw_events` is the commit point in each ingest batch — projection tables
(`connection_closed`, `session_epoch`, `session_*_dim`) are derived from it
and are safe to rebuild from `raw_events` if a projection ever drifts.

## Adding a query

`src/db/query.ts` is the read API. The dashboard pages import `runUsageQuery`
directly — there is no query gRPC service. Reads stay in-process.

Query language supports two JSON dimensions backed by their respective dims:

- `{ kind: "session_params", key: "<k>" }` — JOINs `session_params_dim AS pdim`
- `{ kind: "session_meta", key: "<k>" }` — JOINs `session_meta_dim AS mdim`

Each JOIN is added only when a dimension or `where`-predicate needs it, so
meta-only queries don't pull in the params dim and vice versa.
