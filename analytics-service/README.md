# analytics-service

Receives usage deltas from `proxy-gateway` via gRPC, persists them in libSQL,
and serves a server-rendered Astro dashboard.

## Stack

- Bun (runtime + package manager)
- Connect-RPC over h2c (HTTP/2 cleartext) — speaks plain gRPC, so a standard
  Go `grpc.Dial` client (the gateway) can connect.
- libSQL via `@libsql/client` + Drizzle ORM
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
| `ANALYTICS_DB_URL`        | `file:./analytics.db`    | libSQL URL (or `libsql://...`)   |
| `ANALYTICS_DB_AUTH_TOKEN` | -                        | Turso auth token, if remote      |
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

## Adding a query

`src/db/query.ts` is the read API. The dashboard pages import `queryUsage`
directly — there is no query gRPC service. Reads stay in-process.
