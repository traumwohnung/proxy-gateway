# Proxy-Gateway Observability — Composed Plan v2

## Goal

Lay groundwork now (libSQL + current event volumes) so the same transport and schema carry us into ClickHouse/DuckDB later without migration pain. Capture enough signal that the vision's billing- and quality-critical features (cache savings, IP quality scoring, session analytics, agentic query) are answerable the day they're built. Treat ingest as **eventually consistent, out-of-order, at-least-once, lossy**.

---

## Architecture in one picture

```
gateway (fire-and-forget)
   │  gRPC stream: Event { event_id, ts, oneof payload }
   ▼
analytics-service ingest handler
   │
   ├─► raw_events            (LOG — source of truth, append-only JSON)
   │
   └─► projection writers
          ├─► session_params_dim   (identity, lazy upsert)
          ├─► session_epoch        (IP bindings over time, append-only)
          ├─► connection_closed    (per-connection activity, append-only)
          └─► mitm_request         (reserved, empty for now)

           rollups (later) ← built from projections, cache only
```

- **Log** is truth. Projections and rollups are caches; rebuildable.
- One idempotency surface: `event_id` in `raw_events`.
- Projections never block log inserts. If a projection writer fails, the log still has the row; we replay.

---

## Transport: event union over the existing gRPC stream

```proto
service Ingest {
  rpc RecordEvents(stream Event) returns (RecordAck) {}
}

message Event {
  google.protobuf.Timestamp ts = 1;
  string event_id = 2;             // gateway-generated ULID, idempotency key
  oneof payload {
    ConnectionClosed connection_closed = 10;
    EpochTransition  epoch_transition  = 11;
    DropReport       drop_report       = 12;
    MitmRequest      mitm_request      = 13;   // reserved, not emitted
  }
}

message ConnectionClosed {
  string connection_id        = 1;
  string proxyset             = 2;
  string provider             = 3;
  string session_params_hash  = 4;   // first 16 bytes of SHA-256(canonical_json), hex
  int32  session_duration_minutes = 5;
  int32  epoch                = 6;
  string upstream_ip          = 7;
  string sni                  = 8;
  string close_reason         = 9;   // ok|client_close|upstream_err|timeout|auth_fail
  int64  upload_bytes         = 10;
  int64  download_bytes       = 11;
  int64  duration_ms          = 12;
}

message EpochTransition {
  string session_params_hash  = 1;
  string params_json          = 2;   // canonical JSON. Populated on first_bind; may be empty otherwise.
  string proxyset             = 3;
  string provider             = 4;
  int32  prev_epoch           = 5;   // -1 on first_bind
  int32  new_epoch            = 6;
  string prev_ip              = 7;   // empty on first_bind
  string new_ip               = 8;
  string start_reason         = 9;   // first_bind|ttl|forced|burned|upstream_5xx|client_signal|pool_reshuffle
}

message DropReport {
  int64 dropped_events = 1;
  google.protobuf.Timestamp window_start = 2;
  google.protobuf.Timestamp window_end   = 3;
}

message MitmRequest { /* reserved */ }

message RecordAck { uint64 accepted = 1; }
```

Notes:
- `session_params_hash` = first 16 bytes of SHA-256 over **canonical JSON** (sorted keys, no whitespace, fixed number formatting). Canonicalization rule pinned in a comment on the proto field; same library used on gateway and any back-fill path.
- `event_id` is a gateway-generated ULID, so reconnect-replay and at-least-once are safe.
- `EpochTransition.params_json` rides only on `first_bind`; lazy backfill handles drops.
- `DropReport` makes queue-full loss visible instead of silent.
- `MitmRequest` is reserved; adding emission later is non-breaking.

---

## Persistence: libSQL today, ClickHouse-shaped

### Layer 1 — the log

```sql
CREATE TABLE raw_events (
  event_id    TEXT PRIMARY KEY,        -- ULID
  ts          INTEGER NOT NULL,        -- unix seconds, from event
  kind        TEXT NOT NULL,           -- 'connection_closed'|'epoch_transition'|'drop_report'|'mitm_request'
  payload     TEXT NOT NULL,           -- canonical JSON of the variant
  ingested_at INTEGER NOT NULL         -- unix seconds, server clock
);
CREATE INDEX raw_ts_kind   ON raw_events(ts, kind);
CREATE INDEX raw_ingested  ON raw_events(ingested_at);
```

Source of truth. Append-only. `INSERT OR IGNORE` on `event_id`. Everything below is rebuildable from here.

### Layer 2 — projections

**`session_params_dim`** — identity.

```sql
CREATE TABLE session_params_dim (
  hash         TEXT PRIMARY KEY,
  params_json  TEXT NOT NULL DEFAULT '',   -- '' until we see an event that carries it
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL
);
```

Lazy upsert. Any event carrying a hash does `INSERT OR IGNORE (hash, '', ts, ts)`. When an event carries `params_json`, backfill: `UPDATE ... SET params_json = ? WHERE hash = ? AND params_json = ''`. `last_seen` updated on every reference.

**`session_epoch`** — IP bindings over time. Fully append-only; no `ended_at`/`end_reason`.

```sql
CREATE TABLE session_epoch (
  session_params_hash TEXT NOT NULL,
  epoch               INTEGER NOT NULL,
  upstream_ip         TEXT NOT NULL,
  proxyset            TEXT NOT NULL,
  provider            TEXT NOT NULL DEFAULT '',
  started_at          INTEGER NOT NULL,
  start_reason        TEXT NOT NULL,    -- first_bind|ttl|forced|burned|...
  event_id            TEXT NOT NULL UNIQUE,
  PRIMARY KEY (session_params_hash, epoch)
);
CREATE INDEX epoch_ip_started ON session_epoch(upstream_ip, started_at);
CREATE INDEX epoch_started_reason ON session_epoch(started_at, start_reason);
```

End-of-epoch is derived: `LEAD(started_at) OVER (PARTITION BY hash ORDER BY epoch)`. End-reason of epoch N is the `start_reason` of epoch N+1. Missing transitions show up as gaps in the `epoch` sequence — visible, not silently corrupting.

**`connection_closed`** — per-connection activity log.

```sql
CREATE TABLE connection_closed (
  event_id            TEXT PRIMARY KEY,
  ts                  INTEGER NOT NULL,
  connection_id       TEXT NOT NULL,
  proxyset            TEXT NOT NULL,
  provider            TEXT NOT NULL DEFAULT '',
  session_params_hash TEXT NOT NULL,
  epoch               INTEGER NOT NULL,
  session_duration_minutes INTEGER NOT NULL DEFAULT 0,
  upstream_ip         TEXT NOT NULL DEFAULT '',
  sni                 TEXT NOT NULL DEFAULT '',
  close_reason        TEXT NOT NULL DEFAULT 'ok',
  upload_bytes        INTEGER NOT NULL DEFAULT 0,
  download_bytes      INTEGER NOT NULL DEFAULT 0,
  duration_ms         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX cc_ts              ON connection_closed(ts);
CREATE INDEX cc_proxyset_ts     ON connection_closed(proxyset, ts);
CREATE INDEX cc_session_hash_ts ON connection_closed(session_params_hash, ts);
CREATE INDEX cc_provider_ts     ON connection_closed(provider, ts);
```

**`mitm_request`** — reserved.

```sql
CREATE TABLE mitm_request (
  event_id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL
  -- columns added when MITM ingest lands
);
```

### Migration-readiness properties

- Append-only; no UPDATEs in fact tables (only `session_params_dim` has a single backfill UPDATE).
- One table per event kind → matches ClickHouse `MergeTree` grain.
- String enums → become `LowCardinality(String)`.
- `ts` as unix seconds → directly `DateTime`.
- JSON only in `raw_events.payload` and `session_params_dim.params_json`; fact rows are fully flat.
- Indexes are advisory; ClickHouse sort keys replace them.

---

## Gateway-side write path

Each lifecycle moment, the gateway computes the hash locally (canonical JSON → SHA-256 first 16 bytes hex) and emits:

1. **New logical session seen** (first IP assigned):
   - `EpochTransition { prev_epoch: -1, new_epoch: 0, start_reason: 'first_bind', params_json: <canonical> }`
2. **IP changes** (rotation, TTL, provider drop, quality eviction, reshuffle):
   - `EpochTransition { prev_epoch: N, new_epoch: N+1, start_reason: <reason>, prev_ip, new_ip }`
3. **Connection closes**:
   - `ConnectionClosed { connection_id, hash, epoch, upstream_ip, close_reason, bytes, duration_ms, ... }`
4. **Periodic** (every minute or every 1000 drops, whichever first):
   - `DropReport { dropped_events, window_start, window_end }`

Hot path stays non-blocking: bounded send queue, drop-on-full, no DB round-trips, no coordination across gateway instances. Epoch numbering is local to (gateway, hash); rare collisions across multi-gateway sharding accepted for now (`PK (hash, epoch)` rejects duplicates; revisit with ULID epochs only if collisions become real).

---

## Ingest server write path

One handler, per event:

```
transaction:
  INSERT OR IGNORE INTO raw_events (event_id, ts, kind, payload, ingested_at)
  if inserted:
      dispatch(kind, payload)   # writes to projection table(s)
commit
```

`dispatch` per kind:

- **`connection_closed`** → `INSERT OR IGNORE INTO connection_closed (...)` + `INSERT OR IGNORE INTO session_params_dim (hash, '', ts, ts)` + `UPDATE session_params_dim SET last_seen = max(last_seen, ts) WHERE hash = ?`.
- **`epoch_transition`** → `INSERT OR IGNORE INTO session_epoch (...)`; if `params_json != ''`, `INSERT OR IGNORE` dim row with it, plus the backfill `UPDATE ... WHERE params_json = ''`.
- **`drop_report`** → log only (in `raw_events`); surface in metrics endpoint.
- **`mitm_request`** → log only for now; no projection table yet.

Batching: keep the 500-row / 250 ms batcher. Per-batch transaction. Idempotency from `event_id` makes retries safe.

Projection failures must **not** roll back the log insert; the log write is the commit point. A separate replay job can rebuild any projection from `raw_events` on demand.

---

## Read-side guarantees

Dashboards and the agent layer must treat results as **lower bounds, eventually consistent**:

- Bandwidth totals: lower bound (drops are silent, `DropReport` makes loss observable).
- Epoch counts per hash: lower bound; gaps in epoch numbers indicate dropped transitions.
- "Currently active session": "max(epoch) for hash AND a recent `connection_closed`", never "epoch with NULL end."
- Joins: `LEFT JOIN` between event kinds, never `INNER` — a `connection_closed` may reference a hash whose dim row hasn't been backfilled yet.

Documented in the analytics-service README.

---

## Queryable answers on day one

- Bandwidth by session intent (`connection_closed` × `session_params_dim`).
- Bandwidth by provider / proxyset (direct GROUP BY).
- Rotation rate by reason (`session_epoch` GROUP BY `start_reason`).
- IPs burned per session (`COUNT(epoch)` per hash).
- Which sessions touched IP X (`session_epoch WHERE upstream_ip = ?`).
- Connection failure rate by `close_reason`.
- Average IP lifetime per provider (`LEAD(started_at) - started_at` over `session_epoch`).
- Known data loss (`DropReport` aggregates).

---

## Retention policy

At current volumes, keep everything. The shape is:

- **Hot raw** (`raw_events`, recent N days) — full grain, ad-hoc, debugging, agent queries, billing audit window.
- **Projections** — kept as long as raw is kept; rebuildable.
- **Rollups** (later) — cache only.
- **Cold raw** (later, post-ClickHouse) — older `raw_events` moved to S3/Parquet, queryable but slow.
- **Drop nothing now.** Revisit when `raw_events` size genuinely hurts.

---

## Deferred

- **MITM ingestion** — proto variant + empty table reserved. No emission. Schema for `mitm_request` columns (host, status, cache_outcome, bytes_saved, blocked_reason, tls_fp_profile, …) designed when MITM goes to production.
- **Cache-savings billing** — depends on MITM.
- **Quality feedback / bad-IP-per-domain** — depends on MITM (needs domain dimension).
- **ClickHouse / DuckDB migration** — schema ready; flip when libSQL hurts.
- **Rollups & materialized views** — built on top of projections once dashboard query patterns stabilize.
- **Agentic query layer** — curated metric endpoints over projections + a schema-aware structured-query tool ({dimensions, filters, metrics, time_range} → SQL). Designed after we have real query patterns to learn from.
- **Tenant / workload labels** on `session_params_dim` — column added when multi-tenant lands.
- **Multi-gateway sharding without sticky routing** — revisit integer-epoch collision via ULID epochs if it bites.

---

## Implementation order

1. **Proto**: add `Event` envelope with `oneof` payload; keep `RecordEvents` stream-of-Event; deprecate old `RecordUsage`/`UsageDelta` after one release of dual-write.
2. **libSQL migration**: create `raw_events`, `session_params_dim`, `session_epoch`, `connection_closed`, empty `mitm_request`. Drop or back-fill old `usage` table from `connection_closed`.
3. **Ingest server**: log-first write path; per-kind projection writers; preserve batching; surface `DropReport` count via metrics.
4. **Gateway**: compute hash on the hot path; emit `EpochTransition` from the session manager (first_bind + all rotations/TTL/reshuffle); enrich `ConnectionClosed` with `connection_id`, `epoch`, `upstream_ip`, `close_reason`, `duration_ms`; periodic `DropReport` from the bounded queue.
5. **Read API + dashboard**: rewire existing dashboard queries to the projection tables; add the day-one queries listed above.
6. **Replay tool**: a small `analytics-service` command that rebuilds any projection from `raw_events` over a time range. Useful immediately, essential later.

---

## Open question to resolve before cutting code

**Canonical JSON spec.** Which library/rule on the gateway (Go) and on any future back-fill path (TS)? Pinning this now prevents the only failure mode of the hash-based design — two implementations producing different hashes for the same logical params.
