// Custom migration runner for the analytics-service DuckDB.
//
// Why hand-rolled and not drizzle-kit? Drizzle's DuckDB story is community-
// third-party and the migration tooling is not first-class. We have a small,
// versioned schema and clear control needs (single writer, append-only
// projections), so a 50-line versioned runner is simpler and lets us write
// DuckDB-flavoured SQL directly without fighting a generator.
//
// Versioning model:
//   - Single `schema_migrations` table with one row per applied migration.
//   - Current version = MAX(version) on that table, 0 if empty.
//   - Each Migration has a unique strictly-increasing integer `version`.
//   - `runMigrations` skips versions <= current and applies the rest in order,
//     wrapped in a BEGIN/COMMIT each so a failed step rolls back cleanly.

import { sql } from './client.js';

interface Migration {
  version: number;
  description: string;
  apply: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// Migration steps
//
// Append-only — never edit an existing step's `apply`. New schema changes
// land as a new Migration with the next integer version.
// ---------------------------------------------------------------------------

const migrations: Migration[] = [
  {
    version: 1,
    description: 'event log + projections',
    apply: async () => {
      // raw_events — source-of-truth log. event_id is the idempotency key.
      await sql`
        CREATE TABLE raw_events (
          event_id    TEXT PRIMARY KEY,
          ts          BIGINT NOT NULL,
          kind        TEXT NOT NULL,
          payload     TEXT NOT NULL,
          ingested_at BIGINT NOT NULL
        )
      `;
      await sql`CREATE INDEX raw_ts_kind  ON raw_events(ts, kind)`;
      await sql`CREATE INDEX raw_ingested ON raw_events(ingested_at)`;

      // session_params_dim — identity for logical sessions.
      //
      // params_json uses DuckDB's native JSON type. The engine validates
      // inserts (invalid JSON is rejected at write time, so the gateway
      // cannot silently poison the table) and json_extract_* functions read
      // cleanly. The column is nullable: NULL means "we have not yet seen
      // the canonical JSON for this hash" — set by a hash-only event such
      // as ConnectionClosed and lazily backfilled the first time an
      // EpochTransition delivers it.
      await sql`
        CREATE TABLE session_params_dim (
          hash         TEXT PRIMARY KEY,
          params_json  JSON,
          first_seen   BIGINT NOT NULL,
          last_seen    BIGINT NOT NULL
        )
      `;

      // session_epoch — IP-binding generations over time, append-only.
      await sql`
        CREATE TABLE session_epoch (
          session_params_hash TEXT NOT NULL,
          epoch               INTEGER NOT NULL,
          upstream_ip         TEXT NOT NULL,
          proxyset            TEXT NOT NULL,
          provider            TEXT NOT NULL DEFAULT '',
          started_at          BIGINT NOT NULL,
          start_reason        TEXT NOT NULL,
          event_id            TEXT NOT NULL UNIQUE,
          PRIMARY KEY (session_params_hash, epoch)
        )
      `;
      await sql`CREATE INDEX epoch_ip_started     ON session_epoch(upstream_ip, started_at)`;
      await sql`CREATE INDEX epoch_started_reason ON session_epoch(started_at, start_reason)`;

      // connection_closed — per-connection activity log.
      await sql`
        CREATE TABLE connection_closed (
          event_id                 TEXT PRIMARY KEY,
          ts                       BIGINT NOT NULL,
          connection_id            TEXT NOT NULL,
          proxyset                 TEXT NOT NULL,
          provider                 TEXT NOT NULL DEFAULT '',
          session_params_hash      TEXT NOT NULL,
          epoch                    INTEGER NOT NULL,
          session_duration_minutes INTEGER NOT NULL DEFAULT 0,
          upstream_ip              TEXT NOT NULL DEFAULT '',
          sni                      TEXT NOT NULL DEFAULT '',
          close_reason             TEXT NOT NULL DEFAULT 'ok',
          upload_bytes             BIGINT NOT NULL,
          download_bytes           BIGINT NOT NULL,
          duration_ms              BIGINT NOT NULL
        )
      `;
      await sql`CREATE INDEX cc_ts              ON connection_closed(ts)`;
      await sql`CREATE INDEX cc_proxyset_ts     ON connection_closed(proxyset, ts)`;
      await sql`CREATE INDEX cc_session_hash_ts ON connection_closed(session_params_hash, ts)`;
      await sql`CREATE INDEX cc_provider_ts     ON connection_closed(provider, ts)`;

      // mitm_request — reserved (slice will add columns when MITM lands).
      await sql`
        CREATE TABLE mitm_request (
          event_id TEXT PRIMARY KEY,
          ts       BIGINT NOT NULL
        )
      `;
    },
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export async function getCurrentVersion(): Promise<number> {
  await sql`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    INTEGER PRIMARY KEY,
      applied_at BIGINT NOT NULL
    )
  `;
  type Row = { version: number | bigint };
  const rows =
    (await sql`SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`) as Row[];
  if (rows.length === 0) return 0;
  return Number(rows[0]?.version);
}

export async function runMigrations(): Promise<{ from: number; to: number; applied: number[] }> {
  let current = await getCurrentVersion();
  const startVersion = current;
  const applied: number[] = [];

  const ordered = [...migrations].sort((a, b) => a.version - b.version);
  for (const m of ordered) {
    if (m.version <= current) continue;
    if (m.version !== current + 1) {
      throw new Error(
        `migration version gap: at ${current}, next migration is ${m.version} (expected ${current + 1})`,
      );
    }
    console.log(`[migrate] applying ${m.version}: ${m.description}`);
    await sql`BEGIN TRANSACTION`;
    try {
      await m.apply();
      const now = Math.floor(Date.now() / 1000);
      await sql`INSERT INTO schema_migrations (version, applied_at) VALUES (${m.version}, ${now})`;
      await sql`COMMIT`;
    } catch (err) {
      await sql`ROLLBACK`.execute().catch(() => undefined);
      throw err;
    }
    current = m.version;
    applied.push(m.version);
  }
  return { from: startVersion, to: current, applied };
}

// Latest known migration version (for sanity checks).
export const TARGET_VERSION: number = migrations.reduce((max, m) => Math.max(max, m.version), 0);
