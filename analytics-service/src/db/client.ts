import { waddler } from 'waddler/duckdb-neo';

// ANALYTICS_DB_URL may be a plain path (`./analytics.duckdb`) or `:memory:`.
// We strip a leading `file:` prefix for compat with the older configuration.
function resolvePath(raw: string): string {
  if (raw.startsWith('file:')) return raw.slice('file:'.length);
  return raw;
}

const url = resolvePath(process.env.ANALYTICS_DB_URL ?? './analytics.duckdb');

// DuckDB is a single-writer engine. We pin the pool to one connection so all
// ingest transactions (BEGIN/.../COMMIT issued as separate sql template calls)
// land on the same physical session — otherwise BEGIN on one connection and
// the following INSERTs on another would simply not be inside a transaction.
export const sql = waddler({ url, min: 1, max: 1 });
