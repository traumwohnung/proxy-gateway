import { sql } from './client.js';
import {
  dimName,
  dimRequiresDim,
  whereRequiresDim,
  type UsageQuery as UsageQuery_,
  type Dimension,
  type Metric,
  type Where as Where_,
} from './query-schema.js';
type UsageQuery = UsageQuery_;
type Where = Where_;

export { UsageQuery, validate } from './query-schema.js';
export type { Dimension, Metric, Where, QueryError } from './query-schema.js';

// ---------------------------------------------------------------------------
// SQL rendering for the analytics dashboard.
//
// All values that reach SQL come from zod-validated input. Strings are
// inline-quoted (single-quote doubled); numbers are inlined as-is; JSON keys
// and identifier names are constrained by regex upstream so direct
// interpolation is injection-safe. We pass the assembled string through
// waddler's sql.raw — no separate parameter binding needed.
//
// Queries target `connection_closed AS cc`. When a JSON dimension or filter
// is present, we LEFT JOIN `session_params_dim AS dim` and read keys via
// DuckDB's json_extract_string.
// ---------------------------------------------------------------------------

const UNIT_SECONDS: Record<'minute'|'hour'|'day', number> = {
  minute: 60,
  hour:   3600,
  day:    86400,
};

function quoteStr(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

function quoteList(values: readonly (string | number)[]): string {
  return values.map((v) => (typeof v === 'number' ? String(v) : quoteStr(v))).join(', ');
}

function quoteScalar(v: string | number): string {
  return typeof v === 'number' ? String(v) : quoteStr(v);
}

function dimExpr(d: Dimension): string {
  switch (d.kind) {
    case 'proxyset':     return 'cc.proxyset';
    case 'provider':     return 'cc.provider';
    case 'close_reason': return 'cc.close_reason';
    case 'json':         return `json_extract_string(dim.params_json, '$.${d.key}')`;
  }
}

function metricExpr(m: Metric): string {
  switch (m) {
    case 'connections':    return 'COUNT(*)';
    case 'upload_bytes':   return 'SUM(CAST(cc.upload_bytes AS DOUBLE))';
    case 'download_bytes': return 'SUM(CAST(cc.download_bytes AS DOUBLE))';
    case 'total_bytes':    return 'SUM(CAST(cc.upload_bytes AS DOUBLE) + CAST(cc.download_bytes AS DOUBLE))';
  }
}

function jsonKeyExpr(key: string): string {
  return `json_extract_string(dim.params_json, '$.${key}')`;
}

function renderWhere(time: UsageQuery['time'], where: Where | undefined, needsDim: boolean): string[] {
  const clauses: string[] = [`cc.ts >= ${time.from}`, `cc.ts <= ${time.to}`];
  if (!where) return clauses;

  if (where.proxyset_eq     != null) clauses.push(`cc.proxyset = ${quoteStr(where.proxyset_eq)}`);
  if (where.proxyset_ne     != null) clauses.push(`cc.proxyset != ${quoteStr(where.proxyset_ne)}`);
  if (where.proxyset_in     != null) clauses.push(`cc.proxyset IN (${quoteList(where.proxyset_in)})`);
  if (where.proxyset_not_in != null) clauses.push(`cc.proxyset NOT IN (${quoteList(where.proxyset_not_in)})`);

  if (where.provider_eq     != null) clauses.push(`cc.provider = ${quoteStr(where.provider_eq)}`);
  if (where.provider_ne     != null) clauses.push(`cc.provider != ${quoteStr(where.provider_ne)}`);
  if (where.provider_in     != null) clauses.push(`cc.provider IN (${quoteList(where.provider_in)})`);
  if (where.provider_not_in != null) clauses.push(`cc.provider NOT IN (${quoteList(where.provider_not_in)})`);

  if (where.close_reason_eq != null) clauses.push(`cc.close_reason = ${quoteStr(where.close_reason_eq)}`);
  if (where.close_reason_in != null) clauses.push(`cc.close_reason IN (${quoteList(where.close_reason_in)})`);

  if (where.session_duration_eq      != null) clauses.push(`cc.session_duration_minutes = ${where.session_duration_eq}`);
  if (where.session_duration_ne      != null) clauses.push(`cc.session_duration_minutes != ${where.session_duration_ne}`);
  if (where.session_duration_gt      != null) clauses.push(`cc.session_duration_minutes > ${where.session_duration_gt}`);
  if (where.session_duration_gte     != null) clauses.push(`cc.session_duration_minutes >= ${where.session_duration_gte}`);
  if (where.session_duration_lt      != null) clauses.push(`cc.session_duration_minutes < ${where.session_duration_lt}`);
  if (where.session_duration_lte     != null) clauses.push(`cc.session_duration_minutes <= ${where.session_duration_lte}`);
  if (where.session_duration_between != null) clauses.push(`cc.session_duration_minutes BETWEEN ${where.session_duration_between[0]} AND ${where.session_duration_between[1]}`);

  if (needsDim) {
    for (const p of where.session_params_eq ?? []) clauses.push(`${jsonKeyExpr(p.key)} = ${quoteScalar(p.value)}`);
    for (const p of where.session_params_ne ?? []) clauses.push(`${jsonKeyExpr(p.key)} != ${quoteScalar(p.value)}`);
    for (const p of where.session_params_in ?? []) clauses.push(`${jsonKeyExpr(p.key)} IN (${quoteList(p.values)})`);
    for (const p of where.session_params_not_in ?? []) clauses.push(`${jsonKeyExpr(p.key)} NOT IN (${quoteList(p.values)})`);
    for (const k of where.session_params_has_key ?? []) clauses.push(`${jsonKeyExpr(k)} IS NOT NULL`);
  }

  return clauses;
}

export function renderSQL(q: UsageQuery): string {
  const needsDim = (q.group_by ?? []).some(dimRequiresDim) || whereRequiresDim(q.where);
  const clauses = renderWhere(q.time, q.where, needsDim);

  const selectCols: string[] = [];
  const groupCols: string[] = [];

  if (q.time.resolution != null) {
    const r = q.time.resolution;
    const w = UNIT_SECONDS[r.unit] * r.value;
    selectCols.push(`(cc.ts / ${w}) * ${w} AS bucket`);
    groupCols.push('bucket');
  }

  for (const d of q.group_by ?? []) {
    const alias = `"${dimName(d)}"`;
    selectCols.push(`${dimExpr(d)} AS ${alias}`);
    groupCols.push(alias);
  }

  selectCols.push(`${metricExpr(q.metric)} AS value`);

  const join = needsDim
    ? 'LEFT JOIN session_params_dim AS dim ON dim.hash = cc.session_params_hash'
    : '';

  const groupBy = groupCols.length ? `GROUP BY ${groupCols.join(', ')}` : '';

  return (
    `SELECT ${selectCols.join(', ')} FROM connection_closed AS cc ${join} ` +
    `WHERE ${clauses.join(' AND ')} ${groupBy}`
  );
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

export interface Series {
  group:  Record<string, string | number | null>;
  total:  number;
  points: [number, number][];
}

export interface UsageQueryResult {
  query:  UsageQuery;
  series: Series[];
  total:  number;
  meta:   { series_count: number; buckets: number };
}

type RawRow = Record<string, unknown>;

function rowVal(v: unknown, fallback: number): number {
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'number') return v;
  if (v == null) return fallback;
  return Number(v);
}

export async function runUsageQuery(q: UsageQuery): Promise<UsageQueryResult> {
  const text = renderSQL(q);
  const rows = (await sql`${sql.raw(text)}`) as RawRow[];

  const hasResolution = q.time.resolution != null;
  const dims = q.group_by ?? [];
  const dimNames = dims.map(dimName);

  const seriesMap = new Map<string, Series>();
  const bucketSet = new Set<number>();

  for (const row of rows) {
    const value = rowVal(row.value, 0);
    const ts = hasResolution ? rowVal(row.bucket, q.time.from) : q.time.from;
    bucketSet.add(ts);

    const group: Record<string, string | number | null> = {};
    for (const n of dimNames) {
      const v = row[n];
      if (v == null) {
        group[n] = null;
      } else if (typeof v === 'bigint') {
        group[n] = Number(v);
      } else if (typeof v === 'number') {
        group[n] = v;
      } else {
        group[n] = String(v);
      }
    }
    const key = JSON.stringify(group);

    let s = seriesMap.get(key);
    if (!s) {
      s = { group, total: 0, points: [] };
      seriesMap.set(key, s);
    }
    s.points.push([ts, value]);
    s.total += value;
  }

  for (const s of seriesMap.values()) s.points.sort((a, b) => a[0] - b[0]);

  const sortBy  = q.sort?.by  ?? 'metric';
  const sortDir = q.sort?.dir ?? 'desc';
  const cmpNum = (a: number, b: number) => sortDir === 'asc' ? a - b : b - a;
  const cmpStr = (a: string, b: string) => sortDir === 'asc' ? a.localeCompare(b) : b.localeCompare(a);

  let series = [...seriesMap.values()];
  if (sortBy === 'metric') {
    series.sort((a, b) => cmpNum(a.total, b.total));
  } else if (sortBy === 'time') {
    const lastTs = (s: Series) => s.points.length ? s.points[s.points.length - 1]![0] : 0;
    series.sort((a, b) => cmpNum(lastTs(a), lastTs(b)));
  } else {
    series.sort((a, b) => {
      const va = a.group[sortBy];
      const vb = b.group[sortBy];
      if (typeof va === 'number' && typeof vb === 'number') return cmpNum(va, vb);
      return cmpStr(String(va ?? ''), String(vb ?? ''));
    });
  }

  let total = 0;
  for (const s of series) total += s.total;

  const limit = q.limit ?? 100;
  if (series.length > limit) series = series.slice(0, limit);

  return {
    query:  q,
    series,
    total,
    meta: { series_count: series.length, buckets: bucketSet.size },
  };
}
