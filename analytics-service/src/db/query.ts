import { sqlite } from './client.js';
import {
  dimName,
  type UsageQuery as UsageQuery_,
  type Dimension,
  type Metric,
  type Where as Where_,
} from './query-schema.js';
type UsageQuery = UsageQuery_;
type Where = Where_;

export { UsageQuery, validate } from './query-schema.js';
export type { UsageQuery, Dimension, Metric, Where, QueryError } from './query-schema.js';

// ---------------------------------------------------------------------------
// SQL rendering
// ---------------------------------------------------------------------------

const UNIT_SECONDS: Record<'minute'|'hour'|'day', number> = {
  minute: 60,
  hour:   3600,
  day:    86400,
};

function dimSQL(d: Dimension): string {
  return d.kind === 'proxyset'
    ? 'proxyset'
    : `json_extract(session_params, '$.${d.key}')`;
}

function metricSQL(m: Metric): string {
  switch (m) {
    case 'connections':    return 'COUNT(*)';
    case 'upload_bytes':   return 'SUM(upload_bytes)';
    case 'download_bytes': return 'SUM(download_bytes)';
    case 'total_bytes':    return 'SUM(upload_bytes + download_bytes)';
  }
}

type BoundArg = string | number;

interface Rendered {
  sql: string;
  args: BoundArg[];
}

function renderWhere(time: UsageQuery['time'], where?: Where): { clauses: string[]; args: BoundArg[] } {
  const clauses: string[] = ['ts >= ?', 'ts <= ?'];
  const args: BoundArg[] = [time.from, time.to];
  if (!where) return { clauses, args };

  const push = (sql: string, ...a: BoundArg[]) => { clauses.push(sql); args.push(...a); };

  if (where.proxyset_eq     != null) push('proxyset = ?',  where.proxyset_eq);
  if (where.proxyset_ne     != null) push('proxyset != ?', where.proxyset_ne);
  if (where.proxyset_in     != null) push(`proxyset IN (${where.proxyset_in.map(()=>'?').join(',')})`,        ...where.proxyset_in);
  if (where.proxyset_not_in != null) push(`proxyset NOT IN (${where.proxyset_not_in.map(()=>'?').join(',')})`, ...where.proxyset_not_in);

  if (where.session_duration_eq      != null) push('session_duration_minutes = ?',  where.session_duration_eq);
  if (where.session_duration_ne      != null) push('session_duration_minutes != ?', where.session_duration_ne);
  if (where.session_duration_gt      != null) push('session_duration_minutes > ?',  where.session_duration_gt);
  if (where.session_duration_gte     != null) push('session_duration_minutes >= ?', where.session_duration_gte);
  if (where.session_duration_lt      != null) push('session_duration_minutes < ?',  where.session_duration_lt);
  if (where.session_duration_lte     != null) push('session_duration_minutes <= ?', where.session_duration_lte);
  if (where.session_duration_between != null) push('session_duration_minutes BETWEEN ? AND ?', where.session_duration_between[0], where.session_duration_between[1]);

  for (const p of where.session_params_eq ?? []) push(`json_extract(session_params, '$.${p.key}') = ?`, p.value);
  for (const p of where.session_params_ne ?? []) push(`json_extract(session_params, '$.${p.key}') != ?`, p.value);
  for (const p of where.session_params_in ?? []) push(
    `json_extract(session_params, '$.${p.key}') IN (${p.values.map(()=>'?').join(',')})`, ...p.values);
  for (const p of where.session_params_not_in ?? []) push(
    `json_extract(session_params, '$.${p.key}') NOT IN (${p.values.map(()=>'?').join(',')})`, ...p.values);
  for (const k of where.session_params_has_key ?? []) push(`json_extract(session_params, '$.${k}') IS NOT NULL`);

  return { clauses, args };
}

export function renderSQL(q: UsageQuery): Rendered {
  const { clauses, args } = renderWhere(q.time, q.where);

  const selectCols: string[] = [];
  const groupCols: string[] = [];

  const hasResolution = q.time.resolution != null;
  if (hasResolution) {
    const r = q.time.resolution!;
    const w = UNIT_SECONDS[r.unit] * r.value;
    selectCols.push(`(ts / ?) * ? AS bucket`);
    groupCols.push('bucket');
    args.unshift(w, w);
  }

  for (const d of q.group_by ?? []) {
    selectCols.push(`${dimSQL(d)} AS ${dimName(d)}`);
    groupCols.push(dimName(d));
  }

  selectCols.push(`${metricSQL(q.metric)} AS value`);

  const sql =
    `SELECT ${selectCols.join(', ')} FROM usage ` +
    `WHERE ${clauses.join(' AND ')}` +
    (groupCols.length ? ` GROUP BY ${groupCols.join(', ')}` : '');

  return { sql, args };
}

// (validate + QueryError live in query-schema.ts — re-exported at top.)

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

export async function runUsageQuery(q: UsageQuery): Promise<UsageQueryResult> {
  const { sql, args } = renderSQL(q);
  const res = await sqlite.execute({ sql, args: args as never });

  const hasResolution = q.time.resolution != null;
  const dims = q.group_by ?? [];
  const dimNames = dims.map(dimName);

  // Pivot rows into series keyed by stringified group.
  const seriesMap = new Map<string, Series>();
  let bucketSet = new Set<number>();

  for (const row of res.rows) {
    const value = Number(row.value ?? 0);
    const ts = hasResolution ? Number(row.bucket) : q.time.from;
    bucketSet.add(ts);

    const group: Record<string, string | number | null> = {};
    for (const n of dimNames) {
      const v = row[n];
      group[n] = v == null ? null : (typeof v === 'number' ? v : String(v));
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

  // Sort points within each series chronologically.
  for (const s of seriesMap.values()) s.points.sort((a, b) => a[0] - b[0]);

  // Sort series.
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

  // Compute global total BEFORE limiting (so total reflects everything matched).
  let total = 0;
  for (const s of series) total += s.total;

  // Apply limit.
  const limit = q.limit ?? 100;
  if (series.length > limit) series = series.slice(0, limit);

  return {
    query:  q,
    series,
    total,
    meta: { series_count: series.length, buckets: bucketSet.size },
  };
}
