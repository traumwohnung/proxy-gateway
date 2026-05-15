import { z } from 'zod';
import { sqlite } from './client.js';

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const JsonKey = z.string().regex(/^[A-Za-z0-9_.\-]+$/, 'invalid json key');

const TimeResolution = z.object({
  unit:  z.enum(['minute', 'hour', 'day']),
  value: z.int().positive(),
});

const Time = z.object({
  from: z.int(),
  to:   z.int(),
  resolution: TimeResolution.optional(),
}).refine((t) => t.from < t.to, { message: 'time.from must be less than time.to' });

const Metric = z.enum(['connections', 'upload_bytes', 'download_bytes', 'total_bytes']);

const Dimension = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('proxyset'), as: z.string().optional() }),
  z.object({ kind: z.literal('json'), key: JsonKey, as: z.string().optional() }),
]);

const ScalarValue = z.union([z.string(), z.number()]);

const JsonPredicate    = z.object({ key: JsonKey, value: ScalarValue });
const JsonInPredicate  = z.object({ key: JsonKey, values: z.array(ScalarValue).min(1) });

const Where = z.object({
  proxyset_eq:              z.string().optional(),
  proxyset_ne:              z.string().optional(),
  proxyset_in:              z.array(z.string()).min(1).optional(),
  proxyset_not_in:          z.array(z.string()).min(1).optional(),

  session_duration_eq:      z.int().optional(),
  session_duration_ne:      z.int().optional(),
  session_duration_gt:      z.int().optional(),
  session_duration_gte:     z.int().optional(),
  session_duration_lt:      z.int().optional(),
  session_duration_lte:     z.int().optional(),
  session_duration_between: z.tuple([z.int(), z.int()]).optional(),

  session_params_eq:        z.array(JsonPredicate).min(1).optional(),
  session_params_ne:        z.array(JsonPredicate).min(1).optional(),
  session_params_in:        z.array(JsonInPredicate).min(1).optional(),
  session_params_not_in:    z.array(JsonInPredicate).min(1).optional(),
  session_params_has_key:   z.array(JsonKey).min(1).optional(),
}).strict();

const Sort = z.object({
  by:  z.string().min(1).default('metric'),
  dir: z.enum(['asc', 'desc']).default('desc'),
});

export const UsageQuery = z.object({
  time:     Time,
  metric:   Metric,
  where:    Where.optional(),
  group_by: z.array(Dimension).optional(),
  sort:     Sort.optional(),
  limit:    z.int().min(1).max(1000).optional(),
}).strict();

export type UsageQuery       = z.infer<typeof UsageQuery>;
export type Dimension        = z.infer<typeof Dimension>;
export type Metric           = z.infer<typeof Metric>;
export type Where            = z.infer<typeof Where>;

// ---------------------------------------------------------------------------
// SQL rendering
// ---------------------------------------------------------------------------

const UNIT_SECONDS: Record<'minute'|'hour'|'day', number> = {
  minute: 60,
  hour:   3600,
  day:    86400,
};

const MAX_BUCKETS = 10_000;

function dimName(d: Dimension): string {
  if (d.as) return d.as;
  return d.kind === 'proxyset' ? 'proxyset' : d.key;
}

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

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface QueryError { error: string; path?: string }

export function validate(input: unknown): { ok: true; query: UsageQuery } | { ok: false; errors: QueryError[] } {
  const parsed = UsageQuery.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      errors: parsed.error.issues.map((i) => ({
        error: i.message,
        path:  i.path.join('.'),
      })),
    };
  }
  const q = parsed.data;

  const errors: QueryError[] = [];

  // bucket-count guardrail
  if (q.time.resolution) {
    const w = UNIT_SECONDS[q.time.resolution.unit] * q.time.resolution.value;
    const buckets = Math.ceil((q.time.to - q.time.from) / w);
    if (buckets > MAX_BUCKETS) {
      errors.push({ error: `resolution too fine: would produce ${buckets} buckets (max ${MAX_BUCKETS})`, path: 'time.resolution' });
    }
  }

  // sort.by must be 'metric', 'time', or a group_by dim name
  if (q.sort) {
    const validNames = new Set<string>(['metric', 'time']);
    for (const d of q.group_by ?? []) validNames.add(dimName(d));
    if (!validNames.has(q.sort.by)) {
      errors.push({
        error: `invalid sort.by '${q.sort.by}' (valid: ${[...validNames].join(', ')})`,
        path:  'sort.by',
      });
    }
    if ((q.sort.by !== 'metric' && q.sort.by !== 'time') && (!q.group_by || q.group_by.length === 0)) {
      errors.push({ error: `sort.by '${q.sort.by}' requires group_by`, path: 'sort.by' });
    }
  }

  // duplicate dim names
  const seen = new Set<string>();
  for (const d of q.group_by ?? []) {
    const n = dimName(d);
    if (seen.has(n)) errors.push({ error: `duplicate group_by name '${n}'`, path: 'group_by' });
    seen.add(n);
  }

  if (errors.length) return { ok: false, errors };
  return { ok: true, query: q };
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
