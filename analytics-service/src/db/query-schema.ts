import { z } from 'zod';

// ---------------------------------------------------------------------------
// Schema (browser-safe — no DB imports)
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

// Built-in column dimensions plus a JSON-extraction dimension that reaches
// into session_params_dim.params_json via the canonical hash join.
const Dimension = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('proxyset'),     as: z.string().optional() }),
  z.object({ kind: z.literal('provider'),     as: z.string().optional() }),
  z.object({ kind: z.literal('close_reason'), as: z.string().optional() }),
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

  provider_eq:              z.string().optional(),
  provider_ne:              z.string().optional(),
  provider_in:              z.array(z.string()).min(1).optional(),
  provider_not_in:          z.array(z.string()).min(1).optional(),

  close_reason_eq:          z.string().optional(),
  close_reason_in:          z.array(z.string()).min(1).optional(),

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

export type UsageQuery = z.infer<typeof UsageQuery>;
export type Dimension  = z.infer<typeof Dimension>;
export type Metric     = z.infer<typeof Metric>;
export type Where      = z.infer<typeof Where>;

export interface QueryError { error: string; path?: string }

const UNIT_SECONDS: Record<'minute'|'hour'|'day', number> = { minute: 60, hour: 3600, day: 86400 };
const MAX_BUCKETS = 10_000;

export function dimName(d: Dimension): string {
  if (d.as) return d.as;
  switch (d.kind) {
    case 'proxyset':     return 'proxyset';
    case 'provider':     return 'provider';
    case 'close_reason': return 'close_reason';
    case 'json':         return d.key;
  }
}

// dimRequiresDim returns true when this dimension/filter needs the dim-table
// JOIN to be present in the rendered SQL.
export function dimRequiresDim(d: Dimension): boolean {
  return d.kind === 'json';
}

export function whereRequiresDim(w?: Where): boolean {
  if (!w) return false;
  return Boolean(
    w.session_params_eq ||
      w.session_params_ne ||
      w.session_params_in ||
      w.session_params_not_in ||
      w.session_params_has_key,
  );
}

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

  if (q.time.resolution) {
    const w = UNIT_SECONDS[q.time.resolution.unit] * q.time.resolution.value;
    const buckets = Math.ceil((q.time.to - q.time.from) / w);
    if (buckets > MAX_BUCKETS) {
      errors.push({ error: `resolution too fine: would produce ${buckets} buckets (max ${MAX_BUCKETS})`, path: 'time.resolution' });
    }
  }

  if (q.sort) {
    const validNames = new Set<string>(['metric', 'time']);
    for (const d of q.group_by ?? []) validNames.add(dimName(d));
    if (!validNames.has(q.sort.by)) {
      errors.push({ error: `invalid sort.by '${q.sort.by}' (valid: ${[...validNames].join(', ')})`, path: 'sort.by' });
    }
    if ((q.sort.by !== 'metric' && q.sort.by !== 'time') && (!q.group_by || q.group_by.length === 0)) {
      errors.push({ error: `sort.by '${q.sort.by}' requires group_by`, path: 'sort.by' });
    }
  }

  const seen = new Set<string>();
  for (const d of q.group_by ?? []) {
    const n = dimName(d);
    if (seen.has(n)) errors.push({ error: `duplicate group_by name '${n}'`, path: 'group_by' });
    seen.add(n);
  }

  if (errors.length) return { ok: false, errors };
  return { ok: true, query: q };
}
