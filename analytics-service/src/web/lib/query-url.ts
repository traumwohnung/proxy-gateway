import type { Dimension, Metric, UsageQuery } from '../../db/query.js';

const METRICS: Metric[] = ['connections', 'upload_bytes', 'download_bytes', 'total_bytes'];

// Default window: last 30 days, daily resolution.
export function defaultQuery(): UsageQuery {
  const now = Math.floor(Date.now() / 1000);
  return {
    time: { from: now - 30 * 86400, to: now, resolution: { unit: 'day', value: 1 } },
    metric: 'total_bytes',
  };
}

export function parseQuery(params: URLSearchParams): UsageQuery {
  const q: UsageQuery = defaultQuery();

  const from = Number(params.get('from'));
  if (Number.isFinite(from) && from > 0) q.time.from = from;
  const to = Number(params.get('to'));
  if (Number.isFinite(to) && to > 0) q.time.to = to;

  const ru = params.get('res_unit');
  const rv = Number(params.get('res_value'));
  if (ru === 'minute' || ru === 'hour' || ru === 'day') {
    q.time.resolution = { unit: ru, value: Number.isFinite(rv) && rv > 0 ? Math.floor(rv) : 1 };
  } else if (ru === 'none') {
    delete q.time.resolution;
  }

  const m = params.get('metric') as Metric | null;
  if (m && (METRICS as string[]).includes(m)) q.metric = m;

  const where: NonNullable<UsageQuery['where']> = {};
  const proxysetEq = params.get('proxyset_eq');
  if (proxysetEq) where.proxyset_eq = proxysetEq;
  const sdGte = Number(params.get('session_duration_gte'));
  if (Number.isFinite(sdGte) && params.has('session_duration_gte'))
    where.session_duration_gte = sdGte;
  const sdLte = Number(params.get('session_duration_lte'));
  if (Number.isFinite(sdLte) && params.has('session_duration_lte'))
    where.session_duration_lte = sdLte;

  const spEq = params.getAll('session_params_eq'); // each "key:value"
  if (spEq.length) {
    where.session_params_eq = spEq.map((s) => {
      const i = s.indexOf(':');
      return i < 0 ? { key: s, value: '' } : { key: s.slice(0, i), value: s.slice(i + 1) };
    });
  }
  const spHas = params.getAll('session_params_has_key');
  if (spHas.length) where.session_params_has_key = spHas;

  if (Object.keys(where).length) q.where = where;

  // "proxyset" | "provider" | "close_reason"
  // | "session_params:<key>" | "session_meta:<key>"
  // Legacy form "json:<key>" still parses as session_params.
  const groups = params.getAll('group');
  if (groups.length) {
    q.group_by = groups.map<Dimension>((g) => {
      if (g === 'proxyset') return { kind: 'proxyset' };
      if (g === 'provider') return { kind: 'provider' };
      if (g === 'close_reason') return { kind: 'close_reason' };
      if (g.startsWith('session_meta:'))
        return { kind: 'session_meta', key: g.slice('session_meta:'.length) };
      if (g.startsWith('session_params:'))
        return { kind: 'session_params', key: g.slice('session_params:'.length) };
      return { kind: 'session_params', key: g.replace(/^json:/, '') };
    });
  }

  const sortBy = params.get('sort_by');
  const sortDir = params.get('sort_dir');
  if (sortBy || sortDir) {
    q.sort = {
      by: sortBy ?? 'metric',
      dir: sortDir === 'asc' ? 'asc' : 'desc',
    };
  }

  const limit = Number(params.get('limit'));
  if (Number.isFinite(limit) && limit > 0) q.limit = Math.min(1000, Math.floor(limit));

  return q;
}

export function serializeQuery(q: UsageQuery): URLSearchParams {
  const p = new URLSearchParams();
  p.set('from', String(q.time.from));
  p.set('to', String(q.time.to));
  if (q.time.resolution) {
    p.set('res_unit', q.time.resolution.unit);
    p.set('res_value', String(q.time.resolution.value));
  } else {
    p.set('res_unit', 'none');
  }
  p.set('metric', q.metric);
  const w = q.where ?? {};
  if (w.proxyset_eq) p.set('proxyset_eq', w.proxyset_eq);
  if (w.session_duration_gte != null) p.set('session_duration_gte', String(w.session_duration_gte));
  if (w.session_duration_lte != null) p.set('session_duration_lte', String(w.session_duration_lte));
  for (const e of w.session_params_eq ?? []) p.append('session_params_eq', `${e.key}:${e.value}`);
  for (const k of w.session_params_has_key ?? []) p.append('session_params_has_key', k);
  for (const d of q.group_by ?? []) {
    if (d.kind === 'session_params' || d.kind === 'session_meta') {
      p.append('group', `${d.kind}:${d.key}`);
    } else {
      p.append('group', d.kind);
    }
  }
  if (q.sort) {
    p.set('sort_by', q.sort.by);
    p.set('sort_dir', q.sort.dir);
  }
  if (q.limit) p.set('limit', String(q.limit));
  return p;
}
