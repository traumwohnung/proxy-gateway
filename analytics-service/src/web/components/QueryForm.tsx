import { useForm } from '@tanstack/react-form';
import { useEffect } from 'react';
import type { UsageQuery, Metric, Dimension } from '../../db/query';

type ResUnit = 'none' | 'minute' | 'hour' | 'day';

interface FormValues {
  from:      string;   // ISO local datetime
  to:        string;
  res_unit:  ResUnit;
  res_value: number;
  metric:    Metric;
  where: {
    proxyset_eq:           string;
    session_duration_gte:  string;
    session_duration_lte:  string;
    session_params_eq:     { key: string; value: string }[];
    session_params_has_key:{ key: string }[];
  };
  group_by:  { kind: 'proxyset' | 'json'; key: string }[];
  sort_by:   string;
  sort_dir:  'asc' | 'desc';
  limit:     number;
}

const METRICS: Metric[] = ['connections', 'upload_bytes', 'download_bytes', 'total_bytes'];

const inputCls = 'rounded border border-border bg-background px-2 py-1 text-xs';
const btnCls   = 'rounded border border-border bg-background hover:bg-muted px-2 py-1 text-xs';

function pad(n: number): string { return String(n).padStart(2, '0'); }
function tsToLocal(ts: number): string {
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function localToTs(s: string): number { return Math.floor(new Date(s).getTime() / 1000); }

function queryToValues(q: UsageQuery): FormValues {
  const w = q.where ?? {};
  return {
    from:      tsToLocal(q.time.from),
    to:        tsToLocal(q.time.to),
    res_unit:  (q.time.resolution?.unit ?? 'none') as ResUnit,
    res_value: q.time.resolution?.value ?? 1,
    metric:    q.metric,
    where: {
      proxyset_eq:            w.proxyset_eq ?? '',
      session_duration_gte:   w.session_duration_gte != null ? String(w.session_duration_gte) : '',
      session_duration_lte:   w.session_duration_lte != null ? String(w.session_duration_lte) : '',
      session_params_eq:      (w.session_params_eq ?? []).map((e) => ({ key: e.key, value: String(e.value) })),
      session_params_has_key: (w.session_params_has_key ?? []).map((k) => ({ key: k })),
    },
    group_by:  (q.group_by ?? []).map((d) => d.kind === 'proxyset' ? { kind: 'proxyset' as const, key: '' } : { kind: 'json' as const, key: d.key }),
    sort_by:   q.sort?.by  ?? 'metric',
    sort_dir:  q.sort?.dir ?? 'desc',
    limit:     q.limit ?? 100,
  };
}

function valuesToQuery(v: FormValues): UsageQuery {
  const next: UsageQuery = {
    time: {
      from: localToTs(v.from),
      to:   localToTs(v.to),
      ...(v.res_unit === 'none'
        ? {}
        : { resolution: { unit: v.res_unit, value: Math.max(1, Number(v.res_value) || 1) } }),
    },
    metric: v.metric,
  };

  const where: NonNullable<UsageQuery['where']> = {};
  if (v.where.proxyset_eq.trim()) where.proxyset_eq = v.where.proxyset_eq.trim();
  if (v.where.session_duration_gte !== '') where.session_duration_gte = Number(v.where.session_duration_gte);
  if (v.where.session_duration_lte !== '') where.session_duration_lte = Number(v.where.session_duration_lte);
  const eqs = v.where.session_params_eq.filter((e) => e.key.trim());
  if (eqs.length) where.session_params_eq = eqs.map((e) => ({ key: e.key.trim(), value: e.value }));
  const hasKeys = v.where.session_params_has_key.map((k) => k.key.trim()).filter(Boolean);
  if (hasKeys.length) where.session_params_has_key = hasKeys;
  if (Object.keys(where).length) next.where = where;

  const groups: Dimension[] = v.group_by
    .filter((g) => g.kind === 'proxyset' || g.key.trim())
    .map((g) => g.kind === 'proxyset' ? { kind: 'proxyset' } : { kind: 'json', key: g.key.trim() });
  if (groups.length) next.group_by = groups;

  if (v.sort_by) next.sort = { by: v.sort_by, dir: v.sort_dir };
  if (v.limit)   next.limit = Math.min(1000, Math.max(1, Number(v.limit) || 100));

  return next;
}

interface Props {
  query:    UsageQuery;
  onSubmit: (q: UsageQuery) => void;
  loading:  boolean;
}

export default function QueryForm({ query, onSubmit, loading }: Props) {
  const form = useForm({
    defaultValues: queryToValues(query),
    onSubmit: ({ value }) => onSubmit(valuesToQuery(value)),
  });

  // Re-seed when the query comes from outside.
  useEffect(() => { form.reset(queryToValues(query)); /* eslint-disable-next-line */ }, [query]);

  // Build sort_by options from current group_by names.
  function sortByOptionsFrom(groups: FormValues['group_by']): string[] {
    const opts = new Set<string>(['metric', 'time']);
    for (const g of groups) {
      const name = g.kind === 'proxyset' ? 'proxyset' : g.key.trim();
      if (name) opts.add(name);
    }
    return [...opts];
  }

  return (
    <form
      onSubmit={(e) => { e.preventDefault(); e.stopPropagation(); void form.handleSubmit(); }}
      className="rounded-md border border-border bg-card p-4 grid gap-4 text-xs mb-6"
    >
      {/* ───── row 1: time + metric ───── */}
      <div className="grid gap-3 grid-cols-2 md:grid-cols-5">
        <form.Field name="from" children={(f) => (
          <Field label="From">
            <input type="datetime-local" className={inputCls}
                   value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
          </Field>
        )} />
        <form.Field name="to" children={(f) => (
          <Field label="To">
            <input type="datetime-local" className={inputCls}
                   value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
          </Field>
        )} />
        <form.Field name="res_unit" children={(f) => (
          <Field label="Resolution unit">
            <select className={inputCls} value={f.state.value}
                    onChange={(e) => f.handleChange(e.target.value as ResUnit)}>
              <option value="none">none</option>
              <option value="minute">minute</option>
              <option value="hour">hour</option>
              <option value="day">day</option>
            </select>
          </Field>
        )} />
        <form.Field name="res_value" children={(f) => (
          <Field label="Resolution value">
            <input type="number" min={1} className={inputCls}
                   value={f.state.value} onChange={(e) => f.handleChange(Number(e.target.value))} />
          </Field>
        )} />
        <form.Field name="metric" children={(f) => (
          <Field label="Metric">
            <select className={inputCls} value={f.state.value}
                    onChange={(e) => f.handleChange(e.target.value as Metric)}>
              {METRICS.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </Field>
        )} />
      </div>

      {/* ───── row 2: simple filters ───── */}
      <div className="grid gap-3 grid-cols-2 md:grid-cols-3">
        <form.Field name="where.proxyset_eq" children={(f) => (
          <Field label="Proxyset =">
            <input className={inputCls} placeholder="(any)"
                   value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
          </Field>
        )} />
        <form.Field name="where.session_duration_gte" children={(f) => (
          <Field label="Session duration ≥ (min)">
            <input type="number" min={0} className={inputCls}
                   value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
          </Field>
        )} />
        <form.Field name="where.session_duration_lte" children={(f) => (
          <Field label="Session duration ≤ (min)">
            <input type="number" min={0} className={inputCls}
                   value={f.state.value} onChange={(e) => f.handleChange(e.target.value)} />
          </Field>
        )} />
      </div>

      {/* ───── group_by (array of rows) ───── */}
      <form.Field name="group_by" mode="array" children={(f) => (
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-muted-foreground">Group by</span>
            <button type="button" className={btnCls}
                    onClick={() => f.pushValue({ kind: 'proxyset', key: '' })}>+ add</button>
          </div>
          <div className="grid gap-2">
            {f.state.value.length === 0 && <div className="text-muted-foreground italic">(none — single series)</div>}
            {f.state.value.map((_, i) => (
              <div key={i} className="grid grid-cols-[10rem_1fr_auto] gap-2 items-center">
                <form.Field name={`group_by[${i}].kind`} children={(sub) => (
                  <select className={inputCls} value={sub.state.value as 'proxyset'|'json'}
                          onChange={(e) => sub.handleChange(e.target.value as 'proxyset'|'json')}>
                    <option value="proxyset">proxyset</option>
                    <option value="json">json key</option>
                  </select>
                )} />
                <form.Field name={`group_by[${i}].kind`} children={(sub) => (
                  sub.state.value === 'json'
                    ? (
                      <form.Field name={`group_by[${i}].key`} children={(kf) => (
                        <input className={inputCls} placeholder="json key (e.g. user)"
                               value={kf.state.value} onChange={(e) => kf.handleChange(e.target.value)} />
                      )} />
                    )
                    : <div className="text-muted-foreground">—</div>
                )} />
                <button type="button" className={btnCls} onClick={() => f.removeValue(i)}>×</button>
              </div>
            ))}
          </div>
        </div>
      )} />

      {/* ───── session_params_eq (array) ───── */}
      <form.Field name="where.session_params_eq" mode="array" children={(f) => (
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-muted-foreground">session_params equals</span>
            <button type="button" className={btnCls}
                    onClick={() => f.pushValue({ key: '', value: '' })}>+ add</button>
          </div>
          <div className="grid gap-2">
            {f.state.value.length === 0 && <div className="text-muted-foreground italic">(no filters)</div>}
            {f.state.value.map((_, i) => (
              <div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-center">
                <form.Field name={`where.session_params_eq[${i}].key`} children={(sub) => (
                  <input className={inputCls} placeholder="key"
                         value={sub.state.value} onChange={(e) => sub.handleChange(e.target.value)} />
                )} />
                <form.Field name={`where.session_params_eq[${i}].value`} children={(sub) => (
                  <input className={inputCls} placeholder="value"
                         value={sub.state.value} onChange={(e) => sub.handleChange(e.target.value)} />
                )} />
                <button type="button" className={btnCls} onClick={() => f.removeValue(i)}>×</button>
              </div>
            ))}
          </div>
        </div>
      )} />

      {/* ───── session_params_has_key (array) ───── */}
      <form.Field name="where.session_params_has_key" mode="array" children={(f) => (
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-muted-foreground">session_params has key</span>
            <button type="button" className={btnCls}
                    onClick={() => f.pushValue({ key: '' })}>+ add</button>
          </div>
          <div className="grid gap-2">
            {f.state.value.length === 0 && <div className="text-muted-foreground italic">(no filters)</div>}
            {f.state.value.map((_, i) => (
              <div key={i} className="grid grid-cols-[1fr_auto] gap-2 items-center">
                <form.Field name={`where.session_params_has_key[${i}].key`} children={(sub) => (
                  <input className={inputCls} placeholder="key (e.g. user)"
                         value={sub.state.value} onChange={(e) => sub.handleChange(e.target.value)} />
                )} />
                <button type="button" className={btnCls} onClick={() => f.removeValue(i)}>×</button>
              </div>
            ))}
          </div>
        </div>
      )} />

      {/* ───── sort + limit ───── */}
      <div className="grid gap-3 grid-cols-3">
        <form.Subscribe selector={(s) => s.values.group_by} children={(groups) => {
          const opts = sortByOptionsFrom(groups);
          return (
            <form.Field name="sort_by" children={(f) => (
              <Field label="Sort by">
                <select className={inputCls}
                        value={opts.includes(f.state.value) ? f.state.value : 'metric'}
                        onChange={(e) => f.handleChange(e.target.value)}>
                  {opts.map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              </Field>
            )} />
          );
        }} />
        <form.Field name="sort_dir" children={(f) => (
          <Field label="Sort dir">
            <select className={inputCls} value={f.state.value}
                    onChange={(e) => f.handleChange(e.target.value as 'asc'|'desc')}>
              <option value="desc">desc</option>
              <option value="asc">asc</option>
            </select>
          </Field>
        )} />
        <form.Field name="limit" children={(f) => (
          <Field label="Limit">
            <input type="number" min={1} max={1000} className={inputCls}
                   value={f.state.value} onChange={(e) => f.handleChange(Number(e.target.value))} />
          </Field>
        )} />
      </div>

      <div>
        <button type="submit" disabled={loading}
                className="rounded bg-primary text-primary-foreground px-3 py-1.5 disabled:opacity-50">
          {loading ? 'Running…' : 'Run query'}
        </button>
      </div>
    </form>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="flex flex-col gap-1 text-muted-foreground">{label}{children}</label>;
}
