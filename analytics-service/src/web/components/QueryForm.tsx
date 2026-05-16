// biome-ignore-all lint/correctness/noChildrenProp: TanStack Form uses `children` as a render-prop API
// biome-ignore-all lint/suspicious/noArrayIndexKey: form rows are append-only; index is stable enough for this form
import { useForm } from '@tanstack/react-form';
import { format } from 'date-fns';
import { CalendarIcon, Plus, X } from 'lucide-react';
import { useEffect } from 'react';
import type { Dimension, Metric, UsageQuery } from '../../db/query';
import { useStore } from '../lib/store';
import { cn } from '../lib/utils';
import { Button } from './ui/button';
import { Calendar } from './ui/calendar';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Popover, PopoverContent, PopoverTrigger } from './ui/popover';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

type ResUnit = 'none' | 'minute' | 'hour' | 'day';

interface FormValues {
  from: Date;
  to: Date;
  res_unit: ResUnit;
  res_value: number;
  metric: Metric;
  where: {
    proxyset_eq: string;
    session_duration_gte: string;
    session_duration_lte: string;
    session_params_eq: { key: string; value: string }[];
    session_params_has_key: { key: string }[];
  };
  group_by: {
    kind: 'proxyset' | 'provider' | 'close_reason' | 'session_params' | 'session_meta';
    key: string;
  }[];
  sort_by: string;
  sort_dir: 'asc' | 'desc';
  limit: number;
}

const METRICS: Metric[] = ['connections', 'upload_bytes', 'download_bytes', 'total_bytes'];

function queryToValues(q: UsageQuery): FormValues {
  const w = q.where ?? {};
  return {
    from: new Date(q.time.from * 1000),
    to: new Date(q.time.to * 1000),
    res_unit: (q.time.resolution?.unit ?? 'none') as ResUnit,
    res_value: q.time.resolution?.value ?? 1,
    metric: q.metric,
    where: {
      proxyset_eq: w.proxyset_eq ?? '',
      session_duration_gte: w.session_duration_gte != null ? String(w.session_duration_gte) : '',
      session_duration_lte: w.session_duration_lte != null ? String(w.session_duration_lte) : '',
      session_params_eq: (w.session_params_eq ?? []).map((e) => ({
        key: e.key,
        value: String(e.value),
      })),
      session_params_has_key: (w.session_params_has_key ?? []).map((k) => ({ key: k })),
    },
    group_by: (q.group_by ?? []).map((d) =>
      d.kind === 'session_params'
        ? { kind: 'session_params' as const, key: d.key }
        : d.kind === 'session_meta'
          ? { kind: 'session_meta' as const, key: d.key }
          : { kind: d.kind, key: '' },
    ),
    sort_by: q.sort?.by ?? 'metric',
    sort_dir: q.sort?.dir ?? 'desc',
    limit: q.limit ?? 100,
  };
}

function valuesToQuery(v: FormValues): UsageQuery {
  const next: UsageQuery = {
    time: {
      from: Math.floor(v.from.getTime() / 1000),
      to: Math.floor(v.to.getTime() / 1000),
      ...(v.res_unit === 'none'
        ? {}
        : { resolution: { unit: v.res_unit, value: Math.max(1, Number(v.res_value) || 1) } }),
    },
    metric: v.metric,
  };

  const where: NonNullable<UsageQuery['where']> = {};
  if (v.where.proxyset_eq.trim()) where.proxyset_eq = v.where.proxyset_eq.trim();
  if (v.where.session_duration_gte !== '')
    where.session_duration_gte = Number(v.where.session_duration_gte);
  if (v.where.session_duration_lte !== '')
    where.session_duration_lte = Number(v.where.session_duration_lte);
  const eqs = v.where.session_params_eq.filter((e) => e.key.trim());
  if (eqs.length) where.session_params_eq = eqs.map((e) => ({ key: e.key.trim(), value: e.value }));
  const hasKeys = v.where.session_params_has_key.map((k) => k.key.trim()).filter(Boolean);
  if (hasKeys.length) where.session_params_has_key = hasKeys;
  if (Object.keys(where).length) next.where = where;

  const groups: Dimension[] = v.group_by
    .filter((g) => (g.kind !== 'session_params' && g.kind !== 'session_meta') || g.key.trim())
    .map((g) =>
      g.kind === 'session_params'
        ? { kind: 'session_params', key: g.key.trim() }
        : g.kind === 'session_meta'
          ? { kind: 'session_meta', key: g.key.trim() }
          : { kind: g.kind },
    );
  if (groups.length) next.group_by = groups;

  if (v.sort_by) next.sort = { by: v.sort_by, dir: v.sort_dir };
  if (v.limit) next.limit = Math.min(1000, Math.max(1, Number(v.limit) || 100));
  return next;
}

interface Props {
  query: UsageQuery;
  onSubmit: (q: UsageQuery) => void;
  isLoading: boolean;
}

function DraftSync({ values, onSync }: { values: FormValues; onSync: (q: UsageQuery) => void }) {
  useEffect(() => {
    onSync(valuesToQuery(values));
  }, [values, onSync]);
  return null;
}

export default function QueryForm({ query, onSubmit, isLoading }: Props) {
  const setDraftQuery = useStore((s) => s.setDraftQuery);

  const form = useForm({
    defaultValues: queryToValues(query),
    onSubmit: ({ value }) => onSubmit(valuesToQuery(value)),
  });

  useEffect(() => {
    form.reset(queryToValues(query));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, form.reset]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        e.stopPropagation();
        void form.handleSubmit();
      }}
      className="space-y-6"
    >
      {/* Live-publish draft to zustand so the JSON panel updates on every keystroke. */}
      <form.Subscribe
        selector={(s) => s.values}
        children={(values) => <DraftSync values={values} onSync={setDraftQuery} />}
      />

      {/* ── Time range ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <form.Field
          name="from"
          children={(f) => (
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground font-medium">From</Label>
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    className={cn(
                      'w-full justify-start text-left font-normal',
                      !f.state.value && 'text-muted-foreground',
                    )}
                  >
                    <CalendarIcon className="mr-2 h-4 w-4 text-muted-foreground" />
                    {f.state.value ? format(f.state.value, 'MMM d, yyyy') : 'Select date'}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="start">
                  <Calendar
                    mode="single"
                    selected={f.state.value}
                    onSelect={(d) => d && f.handleChange(d)}
                  />
                </PopoverContent>
              </Popover>
            </div>
          )}
        />

        <form.Field
          name="to"
          children={(f) => (
            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground font-medium">To</Label>
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    className={cn(
                      'w-full justify-start text-left font-normal',
                      !f.state.value && 'text-muted-foreground',
                    )}
                  >
                    <CalendarIcon className="mr-2 h-4 w-4 text-muted-foreground" />
                    {f.state.value ? format(f.state.value, 'MMM d, yyyy') : 'Select date'}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="start">
                  <Calendar
                    mode="single"
                    selected={f.state.value}
                    onSelect={(d) => d && f.handleChange(d)}
                  />
                </PopoverContent>
              </Popover>
            </div>
          )}
        />

        <div className="space-y-2">
          <Label className="text-xs text-muted-foreground font-medium">Resolution</Label>
          <div className="flex gap-2">
            <form.Field
              name="res_value"
              children={(f) => (
                <Input
                  type="number"
                  className="w-20"
                  min={1}
                  value={f.state.value}
                  onChange={(e) => f.handleChange(Number(e.target.value) || 1)}
                />
              )}
            />
            <form.Field
              name="res_unit"
              children={(f) => (
                <Select value={f.state.value} onValueChange={(v) => f.handleChange(v as ResUnit)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None</SelectItem>
                    <SelectItem value="minute">Minute</SelectItem>
                    <SelectItem value="hour">Hour</SelectItem>
                    <SelectItem value="day">Day</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
          </div>
        </div>
      </div>

      {/* ── Metric + Proxyset ── */}
      <div className="flex gap-4">
        <div className="space-y-2 flex-1">
          <Label className="text-xs text-muted-foreground font-medium">Metric</Label>
          <form.Field
            name="metric"
            children={(f) => (
              <Select value={f.state.value} onValueChange={(v) => f.handleChange(v as Metric)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {METRICS.map((m) => (
                    <SelectItem key={m} value={m}>
                      {m.replace(/_/g, ' ')}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          />
        </div>
        <form.Field
          name="where.proxyset_eq"
          children={(f) => (
            <div className="space-y-2 flex-1">
              <Label className="text-xs text-muted-foreground font-medium">Proxyset</Label>
              <Input
                value={f.state.value}
                onChange={(e) => f.handleChange(e.target.value)}
                placeholder="(any)"
              />
            </div>
          )}
        />
      </div>

      {/* ── Session Duration range ── */}
      <div className="flex gap-4">
        <form.Field
          name="where.session_duration_gte"
          children={(f) => (
            <div className="space-y-2 flex-1">
              <Label className="text-xs text-muted-foreground font-medium">
                Session Duration ≥ (min)
              </Label>
              <Input
                type="number"
                min={0}
                value={f.state.value}
                onChange={(e) => f.handleChange(e.target.value)}
                placeholder="0"
              />
            </div>
          )}
        />
        <form.Field
          name="where.session_duration_lte"
          children={(f) => (
            <div className="space-y-2 flex-1">
              <Label className="text-xs text-muted-foreground font-medium">
                Session Duration ≤ (min)
              </Label>
              <Input
                type="number"
                min={0}
                value={f.state.value}
                onChange={(e) => f.handleChange(e.target.value)}
                placeholder="∞"
              />
            </div>
          )}
        />
      </div>

      {/* ── Group By ── */}
      <form.Field
        name="group_by"
        mode="array"
        children={(f) => (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-xs text-muted-foreground font-medium">Group By</Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => f.pushValue({ kind: 'proxyset', key: '' })}
                className="h-7 text-xs text-primary hover:text-primary/80 hover:bg-primary/10"
              >
                <Plus className="h-3 w-3 mr-1" /> Add
              </Button>
            </div>
            {f.state.value.length === 0 ? (
              <p className="text-sm text-muted-foreground">No grouping configured</p>
            ) : (
              <div className="space-y-2">
                {f.state.value.map((_, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <form.Field
                      name={`group_by[${i}].kind`}
                      children={(sub) => (
                        <Select
                          value={sub.state.value}
                          onValueChange={(v) =>
                            sub.handleChange(v as FormValues['group_by'][number]['kind'])
                          }
                        >
                          <SelectTrigger className="w-36">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="proxyset">Proxyset</SelectItem>
                            <SelectItem value="provider">Provider</SelectItem>
                            <SelectItem value="close_reason">Close reason</SelectItem>
                            <SelectItem value="session_params">Session params key</SelectItem>
                            <SelectItem value="session_meta">Session meta key</SelectItem>
                          </SelectContent>
                        </Select>
                      )}
                    />
                    <form.Field
                      name={`group_by[${i}].kind`}
                      children={(sub) =>
                        sub.state.value === 'session_params' ||
                        sub.state.value === 'session_meta' ? (
                          <form.Field
                            name={`group_by[${i}].key`}
                            children={(kf) => (
                              <Input
                                className="flex-1"
                                placeholder="e.g. user"
                                value={kf.state.value}
                                onChange={(e) => kf.handleChange(e.target.value)}
                              />
                            )}
                          />
                        ) : (
                          <div className="flex-1" />
                        )
                      }
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => f.removeValue(i)}
                      className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      />

      {/* ── Session Params Equals ── */}
      <form.Field
        name="where.session_params_eq"
        mode="array"
        children={(f) => (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-xs text-muted-foreground font-medium">
                Session Params Equals
              </Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => f.pushValue({ key: '', value: '' })}
                className="h-7 text-xs text-primary hover:text-primary/80 hover:bg-primary/10"
              >
                <Plus className="h-3 w-3 mr-1" /> Add
              </Button>
            </div>
            {f.state.value.length === 0 ? (
              <p className="text-sm text-muted-foreground">No params filter configured</p>
            ) : (
              <div className="space-y-2">
                {f.state.value.map((_, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <form.Field
                      name={`where.session_params_eq[${i}].key`}
                      children={(sub) => (
                        <Input
                          className="flex-1"
                          placeholder="key"
                          value={sub.state.value}
                          onChange={(e) => sub.handleChange(e.target.value)}
                        />
                      )}
                    />
                    <span className="text-muted-foreground">=</span>
                    <form.Field
                      name={`where.session_params_eq[${i}].value`}
                      children={(sub) => (
                        <Input
                          className="flex-1"
                          placeholder="value"
                          value={sub.state.value}
                          onChange={(e) => sub.handleChange(e.target.value)}
                        />
                      )}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => f.removeValue(i)}
                      className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      />

      {/* ── Session Params Has Key ── */}
      <form.Field
        name="where.session_params_has_key"
        mode="array"
        children={(f) => (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-xs text-muted-foreground font-medium">
                Session Params Has Key
              </Label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => f.pushValue({ key: '' })}
                className="h-7 text-xs text-primary hover:text-primary/80 hover:bg-primary/10"
              >
                <Plus className="h-3 w-3 mr-1" /> Add
              </Button>
            </div>
            {f.state.value.length === 0 ? (
              <p className="text-sm text-muted-foreground">No key filter configured</p>
            ) : (
              <div className="space-y-2">
                {f.state.value.map((_, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <form.Field
                      name={`where.session_params_has_key[${i}].key`}
                      children={(sub) => (
                        <Input
                          className="flex-1"
                          placeholder="e.g. user"
                          value={sub.state.value}
                          onChange={(e) => sub.handleChange(e.target.value)}
                        />
                      )}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => f.removeValue(i)}
                      className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      />

      {/* ── Sort & Limit ── */}
      <form.Subscribe
        selector={(s) => s.values.group_by}
        children={(groups) => {
          const opts = new Set<string>(['metric', 'time']);
          for (const g of groups) {
            const name = g.kind === 'proxyset' ? 'proxyset' : g.key.trim();
            if (name) opts.add(name);
          }
          const sortOptions = [...opts];
          return (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <form.Field
                name="sort_by"
                children={(f) => (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground font-medium">Sort By</Label>
                    <Select
                      value={sortOptions.includes(f.state.value) ? f.state.value : 'metric'}
                      onValueChange={(v) => f.handleChange(v)}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {sortOptions.map((o) => (
                          <SelectItem key={o} value={o}>
                            {o}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}
              />
              <form.Field
                name="sort_dir"
                children={(f) => (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground font-medium">Direction</Label>
                    <Select
                      value={f.state.value}
                      onValueChange={(v) => f.handleChange(v as 'asc' | 'desc')}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="desc">Descending</SelectItem>
                        <SelectItem value="asc">Ascending</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
              />
              <form.Field
                name="limit"
                children={(f) => (
                  <div className="space-y-2">
                    <Label className="text-xs text-muted-foreground font-medium">Limit</Label>
                    <Input
                      type="number"
                      min={1}
                      max={1000}
                      value={f.state.value}
                      onChange={(e) => f.handleChange(Number(e.target.value) || 100)}
                    />
                  </div>
                )}
              />
            </div>
          );
        }}
      />

      {/* ── Run ── */}
      <div className="pt-2">
        <Button type="submit" disabled={isLoading}>
          {isLoading ? 'Running…' : 'Run Query'}
        </Button>
      </div>
    </form>
  );
}
