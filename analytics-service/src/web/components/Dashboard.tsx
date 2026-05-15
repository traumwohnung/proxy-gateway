import { useEffect, useMemo } from 'react';
import { useStore } from '../lib/store';
import { formatBytes } from '../lib/utils';
import QueryForm from './QueryForm';
import type { UsageQuery, Metric } from '../../db/query';

const TILE_COLORS = ['#161b22', '#0e4429', '#006d32', '#26a641', '#39d353'];

function fmtMetric(metric: Metric, n: number): string {
  return metric === 'connections' ? String(n) : formatBytes(n);
}

function fmtTs(ts: number, resolution: UsageQuery['time']['resolution']): string {
  const d = new Date(ts * 1000);
  if (!resolution) return d.toISOString();
  if (resolution.unit === 'day')  return d.toISOString().slice(0, 10);
  if (resolution.unit === 'hour') return d.toISOString().slice(0, 13) + ':00';
  return d.toISOString().slice(0, 16);
}

function seriesLabel(group: Record<string, unknown>): string {
  const entries = Object.entries(group);
  if (entries.length === 0) return 'all';
  return entries.map(([k, v]) => `${k}=${v ?? '∅'}`).join(' · ');
}

export default function Dashboard() {
  const { query, result, loading, error, setQuery, run } = useStore();

  useEffect(() => { void run(); }, [run]);

  function onSubmit(next: UsageQuery): void {
    setQuery(next);
    void run();
  }

  const { buckets, maxVal } = useMemo(() => {
    const set = new Set<number>();
    let m = 0;
    for (const s of result?.series ?? []) for (const [t, v] of s.points) { set.add(t); if (v > m) m = v; }
    return { buckets: [...set].sort((a, b) => a - b), maxVal: m };
  }, [result]);

  function intensity(v: number): number {
    if (v <= 0 || maxVal <= 0) return 0;
    const r = v / maxVal;
    if (r > 0.75) return 4;
    if (r > 0.50) return 3;
    if (r > 0.25) return 2;
    return 1;
  }

  return (
    <div>
      <QueryForm query={query} onSubmit={onSubmit} loading={loading} />

      {error && (
        <div className="mb-6 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm">
          <div className="font-medium">Query failed</div>
          <pre className="whitespace-pre-wrap text-xs mt-1">{error}</pre>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-8">
        <Stat label="Metric" value={query.metric} mono />
        <Stat label="Total"   value={result ? fmtMetric(query.metric, result.total) : '—'} />
        <Stat label="Series"  value={result ? String(result.meta.series_count) : '—'} />
        <Stat label="Buckets" value={result ? String(result.meta.buckets) : '—'} />
      </div>

      <div className="rounded-md border border-border bg-card p-4 overflow-x-auto">
        {!result && !loading && <div className="text-center text-sm text-muted-foreground py-8">No data yet.</div>}
        {loading && <div className="text-center text-sm text-muted-foreground py-8">Loading…</div>}
        {result && result.series.length === 0 && (
          <div className="text-center text-sm text-muted-foreground py-8">No data for this query.</div>
        )}
        {result && result.series.length > 0 && (
          <table className="text-xs border-separate" style={{ borderSpacing: '2px' }}>
            <thead>
              <tr>
                <th className="sticky left-0 z-10 bg-card text-left pr-3 font-medium text-muted-foreground"> </th>
                {buckets.map((b) => (
                  <th key={b} title={fmtTs(b, query.time.resolution)}
                      className="text-muted-foreground font-normal align-bottom whitespace-nowrap"
                      style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', height: 64 }}>
                    {fmtTs(b, query.time.resolution)}
                  </th>
                ))}
                <th className="text-left pl-3 font-medium text-muted-foreground">total</th>
              </tr>
            </thead>
            <tbody>
              {result.series.map((s) => {
                const byBucket = new Map(s.points);
                return (
                  <tr key={JSON.stringify(s.group)}>
                    <td className="sticky left-0 z-10 bg-card pr-3 font-mono whitespace-nowrap">{seriesLabel(s.group)}</td>
                    {buckets.map((b) => {
                      const v = byBucket.get(b) ?? 0;
                      const i = intensity(v);
                      return (
                        <td key={b}
                            title={`${fmtTs(b, query.time.resolution)} — ${fmtMetric(query.metric, v)}`}
                            style={{ backgroundColor: TILE_COLORS[i], width: 14, height: 14 }}
                            className="rounded-sm"></td>
                      );
                    })}
                    <td className="pl-3 font-mono whitespace-nowrap">{fmtMetric(query.metric, s.total)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <div className="flex items-center gap-2 mt-4 text-xs text-muted-foreground">
          <span>less</span>
          {TILE_COLORS.map((c, i) => (
            <span key={i} className="inline-block rounded-sm"
                  style={{ backgroundColor: c, width: 12, height: 12 }}></span>
          ))}
          <span>more</span>
          {result && <span className="ml-4">max: {fmtMetric(query.metric, maxVal)}</span>}
        </div>
      </div>

      <details className="mt-6">
        <summary className="cursor-pointer text-xs text-muted-foreground">Show executed query JSON</summary>
        <pre className="mt-2 text-xs rounded-md border border-border bg-card p-3 overflow-x-auto">
{JSON.stringify(query, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border border-border bg-card p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={`text-lg ${mono ? 'font-mono' : 'font-semibold'}`}>{value}</div>
    </div>
  );
}
