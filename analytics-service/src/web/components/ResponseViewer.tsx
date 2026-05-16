import { format } from 'date-fns';
import { Clock, Database, Layers, TrendingUp } from 'lucide-react';
import { useMemo } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { Metric, UsageQuery } from '../../db/query';
import type { UsageQueryResult } from '../lib/store';
import { formatBytes } from '../lib/utils';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';

interface Props {
  result: UsageQueryResult | null;
  query: UsageQuery;
  isLoading: boolean;
}

function fmtMetric(metric: Metric, n: number): string {
  return metric === 'connections' ? n.toLocaleString() : formatBytes(n);
}
function labelFor(m: Metric): string {
  return m.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}
function fmtTs(ts: number, resolution: UsageQuery['time']['resolution']): string {
  const d = new Date(ts * 1000);
  if (!resolution) return format(d, 'MMM d, yyyy');
  if (resolution.unit === 'day') return format(d, 'MMM d');
  if (resolution.unit === 'hour') return format(d, 'MMM d HH:00');
  return format(d, 'MMM d HH:mm');
}
function seriesLabel(group: Record<string, unknown>): string {
  const entries = Object.entries(group);
  if (entries.length === 0) return 'all';
  return entries.map(([k, v]) => `${k}=${v ?? '∅'}`).join(' · ');
}

export default function ResponseViewer({ result, query, isLoading }: Props) {
  const buckets = useMemo(() => {
    if (!result) return [] as number[];
    const set = new Set<number>();
    for (const s of result.series) for (const [t] of s.points) set.add(t);
    return [...set].sort((a, b) => a - b);
  }, [result]);

  // Aggregate across series for the chart (single line). Per-series bucketing
  // still drives the heatmap.
  const aggregatedChart = useMemo(() => {
    if (!result) return [] as { ts: number; label: string; value: number }[];
    const totals = new Map<number, number>();
    for (const s of result.series)
      for (const [t, v] of s.points) totals.set(t, (totals.get(t) ?? 0) + v);
    return buckets.map((b) => ({
      ts: b,
      label: fmtTs(b, query.time.resolution),
      value: totals.get(b) ?? 0,
    }));
  }, [result, query.time.resolution, buckets]);

  const maxVal = useMemo(
    () => Math.max(0, ...aggregatedChart.map((d) => d.value)),
    [aggregatedChart],
  );

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {(['a', 'b', 'c', 'd'] as const).map((k) => (
            <Card key={k}>
              <CardContent className="pt-6">
                <div className="h-4 w-20 bg-muted animate-pulse rounded mb-2" />
                <div className="h-8 w-28 bg-muted animate-pulse rounded" />
              </CardContent>
            </Card>
          ))}
        </div>
        <Card>
          <CardContent className="pt-6">
            <div className="h-64 bg-muted animate-pulse rounded" />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <div className="text-center">
          <Database className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No data yet</p>
          <p className="text-sm">Run a query to see results</p>
        </div>
      </div>
    );
  }

  const accentVar = 'hsl(var(--primary))';

  return (
    <div className="space-y-6">
      {/* Metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="hover:border-primary/30 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <TrendingUp className="h-4 w-4" /> <span>Metric</span>
            </div>
            <p className="text-xl font-semibold font-mono">{labelFor(query.metric)}</p>
          </CardContent>
        </Card>
        <Card className="hover:border-primary/30 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Database className="h-4 w-4" /> <span>Total</span>
            </div>
            <p className="text-xl font-semibold text-primary font-mono">
              {fmtMetric(query.metric, result.total)}
            </p>
          </CardContent>
        </Card>
        <Card className="hover:border-primary/30 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Layers className="h-4 w-4" /> <span>Series</span>
            </div>
            <p className="text-xl font-semibold font-mono">{result.meta.series_count}</p>
          </CardContent>
        </Card>
        <Card className="hover:border-primary/30 transition-colors">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-sm text-muted-foreground mb-1">
              <Clock className="h-4 w-4" /> <span>Buckets</span>
            </div>
            <p className="text-xl font-semibold font-mono">{result.meta.buckets}</p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base font-medium">Time Series</CardTitle>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="area" className="w-full">
            <TabsList className="mb-4">
              <TabsTrigger value="area">Area Chart</TabsTrigger>
              <TabsTrigger value="bar">Bar Chart</TabsTrigger>
              <TabsTrigger value="heatmap">Heatmap</TabsTrigger>
            </TabsList>

            <TabsContent value="area">
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={aggregatedChart}
                    margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={accentVar} stopOpacity={0.3} />
                        <stop offset="95%" stopColor={accentVar} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis
                      dataKey="label"
                      stroke="hsl(var(--muted-foreground))"
                      fontSize={12}
                      tickLine={false}
                    />
                    <YAxis
                      stroke="hsl(var(--muted-foreground))"
                      fontSize={12}
                      tickLine={false}
                      tickFormatter={(v) => fmtMetric(query.metric, Number(v))}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'hsl(var(--popover))',
                        border: '1px solid hsl(var(--border))',
                        borderRadius: 8,
                        color: 'hsl(var(--popover-foreground))',
                      }}
                      labelStyle={{ color: 'hsl(var(--muted-foreground))' }}
                      formatter={(value: unknown) => [
                        fmtMetric(query.metric, Number(value)),
                        labelFor(query.metric),
                      ]}
                    />
                    <Area
                      type="monotone"
                      dataKey="value"
                      stroke={accentVar}
                      strokeWidth={2}
                      fillOpacity={1}
                      fill="url(#colorValue)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </TabsContent>

            <TabsContent value="bar">
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={aggregatedChart}
                    margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis
                      dataKey="label"
                      stroke="hsl(var(--muted-foreground))"
                      fontSize={12}
                      tickLine={false}
                    />
                    <YAxis
                      stroke="hsl(var(--muted-foreground))"
                      fontSize={12}
                      tickLine={false}
                      tickFormatter={(v) => fmtMetric(query.metric, Number(v))}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'hsl(var(--popover))',
                        border: '1px solid hsl(var(--border))',
                        borderRadius: 8,
                        color: 'hsl(var(--popover-foreground))',
                      }}
                      labelStyle={{ color: 'hsl(var(--muted-foreground))' }}
                      formatter={(value: unknown) => [
                        fmtMetric(query.metric, Number(value)),
                        labelFor(query.metric),
                      ]}
                    />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {aggregatedChart.map((entry) => (
                        <Cell
                          key={entry.label}
                          fill={accentVar}
                          fillOpacity={maxVal > 0 ? 0.3 + (entry.value / maxVal) * 0.7 : 0.3}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </TabsContent>

            <TabsContent value="heatmap">
              <div className="space-y-4 overflow-x-auto">
                <div className="flex items-center justify-between text-sm text-muted-foreground">
                  <span>Time × Series</span>
                  <div className="flex items-center gap-2">
                    <span>less</span>
                    <div className="flex gap-0.5">
                      {[0.15, 0.3, 0.5, 0.7, 0.9].map((o) => (
                        <div
                          key={o}
                          className="w-3 h-3 rounded-sm"
                          style={{ backgroundColor: accentVar, opacity: o }}
                        />
                      ))}
                    </div>
                    <span>more</span>
                  </div>
                </div>
                {result.series.length === 0 ? (
                  <p className="text-sm text-muted-foreground text-center py-8">No data</p>
                ) : (
                  <table className="text-xs border-separate" style={{ borderSpacing: '2px' }}>
                    <thead>
                      <tr>
                        <th className="sticky left-0 z-10 bg-card text-left pr-3 font-medium text-muted-foreground">
                          {' '}
                        </th>
                        {buckets.map((b) => (
                          <th
                            key={b}
                            title={fmtTs(b, query.time.resolution)}
                            className="text-muted-foreground font-normal align-bottom whitespace-nowrap"
                            style={{
                              writingMode: 'vertical-rl',
                              transform: 'rotate(180deg)',
                              height: 64,
                            }}
                          >
                            {fmtTs(b, query.time.resolution)}
                          </th>
                        ))}
                        <th className="text-left pl-3 font-medium text-muted-foreground">total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.series.map((s) => {
                        const byBucket = new Map(s.points);
                        const seriesMax = Math.max(0, ...s.points.map(([, v]) => v));
                        return (
                          <tr key={JSON.stringify(s.group)}>
                            <td className="sticky left-0 z-10 bg-card pr-3 font-mono whitespace-nowrap">
                              {seriesLabel(s.group)}
                            </td>
                            {buckets.map((b) => {
                              const v = byBucket.get(b) ?? 0;
                              const opacity =
                                seriesMax > 0 && v > 0 ? 0.15 + (v / seriesMax) * 0.75 : 0.05;
                              return (
                                <td
                                  key={b}
                                  title={`${fmtTs(b, query.time.resolution)} — ${fmtMetric(query.metric, v)}`}
                                  style={{
                                    backgroundColor: accentVar,
                                    opacity,
                                    width: 14,
                                    height: 14,
                                  }}
                                  className="rounded-sm"
                                ></td>
                              );
                            })}
                            <td className="pl-3 font-mono whitespace-nowrap">
                              {fmtMetric(query.metric, s.total)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
