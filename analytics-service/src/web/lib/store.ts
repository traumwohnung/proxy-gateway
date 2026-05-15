import { create } from 'zustand';
import type { UsageQuery } from '../../db/query.js';
import { defaultQuery } from './query-url.js';

export interface UsageQueryResult {
  query: UsageQuery;
  series: { group: Record<string, string | number | null>; total: number; points: [number, number][] }[];
  total: number;
  meta: { series_count: number; buckets: number };
}

interface State {
  /** Last submitted query — what /api/usage/query was called with. */
  query: UsageQuery;
  /** Live draft from the form, updates on every edit. */
  draftQuery: UsageQuery;
  result:  UsageQueryResult | null;
  loading: boolean;
  error:   string | null;
  setQuery(next: UsageQuery): void;
  setDraftQuery(next: UsageQuery): void;
  run(): Promise<void>;
}

export const useStore = create<State>((set, get) => {
  const initial = defaultQuery();
  return {
    query: initial,
    draftQuery: initial,
    result:  null,
    loading: false,
    error:   null,

    setQuery(next) {
      set({ query: next, draftQuery: next });
    },
    setDraftQuery(next) {
      set({ draftQuery: next });
    },

    async run() {
      set({ loading: true, error: null });
      const { query } = get();
      try {
        const res = await fetch('/api/usage/query', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(query),
        });
        if (!res.ok) {
          const text = await res.text();
          set({ loading: false, error: `${res.status}: ${text}` });
          return;
        }
        const result = (await res.json()) as UsageQueryResult;
        set({ loading: false, result });
      } catch (e) {
        set({ loading: false, error: (e as Error).message });
      }
    },
  };
});
