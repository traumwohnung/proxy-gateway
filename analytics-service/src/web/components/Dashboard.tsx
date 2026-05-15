import { useEffect } from 'react';
import { useStore } from '../lib/store';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import QueryForm from './QueryForm';
import QueryJsonPanel from './QueryJsonPanel';
import ResponseViewer from './ResponseViewer';
import type { UsageQuery } from '../../db/query';

export default function Dashboard() {
  const { query, result, loading, error, setQuery, run } = useStore();

  useEffect(() => {
    void run();
  }, [run]);

  function onSubmit(next: UsageQuery): void {
    setQuery(next);
    void run();
  }

  return (
    <div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <Card>
          <CardHeader>
            <CardTitle className="text-xl font-semibold">Query Builder</CardTitle>
          </CardHeader>
          <CardContent>
            <QueryForm query={query} onSubmit={onSubmit} isLoading={loading} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-xl font-semibold">Query JSON</CardTitle>
          </CardHeader>
          <CardContent>
            <QueryJsonPanel />
          </CardContent>
        </Card>
      </div>

      <h2 className="text-xl font-semibold mb-4">Results</h2>

      {error && (
        <div className="mb-6 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
          <div className="font-medium">Query failed</div>
          <pre className="whitespace-pre-wrap text-xs mt-1">{error}</pre>
        </div>
      )}

      <ResponseViewer result={result} query={query} isLoading={loading} />
    </div>
  );
}
