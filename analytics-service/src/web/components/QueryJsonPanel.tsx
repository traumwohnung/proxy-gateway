import Editor from '@monaco-editor/react';
import { AlertCircle, Check, ClipboardPaste, Copy } from 'lucide-react';
import { useState } from 'react';
import { validate } from '../../db/query-schema';
import { useStore } from '../lib/store';
import { useEffectiveTheme } from '../lib/theme';
import { Button } from './ui/button';

export default function QueryJsonPanel() {
  const draftQuery = useStore((s) => s.draftQuery);
  const setQuery = useStore((s) => s.setQuery);
  const run = useStore((s) => s.run);

  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const themeMode = useEffectiveTheme();

  const json = JSON.stringify(draftQuery, null, 2);

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(json);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function onPaste() {
    setError(null);
    try {
      const text = await navigator.clipboard.readText();
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        setError('clipboard is not valid JSON');
        return;
      }
      const v = validate(parsed);
      if (!v.ok) {
        setError(v.errors.map((e) => (e.path ? `${e.path}: ${e.error}` : e.error)).join('; '));
        return;
      }
      setQuery(v.query);
      void run();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="flex flex-col h-[600px]">
      <div className="flex-1 min-h-0">
        <Editor
          height="100%"
          defaultLanguage="json"
          value={json}
          theme={themeMode === 'dark' ? 'vs-dark' : 'vs'}
          options={{
            readOnly: true,
            minimap: { enabled: false },
            fontSize: 12,
            lineNumbers: 'on',
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            renderLineHighlight: 'none',
            folding: true,
            fixedOverflowWidgets: true,
          }}
        />
      </div>

      {error && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive mt-2">
          <AlertCircle className="h-3 w-3 mt-0.5 flex-shrink-0" />
          <span className="flex-1">{error}</span>
          <button
            type="button"
            onClick={() => setError(null)}
            className="text-destructive/70 hover:text-destructive"
          >
            ×
          </button>
        </div>
      )}

      <div className="flex gap-2 pt-3 border-t border-border mt-3">
        <Button type="button" variant="outline" size="sm" onClick={onCopy}>
          {copied ? <Check className="h-3 w-3 mr-1" /> : <Copy className="h-3 w-3 mr-1" />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onPaste}>
          <ClipboardPaste className="h-3 w-3 mr-1" />
          Paste
        </Button>
      </div>
    </div>
  );
}
