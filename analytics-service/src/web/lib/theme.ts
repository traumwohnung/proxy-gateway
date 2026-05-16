export type Theme = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'theme';

export function getStoredTheme(): Theme {
  if (typeof localStorage === 'undefined') return 'system';
  const v = localStorage.getItem(STORAGE_KEY);
  return v === 'light' || v === 'dark' ? v : 'system';
}

export function setStoredTheme(t: Theme): void {
  if (typeof localStorage === 'undefined') return;
  if (t === 'system') localStorage.removeItem(STORAGE_KEY);
  else localStorage.setItem(STORAGE_KEY, t);
  applyTheme(t);
}

export function effectiveTheme(t: Theme): 'light' | 'dark' {
  if (t !== 'system') return t;
  if (typeof matchMedia === 'undefined') return 'light';
  return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function applyTheme(t: Theme): void {
  if (typeof document === 'undefined') return;
  const eff = effectiveTheme(t);
  document.documentElement.classList.toggle('dark', eff === 'dark');
}

import { useEffect, useState } from 'react';

// Module-level so referential identity is stable across renders — keeps
// useExhaustiveDependencies happy without re-creating the closure each time.
const readEffectiveTheme = (): 'light' | 'dark' =>
  typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
    ? 'dark'
    : 'light';

/** React hook: returns the currently effective theme ('light' | 'dark'),
 * tracking changes to the `dark` class on <html>. */
export function useEffectiveTheme(): 'light' | 'dark' {
  const [t, setT] = useState<'light' | 'dark'>(readEffectiveTheme);
  useEffect(() => {
    const update = () => setT(readEffectiveTheme());
    update();
    const obs = new MutationObserver(update);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => obs.disconnect();
  }, []);
  return t;
}
