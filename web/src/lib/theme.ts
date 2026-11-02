export type Theme = 'light' | 'dark';
const KEY = 'eurodns-gate.theme';

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : null;
  } catch {
    return null;
  }
}

export function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function initialTheme(): Theme {
  return stored() ?? systemTheme();
}

export function applyTheme(t: Theme, persist = false) {
  document.documentElement.dataset.theme = t;
  if (!persist) return;
  try {
    localStorage.setItem(KEY, t);
  } catch {
    // storage unavailable (private mode): theme still applies for this page
  }
}
