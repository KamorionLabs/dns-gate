import type { AdoptSelection } from './types';

// An adoption in progress survives a step-up re-authentication round trip.
const key = (zone: string) => 'eurodns-gate.adopt.' + zone;

export interface StoredAdopt {
  selection: AdoptSelection;
  comment: string;
}

export function saveAdopt(zone: string, a: StoredAdopt): void {
  try {
    sessionStorage.setItem(key(zone), JSON.stringify(a));
  } catch {
    // storage unavailable
  }
}

export function takeAdopt(zone: string): StoredAdopt | null {
  try {
    const raw = sessionStorage.getItem(key(zone));
    sessionStorage.removeItem(key(zone));
    return raw ? (JSON.parse(raw) as StoredAdopt) : null;
  } catch {
    return null;
  }
}

export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
