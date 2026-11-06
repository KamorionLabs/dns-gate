import type { StagedChange } from './staging';

// Staged record changes survive a step-up re-authentication round trip.
const key = (zone: string) => 'dns-gate.staged.' + zone;

export function saveStaged(zone: string, list: StagedChange[]): void {
  try {
    if (list.length) sessionStorage.setItem(key(zone), JSON.stringify(list));
    else sessionStorage.removeItem(key(zone));
  } catch {
    // storage unavailable
  }
}

export function takeStaged(zone: string): StagedChange[] {
  try {
    const raw = sessionStorage.getItem(key(zone));
    sessionStorage.removeItem(key(zone));
    return raw ? (JSON.parse(raw) as StagedChange[]) : [];
  } catch {
    return [];
  }
}
