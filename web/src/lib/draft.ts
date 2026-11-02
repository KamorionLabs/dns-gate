import type { PolicyDocument } from './types';

// The policy draft survives a step-up re-authentication round trip.
const KEY = 'eurodns-gate.policy-draft';

export interface StoredDraft {
  parent_id: string;
  document: PolicyDocument;
  comment: string;
  saved_at: string;
}

export function saveDraft(d: Omit<StoredDraft, 'saved_at'>): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify({ ...d, saved_at: new Date().toISOString() }));
  } catch {
    // storage unavailable: the draft is lost on reload, nothing else breaks
  }
}

export function loadDraft(): StoredDraft | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as StoredDraft) : null;
  } catch {
    return null;
  }
}

export function clearDraft(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // ignore
  }
}
