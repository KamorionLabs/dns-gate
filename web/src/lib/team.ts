// Readable form of a binding's owner team (fixed or derived from a claim).
import type { TeamFrom } from './types';

/** Short label, e.g. "ci-‹sub›" for a derived team. */
export function teamLabel(team: string, from?: TeamFrom): string {
  if (!from) return team;
  return `${from.prefix ?? ''}‹${from.claim}›`;
}

/** Full explanation, for titles and hints. */
export function teamFromText(from: TeamFrom): string {
  const prefix = from.prefix ? `"${from.prefix}" + ` : '';
  return `team = ${prefix}lowercased capture of ${from.claim} ~ /${from.regex}/ (one team per identity)`;
}
