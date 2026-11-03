// Readable labels for the identities in the journal, the inventory and the
// policy: one place decides how a subject is shown, the full subject stays
// available as a tooltip and a copy.
import type { Actor, Category } from './types';

export interface IdentityLabel {
  /** Short, readable label, e.g. "Pipeline · dns-deploy" or "alice@example.com". */
  label: string;
  /** Kind of identity, for the icon and the tooltip. */
  kind: Category;
  /** Full subject (issuer:id), shown on hover and copied. */
  full: string;
}

/** The id part of an "issuer:id" subject. */
function idOf(subject: string): string {
  const i = subject.indexOf(':');
  return i >= 0 ? subject.slice(i + 1) : subject;
}

const safeDecode = (s: string) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
};

/** Name of an Azure DevOps service connection subject (sc://<org>/<project>/<name>). */
export function serviceConnectionName(value: string): string | undefined {
  const m = /^sc:\/\/[^/]+\/[^/]+\/(.+)$/.exec(value);
  return m?.[1] ? safeDecode(m[1]) : undefined;
}

/** Readable form of a raw pipeline subject (GitHub Actions, AWS role), undefined when none applies. */
export function pipelineName(value: string): string | undefined {
  const gh = /^repo:([^:]+\/[^:]+):(ref|environment|pull_request)(?::(.+))?$/.exec(value);
  if (gh?.[1]) {
    const [, repo, kind, rest] = gh;
    if (kind === 'ref' && rest) return `${repo} @ ${rest.replace(/^refs\/(heads|tags)\//, '')}`;
    if (kind === 'environment' && rest) return `${repo} · ${rest}`;
    return repo;
  }
  if (/^arn:aws[\w-]*:sts::\d+:assumed-role\//.test(value)) return 'role/' + (value.split('/')[1] ?? '');
  if (/^arn:aws[\w-]*:iam::\d+:role\//.test(value)) return 'role/' + value.slice(value.lastIndexOf('/') + 1);
  return undefined;
}

/** How an actor is shown everywhere in the console. */
export function identityLabel(actor: Actor): IdentityLabel {
  const system = actor.category === 'system' || actor.subject.startsWith('gate:');
  const kind: Category = system ? 'system' : actor.category;
  const full = actor.subject;
  const id = idOf(full);
  const name = actor.name || id;
  if (!system && kind === 'pipeline') {
    const sc = serviceConnectionName(name) ?? serviceConnectionName(id);
    if (sc) return { label: `Pipeline · ${sc}`, kind, full };
    // no display name configured for the issuer: make the raw subject readable
    if (name === id) return { label: pipelineName(id) ?? id, kind, full };
  }
  return { label: name, kind, full };
}
