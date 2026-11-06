// Changes staged in a zone before review: several adds, edits and deletes,
// sent together as one plan, then applied as one write.
import type { Forward, PlanChange, RRset, RRsetChange } from './types';
import type { ShownChange } from './journal';
import { forwardText, isForward, sameForward } from './forwards';

export type StagedKind = 'create' | 'update' | 'delete';

export interface StagedChange {
  kind: StagedKind;
  host: string;
  type: string;
  ttl?: number;
  values?: string[];
  /** A URL forward (type URLFWD): no TTL nor values. */
  forward?: Forward;
  /** Forwards only: the gate refuses the change unless the forwards of the zone answer HTTPS. */
  requireHttps?: boolean;
  /** The record set as loaded, for edits and deletes (its hash is the precondition). */
  before?: RRset;
}

export const stagedKey = (c: { host: string; type: string }) => `${c.host}/${c.type}`;

const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((v, i) => v === [...b].sort()[i]);

/** Whether an edit leaves a record set as it was loaded. */
const unchanged = (before: RRset, c: StagedChange) =>
  isForward(c) ? sameForward(before.forward, c.forward) : before.ttl === c.ttl && sameSet(before.values, c.values ?? []);

/**
 * Adds a change, merging it with what is already staged for the same record set:
 * - editing a record set staged for creation keeps it a creation;
 * - deleting a record set staged for creation drops it;
 * - an edit that brings a record set back to what it was drops it.
 */
export function stage(list: StagedChange[], c: StagedChange): StagedChange[] {
  const k = stagedKey(c);
  const prev = list.find((x) => stagedKey(x) === k);
  const rest = list.filter((x) => stagedKey(x) !== k);
  let next: StagedChange | null = c;
  if (prev?.kind === 'create') {
    next = c.kind === 'delete' ? null : { ...c, kind: 'create', before: undefined };
  } else if (c.kind !== 'create') {
    const before = c.before ?? prev?.before;
    next = { ...c, before };
    if (c.kind === 'update' && before && unchanged(before, c)) next = null;
  }
  if (!next) return rest;
  // keep the position of the change it replaces
  const i = list.findIndex((x) => stagedKey(x) === k);
  if (i < 0) return [...rest, next];
  const out = [...rest];
  out.splice(i, 0, next);
  return out;
}

export const unstage = (list: StagedChange[], key: string) => list.filter((x) => stagedKey(x) !== key);

export const stagedFor = (list: StagedChange[], host: string, type: string) => list.find((x) => x.host === host && x.type === type);

/** The request body of the plan: desired states with their preconditions. */
export function toRequest(list: StagedChange[]): RRsetChange[] {
  return list.map((c): RRsetChange => {
    if (isForward(c) && c.kind !== 'delete') {
      const fwd: RRsetChange = { host: c.host, type: c.type, forward: { ...c.forward! } };
      if (c.requireHttps) fwd.require_https = true;
      if (c.kind === 'create') return { ...fwd, must_not_exist: true };
      return { ...fwd, expected_hash: c.before?.hash || undefined };
    }
    const values = c.values ? [...c.values] : undefined;
    if (c.kind === 'create') return { host: c.host, type: c.type, ttl: c.ttl, values, must_not_exist: true };
    const expected_hash = c.before?.hash || undefined;
    if (c.kind === 'delete') return { host: c.host, type: c.type, delete: true, expected_hash };
    return { host: c.host, type: c.type, ttl: c.ttl, values, expected_hash };
  });
}

/** What the zone looks like with the staged changes: the record sets (host and type) after them. */
export function keysAfter(rrsets: { host: string; type: string }[], list: StagedChange[]): { host: string; type: string }[] {
  const deleted = new Set(list.filter((c) => c.kind === 'delete').map(stagedKey));
  const out = rrsets.filter((r) => !deleted.has(stagedKey(r))).map((r) => ({ host: r.host, type: r.type }));
  for (const c of list) if (c.kind === 'create') out.push({ host: c.host, type: c.type });
  return out;
}

/**
 * After the zone was read again: keeps the staged changes whose record set did
 * not change meanwhile (with the fresh copy as their base), and drops the others.
 */
export function rebase(list: StagedChange[], rrsets: RRset[]): { kept: StagedChange[]; dropped: StagedChange[] } {
  const kept: StagedChange[] = [];
  const dropped: StagedChange[] = [];
  for (const c of list) {
    const now = rrsets.find((r) => r.host === c.host && r.type === c.type);
    if (c.kind === 'create') (now ? dropped : kept).push(c);
    else if (!now || !c.before || now.hash !== c.before.hash) dropped.push(c);
    else kept.push({ ...c, before: now });
  }
  return { kept, dropped };
}

/** A staged change in the shape of the journal, for the diff before the plan answers. */
export function shownStaged(c: StagedChange): ShownChange {
  return {
    op: c.kind,
    host: c.host,
    type: c.type,
    old_ttl: c.before?.ttl,
    old_values: c.before && !c.before.forward ? valuesOf(c.before) : undefined,
    old_forward: c.before?.forward,
    new_ttl: c.kind === 'delete' ? undefined : c.ttl,
    new_values: c.kind === 'delete' ? undefined : c.values,
    new_forward: c.kind === 'delete' ? undefined : c.forward,
  };
}

/** Values for display: an alias reads as its target, a forward as its redirect. */
export function valuesOf(r: { values?: string[] | null; alias?: { target: string } | null; forward?: Forward | null }): string[] {
  if (r.forward) return [forwardText(r.forward)];
  if (r.alias) return [`alias → ${r.alias.target}`];
  return r.values ?? [];
}

/** The fields that are set. */
const defined = <T extends object>(o: T): Partial<T> => Object.fromEntries(Object.entries(o).filter(([, v]) => v != null)) as Partial<T>;

/** A change of a plan as the diff component shows it (old/new objects or the journal fields). */
export function shownPlanChange(c: PlanChange): ShownChange {
  return {
    op: c.op,
    host: c.host,
    type: c.type,
    old_ttl: c.old_ttl ?? c.old?.ttl,
    old_values: c.old_values ?? (c.old && !c.old.forward ? valuesOf(c.old) : undefined),
    new_ttl: c.new_ttl ?? c.new?.ttl,
    new_values: c.new_values ?? (c.new && !c.new.forward ? valuesOf(c.new) : undefined),
    ...defined({
      old_alias: c.old_alias ?? c.old?.alias,
      old_forward: c.old_forward ?? c.old?.forward,
      new_alias: c.new_alias ?? c.new?.alias,
      new_forward: c.new_forward ?? c.new?.forward,
    }),
  };
}

export const kindVerb: Record<StagedKind, string> = { create: 'Add', update: 'Change', delete: 'Delete' };
