// Teams, record set ownership and transfers: what the console tells about
// who owns a record set, which team a write is made for, and who may move
// record sets between teams. The gate stays the authority and checks
// everything again.
import type { Me, RRset, RRsetRef, TeamInfo, TeamKind, Tombstone, Transfer, TransferStatus } from './types';
import type { StagedChange } from './staging';
import { canChange, WRITE } from './rights';
import { zoneMatch } from './glob';

export const OWNERSHIP_APPROVE = 'dns.ownership.approve';

export const teamKindLabel: Record<TeamKind, string> = {
  declared: 'Declared',
  auto: 'Not declared',
  family: 'Derived',
  claim: 'From a claim',
  store: 'Store only',
};

export const teamKindHelp: Record<TeamKind, string> = {
  declared: 'Declared in the teams block of the policy, with its members.',
  auto: 'Named by a binding or a virtual key but not declared: the gate declares it on its own until the policy has a teams block.',
  family: 'Derived from a claim of each identity (team_from): one team per value.',
  claim: 'Taken from the team claim of an issuer.',
  store: 'Owns record sets, but no binding, virtual key or declaration names it: nobody can change them until they are transferred or the team is renamed.',
};

/** Where a team comes from, in a few words. */
export function teamOrigin(t: TeamInfo): string {
  switch (t.kind) {
    case 'declared':
      return t.layer === 'managed' ? 'Declared in the managed policy' : 'Declared in the configuration file';
    case 'auto':
      return 'Referenced by the policy, not declared';
    case 'family':
      return t.family ? `Derived from claim ${t.family.claim}` : 'Derived from a claim';
    case 'claim':
      return t.issuer ? `Team claim of issuer ${t.issuer}` : 'Team claim of an issuer';
    case 'store':
      return 'Found in the ownership store only';
  }
}

/** Teams that can own record sets, by name (families and claims stand for many teams). */
export const concreteTeams = (teams: TeamInfo[]) => teams.filter((t) => t.kind !== 'claim' && !t.name.endsWith('*'));

/** Whether a rule of the user grants an action on the zone (unknown permissions: no). */
export function hasAction(me: Me | null, action: string, zone: string): boolean {
  return !!me?.permissions?.some((p) => p.actions.includes(action) && p.zones.some((z) => zoneMatch(z, zone)));
}

const list = (items: string[]) => (items.length < 2 ? items.join('') : items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1]);

const day = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
/** A date for sentences: "12 Nov, 14:05". */
export const dateText = (iso: string) => day.format(new Date(iso));

/** The tombstone of a record set, if it was deleted recently and is still reserved. */
export function reservation(tombstones: Tombstone[] | undefined, host: string, type: string, now = Date.now()): Tombstone | undefined {
  return tombstones?.find((t) => t.host === host && t.type === type && new Date(t.expires_at).getTime() > now);
}

/** What a reservation means for the user, in one sentence. */
export function reservationText(me: Me | null, t: Tombstone): string {
  if (me?.teams.includes(t.team)) return `Deleted recently: reserved for your team ${t.team} until ${dateText(t.expires_at)}.`;
  return `Deleted recently: reserved for team ${t.team} until ${dateText(t.expires_at)}. Only that team can create or adopt it again; others ask for a transfer.`;
}

export interface Ownership {
  /** Owned by (or reserved for) one of the user's teams. */
  mine: boolean;
  /** Who owns it and why the user can or cannot change it. */
  text: string;
}

/** Who owns a record set and what it means for the user. */
export function ownership(me: Me | null, zone: string, rr: RRset, unmanaged = false, tomb?: Tombstone): Ownership {
  if (unmanaged) return { mine: false, text: 'This zone is not managed by the gate: nobody owns its record sets and the gate changes none of them.' };
  if (rr.status === 'foreign') {
    if (tomb) return { mine: !!me?.teams.includes(tomb.team), text: 'Not managed by the gate. ' + reservationText(me, tomb) };
    return { mine: false, text: 'Not managed by the gate: no team owns it until someone adopts it.' };
  }
  if (!rr.owner) return { mine: false, text: canChange(me, zone, rr, unmanaged).ok ? 'Managed by the gate, without owner team.' : 'Managed by the gate, without owner team: it cannot be changed here.' };
  const v = canChange(me, zone, rr, unmanaged);
  if (me?.teams.includes(rr.owner)) {
    return { mine: true, text: v.ok ? `Owned by your team ${rr.owner}: you can change it.` : `Owned by your team ${rr.owner}. ${v.text}` };
  }
  const yours = me?.teams.length ? ` (your teams: ${me.teams.join(', ')})` : '';
  return {
    mine: false,
    text: `Owned by team ${rr.owner}: you are not a member${yours}, so only its members can change it. If it should belong to another team, request a transfer.`,
  };
}

export interface TeamChoice {
  /** The team sent with the plan and the apply; undefined: the default behaviour of the gate. */
  team?: string;
  /** Whether the user picks the team (several teams, only new record sets). */
  choose: boolean;
  options: string[];
  note: string;
}

/**
 * The team a set of staged changes is planned for. Record sets that change
 * decide it when they all belong to one of the user's teams; with only new
 * record sets, the user chooses (default team first); with record sets of
 * several teams, no team is sent and new ones go to the default team.
 */
export function planTeam(me: Me | null, staged: StagedChange[], chosen?: string, tombstones?: Tombstone[]): TeamChoice {
  const teams = me?.teams ?? [];
  const fallback = me?.default_team ?? teams[0];
  if (teams.length < 2) return { team: undefined, choose: false, options: teams, note: '' };
  const creates = staged.filter((c) => c.kind === 'create');
  const owners = [...new Set(staged.flatMap((c) => (c.kind !== 'create' && c.before?.owner && teams.includes(c.before.owner) ? [c.before.owner] : [])))];
  const reserved = [...new Set(creates.flatMap((c) => reservation(tombstones, c.host, c.type)?.team ?? []).filter((t) => teams.includes(t)))];
  const forced = [...new Set([...owners, ...reserved])];
  if (forced.length > 1) {
    return {
      team: undefined,
      choose: false,
      options: teams,
      note: `These changes touch record sets of your teams ${list(forced)}: they are made for all your teams${creates.length ? `, and new record sets go to your default team ${fallback}` : ''}.`,
    };
  }
  if (forced.length === 1) {
    const t = forced[0]!;
    const why = owners.length ? 'the team of the record sets you change' : 'the team the deleted record set is reserved for';
    return { team: t, choose: false, options: teams, note: `Made for team ${t}, ${why}${creates.length ? '; new record sets go to it too' : ''}.` };
  }
  const team = chosen && teams.includes(chosen) ? chosen : fallback;
  return { team, choose: true, options: teams, note: `New record sets will be owned by team ${team}.` };
}

export const isRequester = (t: Transfer, me: Me | null) => !!me && t.requester.subject === me.subject;

/** Why the user can or cannot approve a transfer. */
export function decisionRule(t: Transfer, me: Me | null): string {
  if (t.status !== 'proposed') return '';
  if (t.kind === 'rename') {
    if (t.can_decide) return 'You can approve it: you hold policy.approve and did not request it.';
    if (isRequester(t, me)) return 'You requested this rename: another holder of policy.approve must approve it. You can withdraw it.';
    return 'A team rename is approved by a holder of policy.approve other than the requester.';
  }
  const zone = t.zone ?? 'the zone';
  if (t.can_decide) {
    return me?.teams.includes(t.from_team)
      ? `You can approve it as a member of team ${t.from_team} allowed to write in ${zone}.`
      : `You can approve it as a holder of ${OWNERSHIP_APPROVE} on ${zone}.`;
  }
  if (isRequester(t, me)) return 'You requested it: a second person must approve it. You can withdraw it.';
  return `Approval needs a member of team ${t.from_team} allowed to write in ${zone}, or a holder of ${OWNERSHIP_APPROVE} on it, other than the requester.`;
}

/** Whether the user may reject (or, as its requester, withdraw) a transfer. */
export const canReject = (t: Transfer, me: Me | null) => t.status === 'proposed' && (t.can_decide || isRequester(t, me));

export const transferStatusLabel: Record<TransferStatus, string> = {
  proposed: 'Waiting for approval',
  approved: 'Approved',
  applied: 'Applied',
  rejected: 'Rejected',
  expired: 'Expired',
  failed: 'Failed',
};

/** A record set the user may add to a transfer selection: managed, owned, and of the team already selected. */
export const pickable = (rr: RRset, from?: string) => rr.status === 'managed' && !!rr.owner && (!from || rr.owner === from);

/** The owner team of a transfer selection, or why the selection cannot be transferred. */
export function selectionTeam(picked: RRsetRef[], rrsets: RRset[], tombstones: Tombstone[] = []): { from?: string; error?: string } {
  let from: string | undefined;
  for (const p of picked) {
    const tb = tombstones.find((t) => t.host === p.host && t.type === p.type);
    const found = rrsets.find((r) => r.host === p.host && r.type === p.type);
    // a name re-created outside the gate after its deletion: the reservation is what moves
    const rr = found?.status === 'foreign' && tb ? undefined : found;
    const name = `${p.host} ${p.type}`;
    if (rr && rr.status !== 'managed') {
      return { error: rr.status === 'foreign' ? `${name} is not managed by the gate: adopt it instead.` : `${name} is ${rr.status === 'pending' ? 'pending' : 'drifted'}: it must be settled before a transfer.` };
    }
    const team = rr?.owner ?? tb?.team;
    if (!team) return { error: `${name} is not owned by a team.` };
    if (from && team !== from) return { error: `A transfer moves the record sets of one team: ${name} belongs to ${team}, not ${from}.` };
    from = team;
  }
  return { from };
}

/** Whether the user may ask for a transfer in the zone, and of which team's record sets. */
export function transferAllowed(me: Me | null, zone: string, from?: string): { ok: boolean; text: string } {
  const approver = hasAction(me, OWNERSHIP_APPROVE, zone);
  if (!approver && !hasAction(me, WRITE, zone)) {
    return { ok: false, text: `Requesting a transfer needs ${WRITE} or ${OWNERSHIP_APPROVE} on this zone.` };
  }
  if (from && !approver && !me?.teams.includes(from)) {
    return { ok: true, text: `You are not a member of team ${from}: the record sets can only move to one of your teams.` };
  }
  return { ok: true, text: '' };
}

/**
 * Teams the selection may move to: every team the policy names but the owner
 * (a team found only in the store has no member to act for it), or only the
 * user's teams when it is neither a member of the owner team nor an approver.
 */
export function transferTargets(me: Me | null, zone: string, from: string, teams: TeamInfo[]): string[] {
  const named = concreteTeams(teams).filter((t) => t.kind !== 'store').map((t) => t.name);
  const all = [...new Set([...named, ...(me?.teams ?? [])])].filter((t) => t !== from);
  const free = hasAction(me, OWNERSHIP_APPROVE, zone) || !!me?.teams.includes(from);
  return (free ? all : all.filter((t) => me?.teams.includes(t))).sort();
}
