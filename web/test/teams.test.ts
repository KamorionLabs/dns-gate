// Teams, ownership and transfers: reasons shown to users, the team of a plan, the transfer rules and the API client.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canReject,
  decisionOutcome,
  decisionRule,
  ownership,
  pickable,
  planTeam,
  reservation,
  reservationText,
  selectionTeam,
  teamOrigin,
  transferAllowed,
  transferTargets,
} from '../src/lib/teams.ts';
import type { StagedChange } from '../src/lib/staging.ts';
import { createRequest, dnsWrites, teamsApi, transferOf } from '../src/lib/http.ts';
import type { Me, RRset, TeamInfo, Tombstone, Transfer } from '../src/lib/types.ts';

const rr = (o: Partial<RRset> & { host: string; type: string }): RRset => ({
  ttl: 600, values: ['x.example.net.'], status: 'managed', protected: false, adopted: false, owner: 'web', hash: 'h-' + o.host + o.type, ...o,
});

const me: Me = {
  subject: 'entra:alice', name: 'alice', category: 'human', roles: ['writer'], teams: ['web', 'platform'], default_team: 'web',
  permissions: [{ role: 'writer', zones: ['example.com'], actions: ['dns.read', 'dns.record.write'], hosts: [], types: ['CNAME', 'TXT'] }],
};
const solo: Me = { ...me, teams: ['web'], default_team: 'web' };
const approver: Me = {
  ...me, subject: 'entra:erin', teams: ['ops'], default_team: 'ops',
  permissions: [{ role: 'owners', zones: ['*'], actions: ['dns.ownership.approve'], hosts: [], types: [] }],
};
const reader: Me = { ...me, subject: 'entra:carol', teams: ['ops'], permissions: [{ role: 'viewer', zones: ['*'], actions: ['ui.read'], hosts: [], types: [] }] };

const later = new Date(Date.now() + 3600_000).toISOString();
const past = new Date(Date.now() - 3600_000).toISOString();
const tomb = (o: Partial<Tombstone> & { host: string; team: string }): Tombstone => ({ type: 'CNAME', deleted_at: past, expires_at: later, ...o });

// -------------------------------------------------------------- ownership

test('each record set says who owns it and why the user can or cannot change it', () => {
  const z = 'example.com';
  assert.deepEqual(ownership(me, z, rr({ host: 'www', type: 'CNAME' })), { mine: true, text: 'Owned by your team web: you can change it.' });
  assert.equal(ownership(me, z, rr({ host: 'www', type: 'CNAME', owner: 'platform' })).mine, true);
  const other = ownership(me, z, rr({ host: 'www', type: 'CNAME', owner: 'corporate' }));
  assert.equal(other.mine, false);
  assert.match(other.text, /^Owned by team corporate: you are not a member \(your teams: web, platform\)/);
  assert.match(other.text, /request a transfer/);
  const tainted = ownership(me, z, rr({ host: 'www', type: 'CNAME', status: 'tainted' }));
  assert.match(tainted.text, /^Owned by your team web\. Changed outside the gate/);
  const scope = ownership(me, z, rr({ host: 'www', type: 'A' }));
  assert.match(scope.text, /^Owned by your team web\. Your roles do not allow/);
  assert.match(ownership(me, z, rr({ host: 'x', type: 'CNAME', status: 'foreign', owner: undefined })).text, /no team owns it until someone adopts it/);
  assert.match(ownership(me, z, rr({ host: 'x', type: 'CNAME' }), true).text, /not managed by the gate/);
  const res = ownership(me, z, rr({ host: 'old', type: 'CNAME', status: 'foreign', owner: undefined }), false, tomb({ host: 'old', team: 'corporate' }));
  assert.equal(res.mine, false);
  assert.match(res.text, /reserved for team corporate until .*Only that team can create or adopt it again; others ask for a transfer\./);
  assert.match(ownership(null, z, rr({ host: 'www', type: 'CNAME' })).text, /you are not a member, so only/);
});

test('a deleted record set stays reserved for its team until the tombstone expires', () => {
  const list = [tomb({ host: 'old', team: 'corporate' }), tomb({ host: 'gone', team: 'web', expires_at: past })];
  assert.equal(reservation(list, 'old', 'CNAME')?.team, 'corporate');
  assert.equal(reservation(list, 'old', 'TXT'), undefined);
  assert.equal(reservation(list, 'gone', 'CNAME'), undefined);
  assert.match(reservationText(me, list[0]!), /reserved for team corporate .*others ask for a transfer/);
  assert.match(reservationText(me, tomb({ host: 'p', team: 'web' })), /^Deleted recently: reserved for your team web until/);
});

// --------------------------------------------------------- team of a plan

test('a plan is made for the team of the record sets it changes, or the one the user picks', () => {
  const www = rr({ host: 'www', type: 'CNAME', owner: 'platform' });
  const api = rr({ host: 'api', type: 'CNAME', owner: 'web' });
  const create: StagedChange = { kind: 'create', host: 'new', type: 'CNAME', ttl: 60, values: ['a.example.net.'] };

  assert.deepEqual(planTeam(solo, [create]), { team: undefined, choose: false, options: ['web'], note: '' });

  const onlyNew = planTeam(me, [create]);
  assert.equal(onlyNew.choose, true);
  assert.equal(onlyNew.team, 'web');
  assert.match(onlyNew.note, /owned by team web/);
  assert.equal(planTeam(me, [create], 'platform').team, 'platform');
  assert.equal(planTeam(me, [create], 'corporate').team, 'web');

  const edit = planTeam(me, [{ kind: 'update', host: 'www', type: 'CNAME', ttl: 60, values: ['b.'], before: www }, create], 'web');
  assert.equal(edit.choose, false);
  assert.equal(edit.team, 'platform');
  assert.match(edit.note, /^Made for team platform, the team of the record sets you change; new record sets go to it too\./);

  const mixed = planTeam(me, [
    { kind: 'delete', host: 'www', type: 'CNAME', before: www },
    { kind: 'update', host: 'api', type: 'CNAME', ttl: 60, values: ['c.'], before: api },
  ]);
  assert.equal(mixed.team, undefined);
  assert.match(mixed.note, /your teams platform and web/);

  const reserved = planTeam(me, [{ ...create, host: 'promo' }], 'web', [tomb({ host: 'promo', team: 'platform' })]);
  assert.equal(reserved.team, 'platform');
  assert.equal(reserved.choose, false);
  assert.match(reserved.note, /reserved for/);
  // reserved for a team of somebody else: the gate refuses, the user still picks
  assert.equal(planTeam(me, [{ ...create, host: 'promo' }], 'platform', [tomb({ host: 'promo', team: 'corporate' })]).team, 'platform');
});

// -------------------------------------------------------------- transfers

test('a transfer selection holds the record sets of one team', () => {
  const rrsets = [
    rr({ host: 'a', type: 'CNAME', owner: 'web' }),
    rr({ host: 'b', type: 'CNAME', owner: 'web' }),
    rr({ host: 'c', type: 'CNAME', owner: 'platform' }),
    rr({ host: 'd', type: 'CNAME', status: 'tainted' }),
    rr({ host: 'e', type: 'CNAME', status: 'foreign', owner: undefined }),
    rr({ host: 'old', type: 'CNAME', status: 'foreign', owner: undefined }),
  ];
  const tombs = [tomb({ host: 'gone', team: 'web' }), tomb({ host: 'old', team: 'corporate' })];
  const ref = (host: string) => ({ host, type: 'CNAME' });
  assert.deepEqual(selectionTeam([ref('a'), ref('b'), ref('gone')], rrsets, tombs), { from: 'web' });
  assert.match(selectionTeam([ref('a'), ref('c')], rrsets, tombs).error!, /one team: c CNAME belongs to platform, not web/);
  assert.match(selectionTeam([ref('d')], rrsets, tombs).error!, /drifted/);
  assert.match(selectionTeam([ref('e')], rrsets, tombs).error!, /adopt it instead/);
  assert.match(selectionTeam([ref('zz')], rrsets, tombs).error!, /not owned by a team/);
  // re-created outside the gate after its deletion: the reservation moves
  assert.deepEqual(selectionTeam([ref('old')], rrsets, tombs), { from: 'corporate' });
  assert.deepEqual(selectionTeam([], rrsets, tombs), { from: undefined });
  assert.equal(pickable(rrsets[0]!), true);
  assert.equal(pickable(rrsets[2]!, 'web'), false);
  assert.equal(pickable(rrsets[3]!), false);
});

test('who may ask for a transfer, and to which teams', () => {
  const teams: TeamInfo[] = [
    { name: 'web', kind: 'declared', roles: [], rrsets: 3 },
    { name: 'platform', kind: 'declared', roles: [], rrsets: 1 },
    { name: 'corporate', kind: 'declared', roles: [], rrsets: 2 },
    { name: 'ci-*', kind: 'family', roles: [], rrsets: 0 },
    { name: '*', kind: 'claim', roles: [], rrsets: 0 },
    { name: 'legacy', kind: 'store', roles: [], rrsets: 4 },
  ];
  assert.deepEqual(transferAllowed(me, 'example.com', 'web'), { ok: true, text: '' });
  assert.equal(transferAllowed(reader, 'example.com').ok, false);
  assert.match(transferAllowed(reader, 'example.com').text, /dns.record.write or dns.ownership.approve/);
  assert.match(transferAllowed(me, 'example.com', 'corporate').text, /only move to one of your teams/);
  assert.equal(transferAllowed(approver, 'example.com', 'corporate').text, '');
  assert.equal(transferAllowed(me, 'other.example').ok, false);

  assert.deepEqual(transferTargets(me, 'example.com', 'web', teams), ['corporate', 'platform']);
  assert.deepEqual(transferTargets(me, 'example.com', 'corporate', teams), ['platform', 'web']);
  assert.deepEqual(transferTargets(solo, 'example.com', 'corporate', teams), ['web']);
  assert.deepEqual(transferTargets(approver, 'example.com', 'legacy', teams), ['corporate', 'ops', 'platform', 'web']);
});

const transfer = (o: Partial<Transfer>): Transfer => ({
  id: 'tr-1', kind: 'rrsets', zone: 'example.com', from_team: 'web', to_team: 'platform', rrsets: [{ host: 'www', type: 'CNAME' }],
  status: 'proposed', comment: 'move', requester: { subject: 'entra:bob', name: 'bob', category: 'human' },
  created_at: past, expires_at: later, can_decide: false, ...o,
});

test('the approval rule is explained to whoever looks at a transfer', () => {
  assert.equal(
    decisionRule(transfer({ can_decide: true }), me),
    'You can approve it: for every record set of the request, you may write it through team web or hold dns.ownership.approve on it.',
  );
  assert.equal(decisionRule(transfer({ can_decide: true, from_team: 'corporate' }), approver), 'You can approve it as a holder of dns.ownership.approve on every record set of the request.');
  const mine = transfer({ requester: { subject: 'entra:alice', name: 'alice', category: 'human' } });
  assert.match(decisionRule(mine, me), /^You requested it: another person than the requester who, for every record set of the request, may write it through the roles of team web or holds dns.ownership.approve on it must approve it\. You can withdraw it\./);
  assert.equal(
    decisionRule(transfer({ from_team: 'corporate' }), reader),
    'Approval needs another person than the requester who, for every record set of the request, may write it through the roles of team corporate or holds dns.ownership.approve on it.',
  );
  // a member of the owner team who cannot decide: a record set outside its rights, or its own request under another identity
  assert.match(decisionRule(transfer({}), me), /You cannot approve it: you lack that right on one of its record sets, or you asked for it under another identity\./);
  assert.match(decisionRule(transfer({}), { ...me, category: 'pipeline' }), /Pipelines and API keys do not approve unless the gate allows machine approvers\./);
  assert.match(decisionRule(transfer({ kind: 'rename', zone: undefined, can_decide: true }), me), /policy.approve.*dns.ownership.approve on every record set of team web/);
  assert.match(decisionRule(transfer({ kind: 'rename', zone: undefined }), reader), /^Approval needs another person than the requester holding policy.approve, and dns.ownership.approve on every record set of the team\.$/);
  assert.match(decisionRule(transfer({ status: 'applying' }), me), /retries on its own/);
  assert.equal(decisionRule(transfer({ status: 'applied' }), me), '');

  assert.equal(canReject(transfer({ can_decide: true }), me), true);
  assert.equal(canReject(mine, me), true);
  assert.equal(canReject(transfer({}), reader), false);
  assert.equal(canReject(transfer({ status: 'rejected', can_decide: true }), me), false);
});

test('team and transfer lookups are reads in the journal, transfer decisions are not', async () => {
  const { isRead } = await import('../src/lib/journal.ts');
  const { actionLabel } = await import('../src/lib/labels.ts');
  const base = { time: '', request_id: 'r', actor: { subject: 's', name: 's', category: 'human' as const }, decision: 'allow' as const };
  assert.equal(isRead({ ...base, action: 'mcp.list_teams' }), true);
  assert.equal(isRead({ ...base, action: 'mcp.get_team' }), true);
  assert.equal(isRead({ ...base, action: 'mcp.transfer_list' }), true);
  assert.equal(isRead({ ...base, action: 'mcp.transfer_approve' }), false);
  assert.equal(isRead({ ...base, action: 'gate.transfer.apply', changes: [{ op: 'transfer', host: 'www', type: 'CNAME' }] }), false);
  assert.equal(actionLabel('gate.transfer.apply'), 'Ownership transfer');
  assert.equal(actionLabel('mcp.transfer_propose'), 'Transfer request (assistant)');
});

test('an approval the gate could not complete says whether it is retried or failed', () => {
  const locked = { reason: 'zone_locked', message: 'zone example.com is locked' };
  const retry = decisionOutcome(locked, transfer({ status: 'applying', error: 'zone example.com is locked' }));
  assert.equal(retry.retrying, true);
  assert.match(retry.text, /^Approved, not applied yet: zone example.com is locked\. The gate retries it on its own/);
  const failed = decisionOutcome({ reason: 'precondition', message: 'www CNAME changed' }, transfer({ status: 'failed', error: 'www CNAME changed since the request' }));
  assert.deepEqual(failed, { retrying: false, text: 'Not applied: www CNAME changed since the request. Nothing moved; ask for a new transfer if it is still needed.' });
  assert.match(decisionOutcome({ reason: 'precondition', message: 'transfer tr-1 is applied' }).text, /decided meanwhile/);
  assert.match(decisionOutcome({ reason: 'expired', message: 'x' }).text, /expired/);
  assert.equal(decisionOutcome({ reason: 'forbidden', message: 'the requester cannot approve its own transfer' }).text, 'the requester cannot approve its own transfer');
});

test('team origins read as sentences', () => {
  assert.equal(teamOrigin({ name: 'web', kind: 'declared', layer: 'managed', roles: [], rrsets: 0 }), 'Declared in the managed policy');
  assert.equal(teamOrigin({ name: 'web', kind: 'declared', roles: [], rrsets: 0 }), 'Declared in the configuration file');
  assert.equal(teamOrigin({ name: 'ci-*', kind: 'family', family: { claim: 'sub', regex: '(.*)' }, roles: [], rrsets: 0 }), 'Derived from claim sub');
  assert.equal(teamOrigin({ name: 'legacy', kind: 'store', roles: [], rrsets: 4 }), 'Found in the ownership store only');
});

// ------------------------------------------------------------- API client

function mockFetch(responses: { status: number; body: unknown }[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const r = responses.shift()!;
    return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { fn, calls };
}
const deps = (fn: typeof fetch) => ({ fetch: fn, csrf: () => 'tok', onUnauthenticated: () => {}, onReauth: () => {} });

test('plan and apply carry the selected team only when there is one', async () => {
  const plan = { zone: 'example.com', allowed: true, changes: [], plan_id: 'pl_1', team: 'platform' };
  const m = mockFetch([{ status: 200, body: plan }, { status: 200, body: plan }, { status: 200, body: { ...plan, team: undefined } }]);
  const w = dnsWrites(createRequest(deps(m.fn)));
  const changes = [{ host: 'a', type: 'CNAME', ttl: 60, values: ['x.'] }];
  assert.equal((await w.plan('example.com', changes, 'platform')).team, 'platform');
  assert.deepEqual(JSON.parse(m.calls[0]!.init.body as string), { changes, team: 'platform' });
  await w.apply('example.com', 'pl_1', 'platform');
  assert.deepEqual(JSON.parse(m.calls[1]!.init.body as string), { plan_id: 'pl_1', team: 'platform' });
  await w.plan('example.com', changes);
  assert.deepEqual(JSON.parse(m.calls[2]!.init.body as string), { changes });
});

test('teams and transfers go to their endpoints, with the CSRF header on decisions', async () => {
  const t = transfer({ rrsets: undefined as unknown as Transfer['rrsets'] });
  const m = mockFetch([
    { status: 200, body: { strict: true, teams: [{ name: 'web', kind: 'declared', roles: null, rrsets: 2 }] } },
    { status: 200, body: { name: 'web', kind: 'declared', roles: ['writer'], rrsets: 2, owned: null, transfers: null } },
    { status: 200, body: { transfers: [t], next_cursor: 'c2' } },
    { status: 201, body: t },
    { status: 200, body: { ...t, status: 'applied' } },
    { status: 200, body: { ...t, status: 'rejected' } },
    { status: 201, body: { ...t, kind: 'rename' } },
    { status: 412, body: { reason: 'precondition', message: 'www CNAME changed since the request', transfer: { ...t, status: 'failed' } } },
    { status: 502, body: { reason: 'upstream', message: 'provider unavailable', transfer: { ...t, status: 'applying', error: 'provider unavailable' } } },
    { status: 403, body: { reason: 'forbidden', message: 'no' } },
  ]);
  const a = teamsApi(createRequest(deps(m.fn)));
  const list = await a.teams();
  assert.deepEqual(list.teams[0]!.roles, []);
  assert.equal(m.calls[0]!.url, '/api/v1/teams');
  const d = await a.team('web');
  assert.deepEqual([d.owned, d.transfers], [[], []]);
  assert.equal(m.calls[1]!.url, '/api/v1/teams/web');
  const page = await a.transfers({ status: 'proposed', zone: 'example.com' });
  assert.deepEqual(page.transfers[0]!.rrsets, []);
  assert.equal(m.calls[2]!.url, '/api/v1/transfers?status=proposed&zone=example.com');
  await a.proposeTransfer('example.com', { rrsets: [{ host: 'www', type: 'CNAME' }], to_team: 'platform', comment: 'move' });
  assert.equal(m.calls[3]!.url, '/api/v1/zones/example.com/transfers');
  assert.deepEqual(JSON.parse(m.calls[3]!.init.body as string), { rrsets: [{ host: 'www', type: 'CNAME' }], to_team: 'platform', comment: 'move' });
  assert.equal((await a.decideTransfer('tr-1', true, 'ok')).status, 'applied');
  assert.equal(m.calls[4]!.url, '/api/v1/transfers/tr-1/approve');
  assert.equal((m.calls[4]!.init.headers as Record<string, string>)['X-Gate-CSRF'], 'tok');
  await a.decideTransfer('tr-1', false, '');
  assert.equal(m.calls[5]!.url, '/api/v1/transfers/tr-1/reject');
  await a.renameTeam('data', 'platform', 'merged');
  assert.equal(m.calls[6]!.url, '/api/v1/teams/data/rename');
  assert.deepEqual(JSON.parse(m.calls[6]!.init.body as string), { to: 'platform', comment: 'merged' });
  await assert.rejects(a.decideTransfer('tr-1', true, ''), (e: unknown) => {
    assert.equal((e as { reason: string }).reason, 'precondition');
    assert.equal(transferOf(e)?.status, 'failed');
    assert.deepEqual(transferOf(e)?.rrsets, []);
    return true;
  });
  await assert.rejects(a.decideTransfer('tr-1', true, ''), (e: unknown) => {
    const back = transferOf(e);
    assert.equal(back?.status, 'applying');
    assert.equal(back?.error, 'provider unavailable');
    return true;
  });
  await assert.rejects(a.decideTransfer('tr-1', true, ''), (e: unknown) => transferOf(e) === undefined);
});
