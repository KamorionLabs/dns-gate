// URL forwards in the console: form, staging, diff, rights, filters and the forwards client.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  URLFWD,
  checkForward,
  draftFromForward,
  filterForwards,
  forwardLines,
  forwardOf,
  forwardsVisible,
  httpsNote,
  httpsServes,
  modeLabel,
  newForwardDraft,
  sameForward,
  splitForwards,
  typeLabel,
  urlError,
  textError,
  MAX_TITLE,
  MAX_URL,
} from '../src/lib/forwards.ts';
import { shownPlanChange, shownStaged, stage, toRequest, valuesOf, type StagedChange } from '../src/lib/staging.ts';
import { mergeTypeChanges } from '../src/lib/journal.ts';
import { canChange, canWriteForwards, canWriteZone, readOnlyLabel, rbacAllows, writableHosts, writeAction } from '../src/lib/rights.ts';
import { describePermissions } from '../src/lib/permissions.ts';
import { createRequest, forwardsApi } from '../src/lib/http.ts';
import type { Forward, Me, RRset } from '../src/lib/types.ts';

const fw = (host: string, forward: Forward, o: Partial<RRset> = {}): RRset => ({
  host, type: URLFWD, ttl: 0, values: [], forward, status: 'managed', protected: false, adopted: false, owner: 'web', hash: 'h-' + host, ...o,
});
const rec = (host: string, type: string, o: Partial<RRset> = {}): RRset => ({
  host, type, ttl: 600, values: ['192.0.2.1'], status: 'managed', protected: false, adopted: false, owner: 'web', hash: 'h-' + host + type, ...o,
});

const me = (permissions: Me['permissions'], teams = ['web']): Me => ({ subject: 's', name: 'n', category: 'human', roles: [], teams, permissions });

// ------------------------------------------------------------------ form

test('target URLs must be absolute http or https URLs', () => {
  assert.equal(urlError('https://www.example.com/'), null);
  assert.equal(urlError(' http://example.org/path?q=1 '), null);
  assert.match(urlError('')!, /required/);
  assert.match(urlError('www.example.com')!, /https:\/\//);
  assert.match(urlError('ftp://example.com/')!, /https:\/\//);
  assert.match(urlError('https:example.com')!, /https:\/\//);
  assert.match(urlError('https://exa mple.com/')!, /spaces/);
  assert.match(urlError('https://user:pw@example.com/')!, /user name/);
  assert.match(urlError('https://example.com/?q=<x>')!, /Percent-encode/);
  assert.match(urlError('https://example.com/' + 'a'.repeat(MAX_URL))!, /at most/);
  assert.equal(textError('The title', 'Shop & co.', MAX_TITLE), null);
  assert.match(textError('The title', '<b>x</b>', MAX_TITLE)!, /plain text/);
  assert.match(textError('The title', 'x'.repeat(MAX_TITLE + 1), MAX_TITLE)!, /at most/);
  assert.match(urlError('https://')!, /valid URL|host/);
});

test('a draft makes a trimmed forward, frame fields only on a frame', () => {
  const d = { ...newForwardDraft(), host: 'go', url: ' https://example.org/ ', title: 'Shop', keywords: ' ', description: 'd' };
  assert.deepEqual(forwardOf(d), { type: '301', url: 'https://example.org/' });
  assert.deepEqual(forwardOf({ ...d, mode: 'frame' }), { type: 'frame', url: 'https://example.org/', title: 'Shop', description: 'd' });
  const back = draftFromForward('shop', { type: 'frame', url: 'https://x.example/', title: 'X' }, true);
  assert.equal(back.mode, 'frame');
  assert.equal(back.title, 'X');
  assert.equal(back.requireHttps, true);
  assert.equal(draftFromForward('x', { type: 'http307', url: 'https://x.example/' }).mode, '301');
});

test('the form checks the name, the URL and that a name has one forward', () => {
  const ok = { ...newForwardDraft(), host: 'go', url: 'https://example.org/' };
  assert.equal(checkForward(ok, 'example.com', []).ok, true);
  assert.match(checkForward({ ...ok, host: '' }, 'example.com', []).host!, /Type a name/);
  assert.match(checkForward({ ...ok, host: 'a b' }, 'example.com', []).host!, /letters/);
  assert.ok(checkForward({ ...ok, url: 'example.org' }, 'example.com', []).url);
  const taken = checkForward({ ...ok, host: 'GO.example.com.' }, 'example.com', [{ host: 'go', type: URLFWD }]);
  assert.equal(taken.ok, false);
  assert.match(taken.form[0]!, /already has a URL forward/);
  assert.equal(checkForward(ok, 'example.com', [{ host: 'go', type: 'A' }]).ok, true, 'records at the name do not count');
  assert.equal(checkForward(ok, 'example.com', [{ host: 'go', type: URLFWD }], 'go').ok, true, 'the forward being edited');
});

// ------------------------------------------------------------------ staging

test('a staged forward becomes a URLFWD change with its preconditions and require_https', () => {
  const before = fw('go', { type: '302', url: 'https://a.example/' }, { hash: 'h1' });
  const list: StagedChange[] = [
    { kind: 'create', host: 'new', type: URLFWD, forward: { type: '301', url: 'https://b.example/' }, requireHttps: true },
    { kind: 'update', host: 'go', type: URLFWD, forward: { type: '301', url: 'https://a.example/' }, before },
    { kind: 'delete', host: 'old', type: URLFWD, before: fw('old', { type: '301', url: 'https://c.example/' }, { hash: 'h2' }) },
  ];
  assert.deepEqual(toRequest(list), [
    { host: 'new', type: URLFWD, forward: { type: '301', url: 'https://b.example/' }, require_https: true, must_not_exist: true },
    { host: 'go', type: URLFWD, forward: { type: '301', url: 'https://a.example/' }, expected_hash: 'h1' },
    { host: 'old', type: URLFWD, delete: true, expected_hash: 'h2' },
  ]);
});

test('editing a forward back to what it was unstages it', () => {
  const before = fw('go', { type: 'frame', url: 'https://a.example/', title: 'A' });
  const edited = stage([], { kind: 'update', host: 'go', type: URLFWD, forward: { type: 'frame', url: 'https://a.example/', title: 'B' }, before });
  assert.equal(edited.length, 1);
  const back = stage(edited, { kind: 'update', host: 'go', type: URLFWD, forward: { type: 'frame', url: ' https://a.example/', title: 'A', keywords: '' }, before });
  assert.equal(back.length, 0);
  assert.equal(sameForward({ type: '301', url: 'https://a.example/' }, { type: '302', url: 'https://a.example/' }), false);
});

// ------------------------------------------------------------------ diff

test('a forward reads as its redirect then its frame fields', () => {
  assert.deepEqual(forwardLines({ type: 'frame', url: 'https://a.example/', title: 'A', description: 'D' }), ['frame → https://a.example/', 'title: A', 'description: D']);
  assert.deepEqual(forwardLines(undefined), []);
  assert.deepEqual(valuesOf(fw('go', { type: '302', url: 'https://a.example/' })), ['302 → https://a.example/']);
  assert.equal(modeLabel('301'), 'Permanent redirect (301)');
  assert.equal(modeLabel('frame'), 'Frame');
  assert.equal(modeLabel('http307'), 'Unknown (http307)');
  assert.equal(typeLabel('URLFWD'), 'URL forward');
  assert.equal(typeLabel('CNAME'), 'CNAME');
});

test('staged and planned forward changes carry their old and new forwards, not values', () => {
  const before = fw('go', { type: '302', url: 'https://a.example/' });
  const s = shownStaged({ kind: 'update', host: 'go', type: URLFWD, forward: { type: '301', url: 'https://a.example/' }, before });
  assert.equal(s.old_values, undefined);
  assert.deepEqual(s.old_forward, before.forward);
  assert.deepEqual(s.new_forward, { type: '301', url: 'https://a.example/' });
  const d = shownStaged({ kind: 'delete', host: 'go', type: URLFWD, before });
  assert.equal(d.new_forward, undefined);

  const journal = shownPlanChange({ op: 'update', host: 'go', type: URLFWD, old_forward: before.forward, new_forward: { type: '301', url: 'https://b.example/' } });
  assert.equal(journal.new_forward?.url, 'https://b.example/');
  const sides = shownPlanChange({ op: 'create', host: 'go', type: URLFWD, old: null, new: { ttl: 0, values: [], forward: { type: '301', url: 'https://b.example/' } } });
  assert.equal(sides.new_values, undefined);
  assert.equal(sides.new_forward?.type, '301');
});

test('a forward deleted with records created at its name is not read as a change of type', () => {
  const shown = mergeTypeChanges([
    { op: 'delete', host: 'go', type: URLFWD, old_forward: { type: '301', url: 'https://a.example/' } },
    { op: 'create', host: 'go', type: 'A', new_ttl: 300, new_values: ['192.0.2.1'] },
  ]);
  assert.equal(shown.length, 2);
  assert.equal(shown[0]!.old_type, undefined);
  const records = mergeTypeChanges([
    { op: 'delete', host: 'go', type: 'A', old_values: ['192.0.2.1'] },
    { op: 'create', host: 'go', type: 'CNAME', new_values: ['x.example.'] },
  ]);
  assert.equal(records.length, 1);
});

// ------------------------------------------------------------------ rights

test('dns.forward.write grants forwards by host, its types do not apply; dns.record.write does not grant them', () => {
  const writer = me([{ role: 'r', zones: ['example.com'], actions: ['dns.forward.write'], hosts: ['go', 'promo-*'], types: ['A'] }]);
  const go = fw('go', { type: '301', url: 'https://a.example/' });
  assert.equal(writeAction(URLFWD), 'dns.forward.write');
  assert.equal(writeAction('A'), 'dns.record.write');
  assert.equal(rbacAllows(writer, 'example.com', 'go', URLFWD), true);
  assert.equal(rbacAllows(writer, 'example.com', 'promo-fall', URLFWD), true);
  assert.equal(rbacAllows(writer, 'example.com', 'www', URLFWD), false);
  assert.equal(rbacAllows(writer, 'example.com', 'go', 'A'), false);
  assert.deepEqual(canChange(writer, 'example.com', go), { ok: true });
  assert.equal(canChange(writer, 'example.com', { ...go, host: 'www' }).ok, false);
  assert.equal(canWriteForwards(writer, 'example.com'), true);
  assert.equal(canWriteForwards(writer, 'example.org'), false);
  assert.equal(canWriteZone(writer, 'example.com'), false);
  assert.deepEqual(writableHosts(writer, 'example.com', URLFWD), ['go', 'promo-*']);

  const records = me([{ role: 'r', zones: ['example.com'], actions: ['dns.record.write'], hosts: [], types: [] }]);
  assert.equal(canWriteForwards(records, 'example.com'), false);
  const v = canChange(records, 'example.com', go);
  assert.equal(v.ok, false);
  assert.ok(!v.ok && v.why === 'forbidden' && v.text.includes('dns.forward.write'));
});

test('forwards follow ownership and read-only reasons like record sets', () => {
  const writer = me([{ role: 'r', zones: ['*'], actions: ['dns.forward.write'], hosts: [], types: [] }]);
  const f = { type: '301', url: 'https://a.example/' };
  const other = canChange(writer, 'example.com', fw('go', f, { owner: 'corporate' }));
  assert.ok(!other.ok && other.why === 'not_owner');
  assert.ok(!canChange(writer, 'example.com', fw('go', f, { status: 'foreign', owner: undefined })).ok);
  const dup = canChange(writer, 'example.com', fw('go', f, { read_only: 'duplicate_forward' }));
  assert.ok(!dup.ok && dup.why === 'read_only' && /Several forwards/.test(dup.text));
  assert.equal(readOnlyLabel(fw('go', f, { read_only: 'unsupported_forward' })), 'Unsupported');
  assert.equal(readOnlyLabel(rec('@', 'URL', { read_only: 'forward_record' })), 'Forward entry');
  assert.ok(describePermissions(writer.permissions!).some((l) => l === 'Write URL forwards in every zone'));
});

// ------------------------------------------------------------------ zone view

test('the forwards are kept apart from the records and filtered by text and owner', () => {
  const list = [
    rec('@', 'A'),
    fw('@', { type: '301', url: 'https://www.example.com/' }),
    fw('shop', { type: 'frame', url: 'https://shop.example.net/', title: 'Boutique' }, { owner: 'corporate', created_by: { subject: 'entra:bob@example.com', name: 'bob@example.com', category: 'human' } }),
  ];
  const { records, forwards } = splitForwards(list);
  assert.deepEqual(records.map((r) => r.type), ['A']);
  assert.equal(forwards.length, 2);
  assert.deepEqual(filterForwards(forwards, 'boutique').map((r) => r.host), ['shop']);
  assert.deepEqual(filterForwards(forwards, 'BOB').map((r) => r.host), ['shop']);
  assert.deepEqual(filterForwards(forwards, '', 'web').map((r) => r.host), ['@']);
  assert.equal(filterForwards(forwards, 'www.example.com', 'corporate').length, 0);
});

test('the forwards section shows for providers with forwards, or whenever forwards exist', () => {
  assert.equal(forwardsVisible({ count: 0, provider: 'eurodns' }), true);
  assert.equal(forwardsVisible({ count: 0, provider: 'eurodns', https: { status: 'unsupported' } }), false);
  assert.equal(forwardsVisible({ count: 0, provider: 'route53' }), false);
  assert.equal(forwardsVisible({ count: 2, provider: 'route53' }), true);
  assert.equal(forwardsVisible({ count: 0, provider: 'eurodns', unmanaged: true }), false);
  assert.equal(forwardsVisible({ count: 0, https: { status: 'inactive' } }), true);
  assert.equal(forwardsVisible({ count: 0 }), false);
});

test('the HTTPS status of the forwards reads in one sentence', () => {
  assert.equal(httpsNote(undefined), null);
  assert.equal(httpsNote({ status: 'unsupported' }), null);
  assert.deepEqual(httpsNote({ status: 'inactive' }), { tone: 'warn', text: 'Forwards answer HTTP only: no HTTPS redirect subscription on this domain.' });
  assert.equal(httpsNote({ status: 'active', expires_at: '2027-05-01' }, (d) => 'D' + d)!.text, 'Forwards answer HTTP and HTTPS: HTTPS redirect subscription active until D2027-05-01.');
  assert.equal(httpsNote({ status: 'pending' })!.tone, 'warn');
  assert.equal(httpsNote({ status: 'no_forward' })!.tone, 'ok');
  assert.match(httpsNote({ status: 'unknown', message: 'timeout' })!.text, /could not be read \(timeout\)/);
  assert.equal(httpsServes('active'), true);
  assert.equal(httpsServes('pending'), false);
  assert.equal(httpsServes('no_forward'), true);
  assert.equal(httpsServes('inactive'), false);
  assert.equal(httpsServes('unknown'), undefined);
  assert.equal(httpsServes(undefined), undefined);
});

// ------------------------------------------------------------------ client

test('the forwards of a zone are read with null lists made empty', async () => {
  const calls: string[] = [];
  const fetch = (async (url: string) => {
    calls.push(url);
    const body = { zone: 'example.com', https: { status: 'inactive' }, forwards: [{ host: 'go', type: URLFWD, ttl: 0, values: null, forward: { type: '301', url: 'https://a.example/' } }] };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof globalThis.fetch;
  const api = forwardsApi(createRequest({ fetch, csrf: () => '', onUnauthenticated: () => {}, onReauth: () => {} }));
  const l = await api.forwards('example.com');
  assert.equal(calls[0], '/api/v1/zones/example.com/forwards');
  assert.deepEqual(l.forwards[0]!.values, []);
  assert.equal(l.https?.status, 'inactive');

  const empty = forwardsApi(
    createRequest({
      fetch: (async () => new Response(JSON.stringify({ zone: 'x.example', forwards: null }), { status: 200 })) as unknown as typeof globalThis.fetch,
      csrf: () => '',
      onUnauthenticated: () => {},
      onReauth: () => {},
    }),
  );
  assert.deepEqual((await empty.forwards('x.example')).forwards, []);
});
