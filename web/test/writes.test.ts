// DNS writes from the console: record forms, staging, rights and the plan/apply client.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  checkDraft,
  draftFromRRset,
  draftValues,
  isIPv6,
  normalizeHost,
  parseValue,
  serializeValue,
  txtValue,
  txtWire,
  unquote,
  validateValue,
  type RecordDraft,
} from '../src/lib/records.ts';
import { keysAfter, rebase, shownPlanChange, stage, toRequest, unstage, type StagedChange } from '../src/lib/staging.ts';
import { canChange, canWriteZone, writableHosts, writableTypes } from '../src/lib/rights.ts';
import { ApiError, createRequest, dnsWrites } from '../src/lib/http.ts';
import type { Me, RRset } from '../src/lib/types.ts';

const rr = (o: Partial<RRset> & { host: string; type: string }): RRset => ({
  ttl: 600, values: ['192.0.2.1'], status: 'managed', protected: false, adopted: false, owner: 'web', hash: 'h-' + o.host + o.type, ...o,
});

// ------------------------------------------------------------------ forms

test('each type turns its fields into a zone-file value and back', () => {
  assert.equal(serializeValue('A', { address: ' 203.0.113.10 ' }), '203.0.113.10');
  assert.equal(serializeValue('CNAME', { target: 'App.Example.net' }), 'app.example.net.');
  assert.equal(serializeValue('MX', { priority: '10', server: 'mx1.example.net.' }), '10 mx1.example.net.');
  assert.equal(serializeValue('SRV', { priority: '10', weight: '5', port: '5060', target: 'sip.example.net' }), '10 5 5060 sip.example.net.');
  assert.equal(serializeValue('CAA', { flags: '0', tag: 'issue', value: 'letsencrypt.org' }), '0 issue "letsencrypt.org"');
  assert.equal(serializeValue('TXT', { text: 'v=spf1 -all' }), 'v=spf1 -all');
  assert.deepEqual(parseValue('MX', '20 mx2.example.com.'), { priority: '20', server: 'mx2.example.com.' });
  assert.deepEqual(parseValue('CAA', '0 issuewild "amazon.com"'), { flags: '0', tag: 'issuewild', value: 'amazon.com' });
  assert.deepEqual(parseValue('SRV', '1 2 443 svc.example.net.'), { priority: '1', weight: '2', port: '443', target: 'svc.example.net.' });
  assert.deepEqual(parseValue('TXT', '"part one " "part two"'), { text: 'part one part two' });
});

test('TXT values are sent unquoted at any length and read back from either form', () => {
  const long = 'v=DKIM1; k=rsa; p=' + 'A'.repeat(400);
  assert.equal(serializeValue('TXT', { text: long }), long);
  assert.equal(parseValue('TXT', serializeValue('TXT', { text: long })).text, long);
  assert.equal(parseValue('TXT', txtValue(long)).text, long);
  assert.equal(txtWire('say "hi"'), 'say "hi"');
  assert.equal(txtWire('"quoted"'), '"\\"quoted\\""');
  assert.equal(parseValue('TXT', txtWire('"quoted"')).text, '"quoted"');
});

test('TXT values in presentation format are quoted, escaped and split in 255-character strings', () => {
  assert.equal(txtValue('say "hi"'), '"say \\"hi\\""');
  assert.deepEqual(unquote(txtValue('say "hi" \\o/')), ['say "hi" \\o/']);
  const long = 'x'.repeat(300);
  const v = txtValue(long);
  assert.deepEqual(unquote(v).map((s) => s.length), [255, 45]);
  assert.equal(parseValue('TXT', v).text, long);
});

test('values are validated field by field, in plain words', () => {
  assert.deepEqual(validateValue('A', { address: '203.0.113.10' }), {});
  assert.match(validateValue('A', { address: '300.1.1.1' }).address!, /IPv4/);
  assert.match(validateValue('A', { address: '' }).address!, /required/);
  assert.deepEqual(validateValue('AAAA', { address: '2001:db8::10' }), {});
  assert.match(validateValue('AAAA', { address: '2001:db8::g' }).address!, /IPv6/);
  assert.equal(isIPv6('::1'), true);
  assert.equal(isIPv6('1:2:3:4:5:6:7:8'), true);
  assert.equal(isIPv6('1:2:3:4:5:6:7'), false);
  assert.equal(isIPv6('::ffff:192.0.2.1'), true);
  assert.match(validateValue('CNAME', { target: '192.0.2.1' }).target!, /not an IP/);
  assert.match(validateValue('CNAME', { target: 'bad name' }).target!, /not a valid name/);
  assert.deepEqual(validateValue('MX', { priority: '10', server: 'mx.example.net' }), {});
  assert.match(validateValue('MX', { priority: 'ten', server: 'mx.example.net' }).priority!, /number/);
  assert.match(validateValue('SRV', { priority: '1', weight: '1', port: '0', target: 'a.example' }).port!, /1 to 65535/);
  assert.match(validateValue('CAA', { flags: '0', tag: 'nope', value: 'x' }).tag!, /issue/);
  assert.match(validateValue('TXT', { text: '' }).text!, /required/);
});

test('names are made relative to the zone, the apex is @', () => {
  assert.equal(normalizeHost('WWW.example.com.', 'example.com'), 'www');
  assert.equal(normalizeHost('example.com', 'example.com'), '@');
  assert.equal(normalizeHost('@', 'example.com'), '@');
  assert.equal(normalizeHost(' api.staging ', 'example.com'), 'api.staging');
});

test('a draft is checked as a whole: apex CNAME, exclusivity, duplicates, existing record sets', () => {
  const zone = 'example.com';
  const existing = [{ host: 'www', type: 'CNAME' }, { host: '@', type: 'A' }, { host: 'mail', type: 'MX' }];
  const d = (o: Partial<RecordDraft>): RecordDraft => ({ host: 'app', type: 'A', ttl: 300, values: [{ address: '192.0.2.1' }], ...o });

  assert.equal(checkDraft(d({}), zone, existing).ok, true);
  assert.match(checkDraft(d({ host: '' }), zone, existing).host!, /@/);
  assert.match(checkDraft(d({ host: 'a b' }), zone, existing).host!, /letters/);
  assert.match(checkDraft(d({ type: 'CNAME', host: '@', values: [{ target: 'x.example.net' }] }), zone, existing).host!, /apex/);
  assert.match(checkDraft(d({ type: 'CNAME', host: 'mail', values: [{ target: 'x.example.net' }] }), zone, existing).form[0]!, /alone/);
  assert.match(checkDraft(d({ host: 'www' }), zone, existing).form[0]!, /is a CNAME/);
  assert.match(checkDraft(d({ host: '@' }), zone, existing).form[0]!, /already has A records/);
  assert.match(checkDraft(d({ type: 'CNAME', values: [{ target: 'a.example' }, { target: 'b.example' }] }), zone, existing).form[0]!, /single/);
  const dup = checkDraft(d({ values: [{ address: '192.0.2.1' }, { address: '192.0.2.1' }] }), zone, existing);
  assert.equal(dup.ok, false);
  assert.match(dup.values[1]!._!, /twice/);
  assert.match(checkDraft(d({ ttl: 0 }), zone, existing).ttl!, /TTL/);
  // editing the existing apex A is not a duplicate of itself
  assert.equal(checkDraft(d({ host: '@' }), zone, existing, { host: '@', type: 'A' }).ok, true);
});

test('an existing record set opens in the form with its values', () => {
  const d = draftFromRRset(rr({ host: '@', type: 'MX', ttl: 3600, values: ['10 mx1.example.com.', '20 mx2.example.com.'] }));
  assert.equal(d.values.length, 2);
  assert.deepEqual(draftValues(d), ['10 mx1.example.com.', '20 mx2.example.com.']);
});

// ---------------------------------------------------------------- staging

test('staged changes merge per record set', () => {
  const www = rr({ host: 'www', type: 'A', values: ['192.0.2.1'] });
  let list: StagedChange[] = [];
  list = stage(list, { kind: 'create', host: 'app', type: 'A', ttl: 300, values: ['192.0.2.9'] });
  list = stage(list, { kind: 'update', host: 'www', type: 'A', ttl: 600, values: ['192.0.2.2'], before: www });
  assert.equal(list.length, 2);

  // editing a staged creation keeps it a creation
  list = stage(list, { kind: 'update', host: 'app', type: 'A', ttl: 60, values: ['192.0.2.10'] });
  assert.equal(list[0]!.kind, 'create');
  assert.equal(list[0]!.ttl, 60);

  // deleting a staged creation drops it
  assert.equal(stage(list, { kind: 'delete', host: 'app', type: 'A' }).length, 1);

  // deleting an edited record set keeps the original as precondition
  const del = stage(list, { kind: 'delete', host: 'www', type: 'A' });
  assert.equal(del[1]!.kind, 'delete');
  assert.equal(del[1]!.before?.hash, www.hash);

  // an edit back to the original content is no change at all
  assert.equal(stage(list, { kind: 'update', host: 'www', type: 'A', ttl: 600, values: ['192.0.2.1'], before: www }).length, 1);

  assert.equal(unstage(list, 'app/A').length, 1);
});

test('the plan request carries the desired states and their preconditions', () => {
  const www = rr({ host: 'www', type: 'A', hash: 'abc' });
  const old = rr({ host: 'old', type: 'TXT', hash: 'def', values: ['"x"'] });
  const body = toRequest([
    { kind: 'create', host: 'app', type: 'CNAME', ttl: 300, values: ['lb.example.net.'] },
    { kind: 'update', host: 'www', type: 'A', ttl: 60, values: ['192.0.2.3'], before: www },
    { kind: 'delete', host: 'old', type: 'TXT', before: old },
  ]);
  assert.deepEqual(body, [
    { host: 'app', type: 'CNAME', ttl: 300, values: ['lb.example.net.'], must_not_exist: true },
    { host: 'www', type: 'A', ttl: 60, values: ['192.0.2.3'], expected_hash: 'abc' },
    { host: 'old', type: 'TXT', delete: true, expected_hash: 'def' },
  ]);
});

test('after a reload, changes on record sets that moved are dropped', () => {
  const www = rr({ host: 'www', type: 'A', hash: 'v1' });
  const api = rr({ host: 'api', type: 'A', hash: 'v1' });
  const list: StagedChange[] = [
    { kind: 'update', host: 'www', type: 'A', ttl: 60, values: ['192.0.2.3'], before: www },
    { kind: 'delete', host: 'api', type: 'A', before: api },
    { kind: 'create', host: 'new', type: 'A', ttl: 60, values: ['192.0.2.4'] },
    { kind: 'create', host: 'taken', type: 'A', ttl: 60, values: ['192.0.2.5'] },
  ];
  const fresh = [{ ...www }, { ...api, hash: 'v2' }, rr({ host: 'taken', type: 'A' })];
  const { kept, dropped } = rebase(list, fresh);
  assert.deepEqual(kept.map((c) => c.host), ['www', 'new']);
  assert.deepEqual(dropped.map((c) => c.host), ['api', 'taken']);
});

test('the zone after staging has the creations and not the deletions', () => {
  const keys = keysAfter([{ host: 'a', type: 'A' }, { host: 'b', type: 'TXT' }], [
    { kind: 'delete', host: 'b', type: 'TXT' },
    { kind: 'create', host: 'c', type: 'CNAME', ttl: 60, values: ['x.'] },
  ]);
  assert.deepEqual(keys, [{ host: 'a', type: 'A' }, { host: 'c', type: 'CNAME' }]);
});

test('plan changes read the same with old/new objects or journal fields', () => {
  assert.deepEqual(shownPlanChange({ op: 'update', host: 'www', type: 'A', old: { ttl: 600, values: ['1.1.1.1'] }, new: { ttl: 60, values: ['2.2.2.2'] } }), {
    op: 'update', host: 'www', type: 'A', old_ttl: 600, old_values: ['1.1.1.1'], new_ttl: 60, new_values: ['2.2.2.2'],
  });
  assert.deepEqual(shownPlanChange({ op: 'create', host: 'a', type: 'A', new_ttl: 60, new_values: ['1.2.3.4'] }).new_values, ['1.2.3.4']);
  const alias = shownPlanChange({ op: 'delete', host: '@', type: 'A', old: { ttl: 0, alias: { target: 'd1.cloudfront.net.', hosted_zone_id: 'Z2', evaluate_target_health: false } }, new: null });
  assert.deepEqual(alias.old_values, ['alias → d1.cloudfront.net.']);
  assert.equal(alias.new_values, undefined);
});

// ----------------------------------------------------------------- rights

const me: Me = {
  subject: 'entra:alice', name: 'alice', category: 'human', roles: ['writer'], teams: ['web'],
  permissions: [
    { role: 'writer', zones: ['example.com'], actions: ['dns.read', 'dns.record.write'], hosts: ['*', '_*.*'], types: ['CNAME', 'TXT'] },
    { role: 'viewer', zones: ['*'], actions: ['dns.read', 'ui.read'], hosts: [], types: [] },
  ],
};

test('edit and delete are offered only on record sets the user may change', () => {
  const z = 'example.com';
  assert.deepEqual(canChange(me, z, rr({ host: 'www', type: 'CNAME', values: ['x.'] })), { ok: true });
  const why = (r: RRset, unmanaged = false) => {
    const v = canChange(me, z, r, unmanaged);
    return v.ok ? 'ok' : v.why;
  };
  assert.equal(why(rr({ host: 'www', type: 'CNAME' }), true), 'zone_unmanaged');
  assert.equal(why(rr({ host: '@', type: 'SOA', read_only: 'server_managed' })), 'server_managed');
  assert.equal(why(rr({ host: 'geo', type: 'CNAME', read_only: 'routing_policy' })), 'routing_policy');
  assert.equal(why(rr({ host: 'x', type: 'CNAME', read_only: 'something_else' })), 'read_only');
  assert.equal(why(rr({ host: 'www', type: 'CNAME', protected: true })), 'protected');
  assert.equal(why(rr({ host: 'www', type: 'CNAME', status: 'foreign', owner: undefined })), 'foreign');
  assert.equal(why(rr({ host: 'www', type: 'CNAME', status: 'tainted' })), 'tainted');
  assert.equal(why(rr({ host: 'www', type: 'CNAME', status: 'pending' })), 'pending');
  assert.equal(why(rr({ host: 'www', type: 'CNAME', owner: 'platform' })), 'not_owner');
  assert.equal(why(rr({ host: '@', type: 'A', values: [], alias: { target: 'd.cloudfront.net.', hosted_zone_id: 'Z2', evaluate_target_health: false } })), 'alias');
  assert.equal(why(rr({ host: 'www', type: 'A' })), 'forbidden'); // type outside the role
  assert.equal(why(rr({ host: 'a.b', type: 'CNAME' })), 'forbidden'); // host outside the role
  assert.equal(why(rr({ host: '_acme.www', type: 'TXT' })), 'ok');
  const otherTeam = canChange(me, z, rr({ host: 'www', type: 'CNAME', owner: 'platform' }));
  assert.equal(!otherTeam.ok && otherTeam.text, 'Owned by team platform: only that team can change it.');
});

test('adding records is offered where a rule grants writes', () => {
  assert.equal(canWriteZone(me, 'example.com'), true);
  assert.equal(canWriteZone(me, 'other.example'), false);
  assert.equal(canWriteZone(null, 'example.com'), false);
  assert.deepEqual(writableTypes(me, 'example.com'), ['CNAME', 'TXT']);
  assert.deepEqual(writableTypes(me, 'other.example'), []);
  assert.deepEqual(writableHosts(me, 'example.com', 'TXT'), ['*', '_*.*']);
  // without effective permissions in /me, the gate decides
  const bare: Me = { ...me, permissions: undefined };
  assert.equal(canWriteZone(bare, 'any.example'), true);
  assert.equal(canChange(bare, 'any.example', rr({ host: 'x', type: 'A' })).ok, true);
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

test('plan and apply post to the zone with the CSRF header', async () => {
  const plan = { zone: 'example.com', allowed: true, changes: [{ op: 'create', host: 'app', type: 'A', new_ttl: 60, new_values: ['192.0.2.1'] }], zone_version: 7, plan_id: 'pl_1' };
  const m = mockFetch([{ status: 200, body: plan }, { status: 200, body: { ...plan, request_id: 'req_1' } }]);
  const w = dnsWrites(createRequest({ fetch: m.fn, csrf: () => 'tok', onUnauthenticated: () => {}, onReauth: () => {} }));

  const changes = [{ host: 'app', type: 'A', ttl: 60, values: ['192.0.2.1'], must_not_exist: true }];
  const p = await w.plan('example.com', changes);
  assert.equal(p.plan_id, 'pl_1');
  assert.equal(m.calls[0]!.url, '/api/v1/zones/example.com/plan');
  assert.equal(m.calls[0]!.init.method, 'POST');
  const h = m.calls[0]!.init.headers as Record<string, string>;
  assert.equal(h['X-Gate-CSRF'], 'tok');
  assert.equal(h['Content-Type'], 'application/json');
  assert.deepEqual(JSON.parse(m.calls[0]!.init.body as string), { changes });

  const a = await w.apply('example.com', 'pl_1');
  assert.equal(a.request_id, 'req_1');
  assert.equal(m.calls[1]!.url, '/api/v1/zones/example.com/apply');
  assert.deepEqual(JSON.parse(m.calls[1]!.init.body as string), { plan_id: 'pl_1' });
});

test('refusals come back as ApiError with reason and details; reauth and sign-in redirect', async () => {
  let reauth = 0;
  let signin = 0;
  const m = mockFetch([
    { status: 412, body: { reason: 'precondition', message: 'zone changed', details: { host: 'www' } } },
    { status: 403, body: { reason: 'reauth_required', message: 'step up' } },
    { status: 401, body: {} },
  ]);
  const w = dnsWrites(createRequest({ fetch: m.fn, csrf: () => '', onUnauthenticated: () => signin++, onReauth: () => reauth++ }));
  await assert.rejects(w.apply('example.com', 'pl_1'), (e: unknown) => {
    assert.ok(e instanceof ApiError);
    assert.equal(e.status, 412);
    assert.equal(e.reason, 'precondition');
    assert.deepEqual(e.details, { host: 'www' });
    return true;
  });
  await assert.rejects(w.plan('example.com', []), (e: unknown) => e instanceof ApiError && e.reason === 'reauth_required');
  assert.equal(reauth, 1);
  await assert.rejects(w.plan('example.com', []), (e: unknown) => e instanceof ApiError && e.status === 401);
  assert.equal(signin, 1);
  // zone names are escaped in the path
  const n = mockFetch([{ status: 200, body: { zone: 'a/b', allowed: true, changes: [] } }]);
  await dnsWrites(createRequest({ fetch: n.fn, csrf: () => '', onUnauthenticated: () => {}, onReauth: () => {} })).plan('a/b', []);
  assert.equal(n.calls[0]!.url, '/api/v1/zones/a%2Fb/plan');
  // a null change list reads as empty
  const z = mockFetch([{ status: 200, body: { zone: 'a', allowed: false, reason: 'forbidden', changes: null } }]);
  const r = await dnsWrites(createRequest({ fetch: z.fn, csrf: () => '', onUnauthenticated: () => {}, onReauth: () => {} })).plan('a', []);
  assert.deepEqual(r.changes, []);
});

// ---------------------------------------------------------------- connect

test('the Connect snippets use the dnsgate provider and the neutral REST API', async () => {
  const { terraformProvider, curlCommand } = await import('../src/lib/connect.ts');
  const c = { base_url: 'https://gate.example', mcp: { enabled: true, url: 'https://gate.example/mcp', allow_writes: false }, claude_desktop_extension_url: '' };
  const tf = terraformProvider(c, 'edge.example.org');
  assert.match(tf, /dnsgate = \{\n\s+source = "KamorionLabs\/dnsgate"/);
  assert.match(tf, /provider "dnsgate" \{\n\s+endpoint = "https:\/\/gate.example"\n\}/);
  assert.match(tf, /resource "dnsgate_record_set" "www" \{\n\s+zone\s+= "edge.example.org"\n\s+name\s+= "www"\n\s+type\s+= "CNAME"\n\s+ttl\s+= 300\n\s+values = \["app.example.net."\]/);
  assert.doesNotMatch(tf, /eurodns/);
  const sh = curlCommand(c, 'edge.example.org');
  assert.match(sh, /GATE=https:\/\/gate.example/);
  assert.match(sh, /curl -X POST .* \\\n  -d '\{"changes":\[\{"host":"www","type":"CNAME","ttl":300,"values":\["app.example.net."\]\}\]\}' \\\n  \$GATE\/api\/v1\/zones\/edge.example.org\/plan/);
  assert.match(sh, /-d '\{"plan_id":"<plan_id>"\}' \$GATE\/api\/v1\/zones\/edge.example.org\/apply/);
});

test('a token from the console comes with ready-to-paste Terraform and curl lines', async () => {
  const { tokenSnippets, tokenLine } = await import('../src/lib/connect.ts');
  const c = { base_url: 'https://gate.example', mcp: { enabled: false, url: '', allow_writes: false }, claude_desktop_extension_url: '', tokens_url: 'https://gate.example/api/v1/tokens', issuer: { url: '', kind: 'saml' as const } };
  const s = tokenSnippets(c, 'eyJ.abc.def', 'edge.example.org');
  assert.equal(s.terraform, "export DNSGATE_TOKEN='eyJ.abc.def'\nterraform plan\n");
  assert.equal(s.curl, 'curl -H "Authorization: Bearer eyJ.abc.def" \\\n  https://gate.example/api/v1/zones/edge.example.org/rrsets\n');
  assert.match(tokenLine(c), /Get an API token/);
  assert.match(tokenLine({ ...c, issuer: { url: '', kind: 'entra' as const, tenant_id: 't' } }), /^TOKEN=\$\(az account get-access-token/);
});

test('the token is asked with the CSRF header and a session_required refusal is typed', async () => {
  const { issueToken } = await import('../src/lib/http.ts');
  const tok = { access_token: 'eyJ.x.y', token_type: 'Bearer', expires_in: 3600, expires_at: '2026-11-05T12:00:00Z', issuer: 'https://gate.example' };
  const m = mockFetch([{ status: 200, body: tok }, { status: 403, body: { reason: 'session_required', message: 'gate tokens are issued to UI sessions only' } }]);
  const req = createRequest({ fetch: m.fn, csrf: () => 'tok', onUnauthenticated: () => {}, onReauth: () => {} });
  assert.deepEqual(await issueToken(req), tok);
  assert.equal(m.calls[0]!.url, '/api/v1/tokens');
  assert.equal(m.calls[0]!.init.method, 'POST');
  assert.equal((m.calls[0]!.init.headers as Record<string, string>)['X-Gate-CSRF'], 'tok');
  await assert.rejects(issueToken(req), (e: unknown) => e instanceof ApiError && e.status === 403 && e.reason === 'session_required');
});
