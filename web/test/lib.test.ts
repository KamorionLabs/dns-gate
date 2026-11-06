// Unit tests of the display helpers (no DOM): node --test, types stripped.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { humanDuration, humanSeconds, parseGoDuration } from '../src/lib/duration.ts';
import { identityLabel } from '../src/lib/identity.ts';
import { isRead, mergeTypeChanges } from '../src/lib/journal.ts';

test('durations read like people write them', () => {
  assert.equal(humanDuration('1h'), '1 h');
  assert.equal(humanDuration('15m'), '15 min');
  assert.equal(humanDuration('10s'), '10 s');
  assert.equal(humanDuration('1h30m0s'), '1 h 30 min');
  assert.equal(humanDuration('24h'), '1 d');
  assert.equal(humanDuration('500ms'), '500 ms');
  assert.equal(humanDuration('soon'), 'soon');
  assert.equal(parseGoDuration('2h3m'), 7380);
  assert.equal(humanSeconds(600), '10 min');
  assert.equal(humanSeconds(86400 * 2), '2 d');
  assert.equal(humanSeconds(0), '0 s');
});

test('identities get a readable label and keep the full subject', () => {
  const sc = identityLabel({ subject: 'ado:sc://example-org/platform/dns-deploy', name: 'sc://example-org/platform/dns-deploy', category: 'pipeline' });
  assert.equal(sc.label, 'Pipeline · dns-deploy');
  assert.equal(sc.full, 'ado:sc://example-org/platform/dns-deploy');
  const gh = identityLabel({ subject: 'github:repo:acme/web:ref:refs/heads/main', name: 'repo:acme/web:ref:refs/heads/main', category: 'pipeline' });
  assert.equal(gh.label, 'acme/web @ main');
  const named = identityLabel({ subject: 'aws:arn:aws:iam::111111111111:role/ci-app', name: 'role/ci-app', category: 'pipeline' });
  assert.equal(named.label, 'role/ci-app');
  const human = identityLabel({ subject: 'entra:alice@example.com', name: 'alice@example.com', category: 'human' });
  assert.equal(human.label, 'alice@example.com');
  assert.equal(identityLabel({ subject: 'gate:reconciler', name: 'reconciler', category: 'system' }).kind, 'system');
});

test('a delete and a create of the same host with another type is one type change', () => {
  const merged = mergeTypeChanges([
    { op: 'delete', host: 'app', type: 'A', old_ttl: 3600, old_values: ['192.0.2.1'] },
    { op: 'create', host: 'other', type: 'TXT', new_ttl: 600, new_values: ['"x"'] },
    { op: 'create', host: 'app', type: 'CNAME', new_ttl: 600, new_values: ['app.example.net.'] },
  ]);
  assert.equal(merged.length, 2);
  assert.deepEqual(merged[0], {
    op: 'update', host: 'app', type: 'CNAME', old_type: 'A', old_ttl: 3600, old_values: ['192.0.2.1'], new_ttl: 600, new_values: ['app.example.net.'],
  });
  assert.equal(merged[1]!.host, 'other');
  // same type: a real delete then create stays as it is
  assert.equal(mergeTypeChanges([{ op: 'delete', host: 'a', type: 'A' }, { op: 'create', host: 'a', type: 'A' }]).length, 2);
});

test('reads and dry runs are told apart from writes', () => {
  const base = { time: '', request_id: 'r', actor: { subject: 's', name: 's', category: 'human' as const } };
  assert.equal(isRead({ ...base, action: 'mcp.list_zones', decision: 'allow' }), true);
  assert.equal(isRead({ ...base, action: 'getDnsZone', decision: 'allow' }), true);
  assert.equal(isRead({ ...base, action: 'mcp.list_rrsets', decision: 'deny' }), false);
  assert.equal(isRead({ ...base, action: 'saveDnsZone', decision: 'allow' }), false);
  assert.equal(isRead({ ...base, action: 'mcp.apply_rrset_change', decision: 'allow' }), false);
  for (const a of ['checkZoneProfile', 'getProfile', 'listZoneProfiles', 'zone_profile.get', 'zone_profile.list', 'zone_profile.check', 'mcp.check_zone_profile', 'mcp.get_zone_profile']) {
    assert.equal(isRead({ ...base, action: a, decision: 'allow' }), true, a);
  }
  for (const a of ['createZoneProfile', 'zone_profile.create', 'zone_profile.delete', 'mcp.update_zone_profile']) {
    assert.equal(isRead({ ...base, action: a, decision: 'allow' }), false, a);
  }
});

test('zone profile grants count on every zone only', async () => {
  const { describePermissions } = await import('../src/lib/permissions.ts');
  const grant = (zones: string[]) => ({ role: 'r', zones, actions: ['dns.zone.profile'], hosts: [], types: [] });
  assert.deepEqual(describePermissions([grant(['*'])]), ['Manage the zone profiles of the EuroDNS accounts']);
  assert.match(describePermissions([grant(['example.com'])])[0], /no effect/);
  assert.deepEqual(describePermissions([grant(['**'])]), ['Manage the zone profiles of the EuroDNS accounts']);
  assert.match(describePermissions([grant(['*.com'])])[0], /no effect/);
});
