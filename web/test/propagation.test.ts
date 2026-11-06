// Unit tests of the propagation panel helpers (no DOM).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canCheckPropagation, expectedLine, expectOf, groupAnswers, keepPolling, placeLine, POLL_FOR_MS, regionLabel, summaryLine } from '../src/lib/propagation.ts';
import type { Me, Propagation, PropagationAnswer } from '../src/lib/types.ts';

const ans = (name: string, kind: PropagationAnswer['kind'], region?: string): PropagationAnswer => ({
  kind, name, address: '192.0.2.1', region, status: 'match', values: ['192.0.2.1'], latency_ms: 10,
});

const result = (over: Partial<Propagation> = {}): Propagation => ({
  zone: 'example.com', host: 'www', type: 'A', name: 'www.example.com.', query_type: 'A',
  expected: { exists: true, hash: 'h', ttl: 300, values: ['192.0.2.1', '192.0.2.2'] },
  checked_at: '2026-11-06T12:00:00Z', cached: false,
  summary: { total: 5, match: 3, stale: 1, missing: 0, error: 1, indeterminate: 0, converged: false, max_ttl_left: 120 },
  answers: [], ...over,
});

test('answers are grouped: name servers first, then regions in a fixed order', () => {
  const groups = groupAnswers([ans('r-asia', 'resolver', 'asia'), ans('Cloudflare', 'resolver', 'anycast'), ans('ns1', 'authoritative'),
    ans('corp', 'resolver'), ans('FDN', 'resolver', 'europe'), ans('lab', 'resolver', 'mars-base'), ans('Quad9', 'resolver', 'anycast')]);
  assert.deepEqual(groups.map((g) => g.label), ['Authoritative name servers', 'Anycast resolvers', 'Europe', 'Asia', 'Other resolvers', 'Mars base']);
  assert.deepEqual(groups[1].answers.map((a) => a.name), ['Cloudflare', 'Quad9']);
  assert.ok(groups[1].note);
  assert.equal(regionLabel('north-america'), 'North America');
});

test('a check refreshes until it converges or two minutes passed', () => {
  assert.equal(keepPolling(null, 0, 1000), true);
  assert.equal(keepPolling(result(), 0, POLL_FOR_MS - 1), true);
  assert.equal(keepPolling(result(), 0, POLL_FOR_MS), false);
  assert.equal(keepPolling(result({ summary: { ...result().summary, converged: true } }), 0, 1000), false);
});

test('summary and expected lines', () => {
  assert.equal(summaryLine(result()), '3 of 4 up to date · 1 without answer');
  assert.equal(summaryLine(result({ summary: { ...result().summary, error: 0, total: 4 } })), '3 of 4 up to date');
  assert.equal(expectedLine(result()), '192.0.2.1, 192.0.2.2');
  assert.equal(expectedLine(result({ expected: { exists: false, values: [] } })), 'No record: the record set does not exist');
  assert.equal(expectedLine(result({ expected: { exists: true, values: [], alias_target: 'd111.cloudfront.net.' } })), 'Addresses of d111.cloudfront.net.');
  assert.equal(placeLine({ ...ans('FDN', 'resolver'), location: 'Paris', country: 'FR' }), 'Paris · FR');
  assert.equal(placeLine(ans('ns1', 'authoritative')), '');
});

test('the check after an apply expects the content written', () => {
  assert.equal(expectOf({ op: 'create', host: 'app', type: 'CNAME', new_hash: 'abc' }), 'abc');
  assert.equal(expectOf({ op: 'update', host: 'app', type: 'CNAME' }), undefined);
  assert.equal(expectOf({ op: 'delete', host: 'old', type: 'A' }), 'absent');
});

test('the panel is offered only with dns.read on the record set', () => {
  const me = (actions: string[], hosts: string[] = [], types: string[] = []): Me => ({
    subject: 's', name: 'n', category: 'human', roles: [], teams: [], groups: [],
    permissions: [{ role: 'r', zones: ['example.com'], actions, hosts, types }],
  });
  assert.equal(canCheckPropagation(me(['dns.read', 'ui.read']), 'example.com', 'www', 'A'), true);
  assert.equal(canCheckPropagation(me(['ui.read']), 'example.com', 'www', 'A'), false);
  assert.equal(canCheckPropagation(me(['dns.read'], ['*.app']), 'example.com', 'www', 'A'), false);
  assert.equal(canCheckPropagation(me(['dns.read'], [], ['TXT']), 'example.com', 'www', 'A'), false);
  assert.equal(canCheckPropagation(me(['dns.read']), 'example.org', 'www', 'A'), false);
  assert.equal(canCheckPropagation(null, 'example.com', 'www', 'A'), false);
  assert.equal(canCheckPropagation({ ...me([]), permissions: undefined } as unknown as Me, 'example.com', 'www', 'A'), true);
});

test('indeterminate alias answers are reported apart and keep the check running', () => {
  const r = result({ summary: { total: 5, match: 3, stale: 0, missing: 0, error: 0, indeterminate: 2, converged: false, max_ttl_left: 0 } });
  assert.equal(summaryLine(r), '3 of 5 up to date · 2 not comparable');
  assert.equal(keepPolling(r, 0, 1000), true);
});
