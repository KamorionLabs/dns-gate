import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, createRequest, oauthGrantsApi, scopeLabel, sortGrants } from '../src/lib/http.ts';
import type { OAuthGrant } from '../src/lib/types.ts';

function mockFetch(responses: { status: number; body?: unknown }[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    const r = responses.shift()!;
    if (r.body === undefined) return new Response(null, { status: r.status });
    return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return { fn, calls };
}

const grant = (over: Partial<OAuthGrant>): OAuthGrant => ({
  id: 'g-1',
  client_id: 'skopea',
  client_name: 'Skopea',
  subject: 'idp:alice',
  scopes: ['dns.read'],
  status: 'active',
  created_at: '2026-11-01T00:00:00Z',
  consented_at: '2026-11-01T00:00:00Z',
  last_used_at: '2026-11-02T00:00:00Z',
  expires_at: '2026-11-16T00:00:00Z',
  ...over,
});

test('connected applications are listed, revoked one by one and by client', async () => {
  const m = mockFetch([
    { status: 200, body: { grants: [{ ...grant({}), scopes: null }], manage: true } },
    { status: 204 },
    { status: 200, body: { revoked: 3 } },
    { status: 403, body: { reason: 'forbidden', message: 'gate.oauth.manage not granted' } },
  ]);
  const api = oauthGrantsApi(createRequest({ fetch: m.fn, csrf: () => 'tok', onUnauthenticated: () => {}, onReauth: () => {} }));
  const l = await api.list();
  assert.deepEqual(l.grants[0]!.scopes, []);
  assert.equal(l.manage, true);
  assert.equal(m.calls[0]!.url, '/api/v1/oauth/grants');
  assert.equal(await api.revoke('g/1'), '');
  assert.equal(m.calls[1]!.url, '/api/v1/oauth/grants/g%2F1');
  assert.equal(m.calls[1]!.init.method, 'DELETE');
  assert.equal((m.calls[1]!.init.headers as Record<string, string>)['X-Gate-CSRF'], 'tok');
  assert.deepEqual(await api.revokeAll({ client: 'skopea' }), { revoked: 3 });
  assert.equal(m.calls[2]!.url, '/api/v1/oauth/grants?client=skopea');
  await assert.rejects(api.list({ subject: 'idp:bob' }), (e: unknown) => e instanceof ApiError && e.status === 403);
  assert.equal(m.calls[3]!.url, '/api/v1/oauth/grants?subject=idp%3Abob');
});

test('active grants come first, most recently used first', () => {
  const out = sortGrants([
    grant({ id: 'old', last_used_at: '2026-10-01T00:00:00Z' }),
    grant({ id: 'revoked', status: 'revoked', last_used_at: '2026-11-05T00:00:00Z' }),
    grant({ id: 'recent', last_used_at: '2026-11-04T00:00:00Z' }),
  ]);
  assert.deepEqual(out.map((g) => g.id), ['recent', 'old', 'revoked']);
  assert.equal(scopeLabel('dns.write'), 'Change records and forwards');
  assert.equal(scopeLabel('custom'), 'custom');
});
