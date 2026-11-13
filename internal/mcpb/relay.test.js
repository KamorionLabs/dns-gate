// Tests of relay.js against a fake gate and a fake OIDC provider.
// Run with: node --test internal/mcpb/
'use strict';

const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const RELAY = path.join(__dirname, 'relay.js');
// Loading relay.js as a library must not start the relay on the test's stdio.
process.env.DNS_GATE_RELAY_NO_MAIN = '1';
const b64url = (b) => Buffer.from(b).toString('base64url');

// fakeServer plays both the OIDC provider and the gate's /mcp endpoint.
function fakeServer() {
  const f = {
    clientID: 'relay-client',
    codes: new Map(), // code -> {challenge, redirect, nonce}
    refreshTokens: new Set(),
    validTokens: new Set(),
    seq: 0,
    tokenRequests: [],
    authorizeError: null,
    mcp: [], // {method, auth, session, protocol}
    getCalls: 0,
    limited: 0, // POSTs to answer 429 before serving again
    retryAfter: '1',
    callDelay: 0, // ms a tools/call takes
    inFlight: 0,
    maxInFlight: 0,
  };
  const issue = (nonce) => {
    f.seq++;
    const at = `at-${f.seq}`;
    const rt = `rt-${f.seq}`;
    f.validTokens.add(at);
    f.refreshTokens.add(rt);
    const tok = { access_token: at, refresh_token: rt, token_type: 'Bearer', expires_in: 3600 };
    if (nonce !== undefined) tok.id_token = `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ nonce, sub: 'user' }))}.`;
    return tok;
  };
  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    res.end(JSON.stringify(body));
  };
  const readBody = (req) =>
    new Promise((resolve) => {
      let b = '';
      req.on('data', (c) => (b += c));
      req.on('end', () => resolve(b));
    });

  f.server = http.createServer(async (req, res) => {
    const u = new URL(req.url, f.url);
    if (u.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, { issuer: f.url, authorization_endpoint: `${f.url}/authorize?prompt=select_account`, token_endpoint: `${f.url}/token` });
    }
    if (u.pathname === '/authorize') {
      const q = u.searchParams;
      const redirect = q.get('redirect_uri');
      assert.equal(q.get('prompt'), 'select_account', 'existing query parameters are kept');
      assert.equal(q.get('response_type'), 'code');
      assert.equal(q.get('client_id'), f.clientID);
      assert.equal(q.get('code_challenge_method'), 'S256');
      assert.equal(q.get('scope'), 'openid offline_access api://gate/.default');
      assert.match(redirect, /^http:\/\/localhost:\d+$/, 'loopback redirect without a path');
      assert.ok(q.get('state') && q.get('nonce') && q.get('code_challenge'));
      const back = new URL(redirect);
      back.searchParams.set('state', q.get('state'));
      if (f.authorizeError) {
        back.searchParams.set('error', f.authorizeError);
      } else {
        const code = `code-${crypto.randomUUID()}`;
        f.codes.set(code, { challenge: q.get('code_challenge'), redirect, nonce: q.get('nonce') });
        back.searchParams.set('code', code);
      }
      res.writeHead(302, { Location: back.href });
      return res.end();
    }
    if (u.pathname === '/token') {
      const p = new URLSearchParams(await readBody(req));
      f.tokenRequests.push(p.get('grant_type'));
      if (p.get('client_id') !== f.clientID) return json(res, 400, { error: 'invalid_client' });
      if (p.get('grant_type') === 'authorization_code') {
        const c = f.codes.get(p.get('code'));
        f.codes.delete(p.get('code'));
        if (!c || c.redirect !== p.get('redirect_uri')) return json(res, 400, { error: 'invalid_grant' });
        const challenge = b64url(crypto.createHash('sha256').update(p.get('code_verifier') || '').digest());
        if (challenge !== c.challenge) return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
        return json(res, 200, issue(c.nonce));
      }
      if (p.get('grant_type') === 'refresh_token') {
        assert.equal(p.get('scope'), 'openid offline_access api://gate/.default');
        if (!f.refreshTokens.delete(p.get('refresh_token'))) return json(res, 400, { error: 'invalid_grant' });
        return json(res, 200, issue());
      }
      return json(res, 400, { error: 'unsupported_grant_type' });
    }
    if (u.pathname === '/mcp') {
      const auth = (req.headers.authorization || '').replace(/^Bearer /, '');
      if (!f.validTokens.has(auth)) return json(res, 401, { reason: 'unauthenticated', message: 'login required' }, { 'WWW-Authenticate': 'Bearer' });
      if (req.method === 'GET') {
        f.getCalls++;
        if (f.getCalls > 1) return json(res, 405, { reason: 'method_not_allowed', message: 'no stream' });
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.end(`data: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/message', params: { level: 'info', data: 'from GET' } })}\n\n`);
        return;
      }
      const msg = JSON.parse(await readBody(req));
      if (f.limited > 0) {
        f.limited--;
        f.mcp.push({ method: msg.method, limited: true });
        return json(res, 429, { reason: 'rate_limited', message: 'too many MCP requests' }, { 'Retry-After': f.retryAfter });
      }
      f.mcp.push({ method: msg.method, auth, session: req.headers['mcp-session-id'], protocol: req.headers['mcp-protocol-version'] });
      if (msg.method === 'initialize') {
        return json(res, 200, { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: msg.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'fake-gate', version: '0' } } }, { 'Mcp-Session-Id': 'sess-1' });
      }
      if (req.headers['mcp-session-id'] !== 'sess-1') return json(res, 400, { reason: 'bad_request', message: 'missing session' });
      if (msg.id === undefined) {
        res.writeHead(202);
        return res.end();
      }
      if (msg.method === 'tools/list') {
        // SSE answer, with a notification first and a multi-line data field.
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.write(`: comment\nevent: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress', params: { progress: 1 } })}\n\n`);
        const result = JSON.stringify({ jsonrpc: '2.0', id: msg.id, result: { tools: [{ name: 'list_zones', inputSchema: { type: 'object' } }] } }, null, 1);
        res.end(result.split('\n').map((l) => `data: ${l}`).join('\r\n') + '\r\n\r\n');
        return;
      }
      if (msg.method === 'tools/call') {
        f.inFlight++;
        f.maxInFlight = Math.max(f.maxInFlight, f.inFlight);
        if (f.callDelay) await new Promise((r) => setTimeout(r, f.callDelay));
        f.inFlight--;
        return json(res, 200, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'zones' }] } });
      }
      return json(res, 200, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } });
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve) =>
    f.server.listen(0, '127.0.0.1', () => {
      f.url = `http://127.0.0.1:${f.server.address().port}`;
      resolve(f);
    }),
  );
}

// startRelay runs relay.js as Claude Desktop would, over stdio.
function startRelay(f, tokenDir, extraEnv = {}, args = [RELAY]) {
  const child = spawn(process.execPath, args, {
    env: {
      PATH: process.env.PATH,
      DNS_GATE_MCP_URL: `${f.url}/mcp`,
      DNS_GATE_ISSUER: f.url,
      DNS_GATE_CLIENT_ID: f.clientID,
      DNS_GATE_SCOPE: 'api://gate/.default',
      DNS_GATE_TOKEN_DIR: tokenDir,
      DNS_GATE_NO_BROWSER: '1',
      ...extraEnv,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const r = { child, messages: [], stderr: '', waiters: [] };
  let out = '';
  const check = () => {
    r.waiters = r.waiters.filter((w) => {
      const m = r.messages.find(w.pred);
      if (m) w.resolve(m);
      return !m;
    });
  };
  child.stdout.on('data', (c) => {
    out += c;
    const lines = out.split('\n');
    out = lines.pop();
    for (const l of lines) if (l.trim()) r.messages.push(JSON.parse(l));
    check();
  });
  child.stderr.on('data', (c) => {
    r.stderr += c;
    check();
  });
  r.send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
  r.wait = (pred, what = 'message') =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`timeout waiting for ${what}; stderr:\n${r.stderr}`)), 10_000);
      r.waiters.push({ pred, resolve: (m) => (clearTimeout(t), resolve(m)) });
      check();
    });
  r.response = (id) => r.wait((m) => m.id === id && !m.method, `response ${id}`);
  r.signInURL = () =>
    new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        clearInterval(poll);
        reject(new Error(`no sign-in URL; stderr:\n${r.stderr}`));
      }, 10_000);
      const poll = setInterval(() => {
        const m = r.stderr.match(/visit (\S+)/);
        if (m) {
          clearTimeout(t);
          clearInterval(poll);
          resolve(m[1]);
        }
      }, 20);
    });
  r.stop = () =>
    new Promise((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) return resolve();
      const kill = setTimeout(() => child.kill(), 2000);
      child.on('exit', () => (clearTimeout(kill), resolve()));
      child.stdin.end();
    });
  return r;
}

// browse plays the user's browser: authorize, then follow the redirect to
// the loopback listener.
async function browse(url) {
  const a = await fetch(url, { redirect: 'manual' });
  assert.equal(a.status, 302);
  const cb = await fetch(a.headers.get('location'));
  return { status: cb.status, text: await cb.text() };
}

const init = (id = 1) => ({ jsonrpc: '2.0', id, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } } });

test('relay', async (t) => {
  const f = await fakeServer();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-relay-'));
  t.after(() => {
    f.server.closeAllConnections();
    f.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const tokenFile = path.join(dir, new URL(f.url).host.replace(/[^A-Za-z0-9.-]/g, '_') + '.json');

  await t.test('signs in lazily with PKCE and forwards JSON and SSE answers with the session', async () => {
    const r = startRelay(f, dir);
    try {
      r.send(init());
      const res = await r.response(1);
      assert.equal(res.result.serverInfo.name, 'dns-gate', 'answered locally before sign-in');
      assert.equal(res.result.capabilities.tools.listChanged, true);
      assert.equal(f.mcp.length, 0, 'no gate call before a request needs it');
      r.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      assert.deepEqual((await r.response(2)).result, { tools: [] }, 'tools/list does not wait for the browser');
      r.send({ jsonrpc: '2.0', id: 3, method: 'prompts/list' });
      assert.deepEqual((await r.response(3)).result, { prompts: [] });
      r.send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'list_zones', arguments: {} } });

      const page = await browse(await r.signInURL());
      assert.equal(page.status, 200);
      assert.match(page.text, /Signed in/);

      await r.wait((m) => m.method === 'notifications/tools/list_changed', 'list_changed');
      const call = await r.response(4);
      assert.equal(call.result.content[0].text, 'zones', 'tools/call waited for the sign-in');
      r.send({ jsonrpc: '2.0', id: 5, method: 'tools/list' });
      const list = await r.response(5);
      assert.equal(list.result.tools[0].name, 'list_zones', 'multi-line SSE data');
      await r.wait((m) => m.method === 'notifications/progress', 'SSE notification');
      await r.wait((m) => m.method === 'notifications/message' && m.params.data === 'from GET', 'GET stream notification');

      assert.deepEqual(f.tokenRequests, ['authorization_code'], 'one sign-in for concurrent requests');
      assert.equal(r.messages.filter((m) => m.method === 'notifications/tools/list_changed').length, 1);
      assert.equal(f.mcp[0].method, 'initialize');
      assert.equal(f.mcp[0].session, undefined);
      assert.equal(f.mcp[1].method, 'notifications/initialized');
      for (const c of f.mcp.slice(1)) {
        assert.equal(c.session, 'sess-1');
        assert.equal(c.protocol, '2025-06-18');
        assert.equal(c.auth, 'at-1');
      }

      const st = fs.statSync(tokenFile);
      if (process.platform !== 'win32') assert.equal(st.mode & 0o777, 0o600);
      const saved = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
      assert.equal(saved.refresh_token, 'rt-1');
      assert.doesNotMatch(r.stderr, /at-1|rt-1|code-/, 'no token in the logs');
    } finally {
      await r.stop();
    }
  });

  await t.test('refreshes silently when the access token expired', async () => {
    const saved = JSON.parse(fs.readFileSync(tokenFile, 'utf8'));
    fs.writeFileSync(tokenFile, JSON.stringify({ ...saved, expires_at: 0 }), { mode: 0o600 });
    f.mcp.length = 0;
    f.tokenRequests.length = 0;
    const r = startRelay(f, dir);
    try {
      r.send(init());
      const res = await r.response(1);
      assert.equal(res.result.serverInfo.name, 'fake-gate', 'initialize forwarded once a token is at hand');
      r.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_zones', arguments: {} } });
      assert.equal((await r.response(2)).result.content[0].text, 'zones');
      r.send({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
      assert.equal((await r.response(3)).result.tools[0].name, 'list_zones', 'tools/list forwarded with a token at hand');
      assert.ok(!r.messages.some((m) => m.method === 'notifications/tools/list_changed'));
      assert.deepEqual(f.tokenRequests, ['refresh_token']);
      assert.equal(JSON.parse(fs.readFileSync(tokenFile, 'utf8')).refresh_token, 'rt-2', 'rotated refresh token kept');
      assert.ok(f.mcp.every((c) => c.auth === 'at-2'));
      assert.doesNotMatch(r.stderr, /visit /, 'no browser');
    } finally {
      await r.stop();
    }
  });

  await t.test('refreshes and retries when the gate refuses the token', async () => {
    f.validTokens.clear();
    f.tokenRequests.length = 0;
    const r = startRelay(f, dir);
    try {
      r.send(init());
      const res = await r.response(1);
      assert.equal(res.result.serverInfo.name, 'fake-gate');
      assert.deepEqual(f.tokenRequests, ['refresh_token']);
    } finally {
      await r.stop();
    }
  });

  await t.test('opens the browser again when the refresh token is refused, and reports a refused sign-in', async () => {
    f.validTokens.clear();
    f.refreshTokens.clear();
    f.authorizeError = 'access_denied';
    const r = startRelay(f, dir);
    try {
      r.send(init());
      assert.equal((await r.response(1)).result.serverInfo.name, 'dns-gate');
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      assert.deepEqual((await r.response(2)).result, { tools: [] });
      r.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_zones', arguments: {} } });
      const page = await browse(await r.signInURL());
      assert.equal(page.status, 400);
      const res = await r.response(3);
      assert.equal(res.error.code, -32001);
      assert.match(res.error.message, /Sign-in to .* failed: access_denied/);
    } finally {
      f.authorizeError = null;
      await r.stop();
    }
  });

  await t.test('times out a sign-in nobody completes', async () => {
    const r = startRelay(f, fs.mkdtempSync(path.join(dir, 'empty-')), { DNS_GATE_LOGIN_TIMEOUT: '1' });
    try {
      r.send(init());
      await r.response(1);
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_zones', arguments: {} } });
      const res = await r.response(2);
      assert.equal(res.error.code, -32001);
      assert.match(res.error.message, /not completed within 1 seconds/);
      r.send({ jsonrpc: '2.0', id: 3, method: 'ping' });
      assert.deepEqual((await r.response(3)).result, {}, 'still alive');
    } finally {
      await r.stop();
    }
  });
});

test('starts when loaded by a host module, as in a Claude Desktop utility process', async () => {
  const f = await fakeServer();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-relay-'));
  const r = startRelay(f, dir, {}, ['-e', `require(${JSON.stringify(RELAY)})`]);
  try {
    r.send(init());
    assert.equal((await r.response(1)).result.serverInfo.name, 'dns-gate');
  } finally {
    await r.stop();
    f.server.closeAllConnections();
    f.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('rejects plain http towards a remote host', async () => {
  const { loadConfig } = require('./relay.js');
  assert.throws(() => loadConfig({ DNS_GATE_MCP_URL: 'http://gate.example.com/mcp', DNS_GATE_ISSUER: 'https://idp.example.com', DNS_GATE_CLIENT_ID: 'x' }), /must use https/);
  const c = loadConfig({ DNS_GATE_MCP_URL: 'https://gate.example.com/mcp', DNS_GATE_ISSUER: 'https://idp.example.com/', DNS_GATE_CLIENT_ID: 'x', DNS_GATE_TOKEN_DIR: '/t' });
  assert.equal(c.scope, 'openid offline_access');
  assert.equal(c.issuer, 'https://idp.example.com');
  assert.equal(c.tokenFile, path.join('/t', 'gate.example.com.json'));
});

// signedIn saves a valid token for f in a new directory, as after a sign-in.
function signedIn(f) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-relay-'));
  f.validTokens.add('at-saved');
  const file = path.join(dir, new URL(f.url).host.replace(/[^A-Za-z0-9.-]/g, '_') + '.json');
  const saved = { issuer: f.url, client_id: f.clientID, scope: 'openid offline_access api://gate/.default', access_token: 'at-saved', expires_at: Date.now() + 3_600_000 };
  fs.writeFileSync(file, JSON.stringify(saved), { mode: 0o600 });
  return dir;
}

test('rate limit of the gate', async (t) => {
  const f = await fakeServer();
  const dirs = [];
  t.after(() => {
    f.server.closeAllConnections();
    f.server.close();
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });
  const relay = () => {
    const d = signedIn(f);
    dirs.push(d);
    return startRelay(f, d);
  };
  const call = (id) => ({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'list_zones', arguments: {} } });

  await t.test('waits for the limit while Claude connects instead of failing the tool list', async () => {
    // Claude Desktop restarted the relay while the agent had emptied the
    // limit: initialize and tools/list must not fail, or Claude gives up on
    // the extension and shows it unavailable.
    f.limited = 1;
    f.retryAfter = '6'; // longer than the wait allowed for initialize
    f.mcp.length = 0;
    const r = relay();
    try {
      const t0 = Date.now();
      r.send(init());
      assert.equal((await r.response(1)).result.serverInfo.name, 'dns-gate', 'initialize answered by the relay');
      assert.ok(Date.now() - t0 < 2000, 'initialize does not wait for the limit');
      r.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      const list = await r.wait((m) => m.id === 2 && !m.method, 'tools/list after the limit');
      assert.equal(list.result.tools[0].name, 'list_zones');
      assert.equal(f.mcp.filter((c) => c.limited).length, 1, 'tools/list waited for Retry-After instead of asking again');
      assert.ok(Date.now() - t0 >= 5900, 'Retry-After respected');
    } finally {
      f.limited = 0;
      f.retryAfter = '1';
      await r.stop();
    }
  });

  await t.test('retries a refused call after Retry-After', async () => {
    const r = relay();
    try {
      r.send(init());
      assert.equal((await r.response(1)).result.serverInfo.name, 'fake-gate');
      f.limited = 2;
      r.send(call(2));
      assert.equal((await r.response(2)).result.content[0].text, 'zones');
    } finally {
      f.limited = 0;
      await r.stop();
    }
  });

  await t.test('fails clearly when the wait exceeds what Claude allows', async () => {
    const r = relay();
    try {
      r.send(init());
      await r.response(1);
      f.limited = 1;
      f.retryAfter = '120';
      const t0 = Date.now();
      r.send(call(2));
      const res = await r.response(2);
      assert.ok(Date.now() - t0 < 2000, 'no pointless wait');
      assert.equal(res.error.code, -32000);
      assert.match(res.error.message, /rate limiting your requests; retry in 120 s/);
      assert.deepEqual(res.error.data, { reason: 'rate_limited', retry_after: 120 });
      f.retryAfter = '1';
      r.send({ jsonrpc: '2.0', id: 3, method: 'ping' });
      assert.deepEqual((await r.response(3)).result, {}, 'still alive');
    } finally {
      f.limited = 0;
      f.retryAfter = '1';
      await r.stop();
    }
  });

  await t.test('bounds the requests in flight in a burst', async () => {
    const r = relay();
    try {
      r.send(init());
      await r.response(1);
      f.callDelay = 50;
      f.maxInFlight = 0;
      for (let i = 0; i < 30; i++) r.send(call(100 + i));
      for (let i = 0; i < 30; i++) assert.equal((await r.response(100 + i)).result.content[0].text, 'zones');
      assert.ok(f.maxInFlight <= 8, `at most 8 calls at once, saw ${f.maxInFlight}`);
      assert.ok(f.maxInFlight > 1, 'calls still run in parallel');
    } finally {
      f.callDelay = 0;
      await r.stop();
    }
  });
});

test('retryAfterMs reads seconds and HTTP dates', () => {
  const { retryAfterMs } = require(RELAY);
  assert.equal(retryAfterMs('10'), 10_000);
  assert.equal(retryAfterMs(null), 1000);
  assert.equal(retryAfterMs('soon'), 1000);
  const now = Date.parse('2026-11-12T10:00:00Z');
  assert.equal(retryAfterMs('Thu, 12 Nov 2026 10:00:05 GMT', now), 5000);
  assert.equal(retryAfterMs('Thu, 12 Nov 2026 09:00:00 GMT', now), 0);
});
