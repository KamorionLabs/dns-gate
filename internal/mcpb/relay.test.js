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
      assert.match(redirect, /^http:\/\/localhost:\d+\/callback$/);
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
function startRelay(f, tokenDir, extraEnv = {}) {
  const child = spawn(process.execPath, [RELAY], {
    env: {
      PATH: process.env.PATH,
      EURODNS_GATE_MCP_URL: `${f.url}/mcp`,
      EURODNS_GATE_ISSUER: f.url,
      EURODNS_GATE_CLIENT_ID: f.clientID,
      EURODNS_GATE_SCOPE: 'api://gate/.default',
      EURODNS_GATE_TOKEN_DIR: tokenDir,
      EURODNS_GATE_NO_BROWSER: '1',
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
// the loopback callback.
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
      assert.equal(res.result.serverInfo.name, 'eurodns-gate', 'answered locally before sign-in');
      assert.equal(res.result.capabilities.tools.listChanged, true);
      assert.equal(f.mcp.length, 0, 'no gate call before a request needs it');
      r.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      r.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_zones', arguments: {} } });

      const page = await browse(await r.signInURL());
      assert.equal(page.status, 200);
      assert.match(page.text, /Signed in/);

      const list = await r.response(2);
      assert.equal(list.result.tools[0].name, 'list_zones', 'multi-line SSE data');
      await r.wait((m) => m.method === 'notifications/progress', 'SSE notification');
      await r.wait((m) => m.method === 'notifications/tools/list_changed', 'list_changed');
      const call = await r.response(3);
      assert.equal(call.result.content[0].text, 'zones');
      await r.wait((m) => m.method === 'notifications/message' && m.params.data === 'from GET', 'GET stream notification');

      assert.deepEqual(f.tokenRequests, ['authorization_code'], 'one sign-in for concurrent requests');
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
      assert.equal((await r.response(1)).result.serverInfo.name, 'eurodns-gate');
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      const page = await browse(await r.signInURL());
      assert.equal(page.status, 400);
      const res = await r.response(2);
      assert.equal(res.error.code, -32001);
      assert.match(res.error.message, /Sign-in to .* failed: access_denied/);
    } finally {
      f.authorizeError = null;
      await r.stop();
    }
  });

  await t.test('times out a sign-in nobody completes', async () => {
    const r = startRelay(f, fs.mkdtempSync(path.join(dir, 'empty-')), { EURODNS_GATE_LOGIN_TIMEOUT: '1' });
    try {
      r.send(init());
      await r.response(1);
      r.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
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

test('rejects plain http towards a remote host', async () => {
  const { loadConfig } = require('./relay.js');
  assert.throws(() => loadConfig({ EURODNS_GATE_MCP_URL: 'http://gate.example.com/mcp', EURODNS_GATE_ISSUER: 'https://idp.example.com', EURODNS_GATE_CLIENT_ID: 'x' }), /must use https/);
  const c = loadConfig({ EURODNS_GATE_MCP_URL: 'https://gate.example.com/mcp', EURODNS_GATE_ISSUER: 'https://idp.example.com/', EURODNS_GATE_CLIENT_ID: 'x', EURODNS_GATE_TOKEN_DIR: '/t' });
  assert.equal(c.scope, 'openid offline_access');
  assert.equal(c.issuer, 'https://idp.example.com');
  assert.equal(c.tokenFile, path.join('/t', 'gate.example.com.json'));
});
