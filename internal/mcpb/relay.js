#!/usr/bin/env node
// eurodns-gate relay: a local stdio MCP server that forwards every JSON-RPC
// message to the gate's /mcp endpoint (Streamable HTTP) with an OIDC access
// token of the signed-in user.
//
// Sign-in is the authorization code flow with PKCE (S256), state and nonce,
// through the system browser and a loopback redirect
// (http://localhost:<ephemeral port>/callback). The refresh token is kept in
// ~/.eurodns-gate/<host>.json (0600) and used silently; the browser opens
// again only when it no longer works.
//
// Node.js >= 18, built-in modules only. Nothing is ever written to stdout but
// JSON-RPC messages; diagnostics go to stderr. Tokens are never logged.
//
// Environment (baked into the bundle manifest by the gate):
//   EURODNS_GATE_MCP_URL      MCP endpoint of the gate (required)
//   EURODNS_GATE_ISSUER       OIDC issuer URL (required)
//   EURODNS_GATE_CLIENT_ID    OAuth client id, a public client (required)
//   EURODNS_GATE_SCOPE        extra scopes, e.g. the gate API scope (optional)
//   EURODNS_GATE_TOKEN_DIR    token directory (default ~/.eurodns-gate)
//   EURODNS_GATE_NO_BROWSER   when set, only print the sign-in URL on stderr
//   EURODNS_GATE_LOGIN_TIMEOUT  seconds to wait for the browser sign-in (default 300)
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');

const RELAY_NAME = 'eurodns-gate';
const RELAY_VERSION = '1.0.0';
const DEFAULT_PROTOCOL_VERSION = '2025-06-18';
const HTTP_TIMEOUT_MS = 30_000;
const EXPIRY_MARGIN_MS = 60_000;
const ERR_GATE = -32000;
const ERR_SIGN_IN = -32001;

const log = (...a) => process.stderr.write(`[${RELAY_NAME}] ${a.join(' ')}\n`);

class RelayError extends Error {
  constructor(message, code = ERR_GATE) {
    super(message);
    this.code = code;
  }
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const randomString = (n = 32) => b64url(crypto.randomBytes(n));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest();

function isLoopbackHost(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

// Only HTTPS, except towards the local machine (development and tests).
function checkURL(name, value) {
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopbackHost(u.hostname))) {
    throw new Error(`${name} must use https`);
  }
  return u;
}

function loadConfig(env) {
  for (const k of ['EURODNS_GATE_MCP_URL', 'EURODNS_GATE_ISSUER', 'EURODNS_GATE_CLIENT_ID']) {
    if (!env[k]) throw new Error(`${k} is not set`);
  }
  const mcpURL = checkURL('EURODNS_GATE_MCP_URL', env.EURODNS_GATE_MCP_URL);
  checkURL('EURODNS_GATE_ISSUER', env.EURODNS_GATE_ISSUER);
  const extra = (env.EURODNS_GATE_SCOPE || '').split(/\s+/).filter(Boolean);
  const scope = [...new Set(['openid', 'offline_access', ...extra])].join(' ');
  const timeout = Number(env.EURODNS_GATE_LOGIN_TIMEOUT || 300);
  return {
    mcpURL: mcpURL.href,
    host: mcpURL.host,
    issuer: env.EURODNS_GATE_ISSUER.replace(/\/+$/, ''),
    clientID: env.EURODNS_GATE_CLIENT_ID,
    scope,
    tokenFile: path.join(env.EURODNS_GATE_TOKEN_DIR || path.join(os.homedir(), '.eurodns-gate'), mcpURL.host.replace(/[^A-Za-z0-9.-]/g, '_') + '.json'),
    openBrowser: !env.EURODNS_GATE_NO_BROWSER,
    loginTimeoutMs: (Number.isFinite(timeout) && timeout > 0 ? timeout : 300) * 1000,
  };
}

// TokenStore keeps the tokens of one gate in a file readable by the user only.
class TokenStore {
  constructor(file) {
    this.file = file;
  }

  load() {
    try {
      return JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch {
      return null;
    }
  }

  save(data) {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, this.file);
  }
}

async function readJSON(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

const formBody = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== undefined && v !== ''));

function oauthError(body, status) {
  return body.error ? body.error + (body.error_description ? `: ${String(body.error_description).split('\n')[0]}` : '') : `HTTP ${status}`;
}

function decodeJWTPayload(jwt) {
  try {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function page(title, text) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escapeHTML(title)}</title></head><body style="font-family:system-ui,sans-serif;max-width:36em;margin:4em auto;line-height:1.5"><h1 style="font-size:1.4em">${escapeHTML(title)}</h1><p>${escapeHTML(text)}</p></body></html>`;
}

function openInBrowser(url) {
  let cmd;
  let args;
  if (process.platform === 'darwin') {
    [cmd, args] = ['open', [url]];
  } else if (process.platform === 'win32') {
    // rundll32 passes the URL untouched, unlike "cmd /c start" which
    // interprets & and % in the query string.
    [cmd, args] = ['rundll32', ['url.dll,FileProtocolHandler', url]];
  } else {
    [cmd, args] = ['xdg-open', [url]];
  }
  try {
    const child = spawn(cmd, args, { stdio: 'ignore', detached: true });
    child.on('error', (e) => log(`could not open the browser (${e.code || e.message}); open the sign-in URL above by hand`));
    child.unref();
  } catch (e) {
    log(`could not open the browser (${e.message}); open the sign-in URL above by hand`);
  }
}

// Auth obtains and refreshes the access token sent to the gate.
class Auth {
  constructor(cfg) {
    this.cfg = cfg;
    this.store = new TokenStore(cfg.tokenFile);
    this.meta = null;
    this.pending = null;
    this.rejected = new Set(); // access tokens the gate refused
  }

  async discover() {
    if (!this.meta) {
      this.meta = (async () => {
        const res = await fetch(`${this.cfg.issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`OpenID discovery failed (HTTP ${res.status})`);
        const meta = await res.json();
        if (!meta.authorization_endpoint || !meta.token_endpoint) throw new Error('OpenID discovery: missing endpoints');
        checkURL('authorization_endpoint', meta.authorization_endpoint);
        checkURL('token_endpoint', meta.token_endpoint);
        return meta;
      })();
      this.meta.catch(() => (this.meta = null));
    }
    return this.meta;
  }

  // token returns an access token, or null when one cannot be had without
  // the browser and interactive is false. Concurrent callers share one
  // acquisition, so a single browser sign-in happens at a time.
  async token(interactive) {
    for (;;) {
      const p = this.pending;
      if (!p) break;
      let t = null;
      try {
        t = await p.promise;
      } catch (e) {
        if (p.interactive) throw e;
      }
      if (t || !interactive || p.interactive) return t;
      if (this.pending === p) this.pending = null;
    }
    const p = { interactive, promise: this.acquire(interactive) };
    this.pending = p;
    p.promise.then(
      () => this.pending === p && (this.pending = null),
      () => this.pending === p && (this.pending = null),
    );
    return p.promise;
  }

  // reject marks an access token as refused by the gate.
  reject(token) {
    this.rejected.add(token);
  }

  stored() {
    const s = this.store.load();
    const c = this.cfg;
    return s && s.issuer === c.issuer && s.client_id === c.clientID && s.scope === c.scope ? s : null;
  }

  async acquire(interactive) {
    const s = this.stored();
    if (s && s.access_token && !this.rejected.has(s.access_token) && s.expires_at - EXPIRY_MARGIN_MS > Date.now()) {
      return s.access_token;
    }
    if (s && s.refresh_token) {
      const t = await this.refresh(s);
      if (t) return t;
    }
    if (!interactive) return null;
    return this.login();
  }

  save(tok, previous) {
    const c = this.cfg;
    this.store.save({
      issuer: c.issuer,
      client_id: c.clientID,
      scope: c.scope,
      access_token: tok.access_token,
      expires_at: Date.now() + (Number(tok.expires_in) > 0 ? Number(tok.expires_in) : 300) * 1000,
      refresh_token: tok.refresh_token || (previous && previous.refresh_token) || undefined,
    });
  }

  // refresh returns null when the identity provider refuses the refresh
  // token, and throws when it cannot be reached: no browser for an outage.
  async refresh(s) {
    let res;
    let body;
    try {
      const meta = await this.discover();
      res = await fetch(meta.token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: formBody({ grant_type: 'refresh_token', refresh_token: s.refresh_token, client_id: this.cfg.clientID, scope: this.cfg.scope }),
        signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
      });
      body = await readJSON(res);
    } catch (e) {
      throw new RelayError(`cannot reach the identity provider (${(e.cause && e.cause.code) || e.message})`);
    }
    if (res.status >= 500) throw new RelayError(`the identity provider answered ${res.status}`);
    if (!res.ok || !body.access_token) {
      log(`token refresh refused (${oauthError(body, res.status)}), a new sign-in is needed`);
      this.store.save({ ...s, access_token: undefined, refresh_token: undefined });
      return null;
    }
    this.save(body, s);
    return body.access_token;
  }

  async login() {
    const meta = await this.discover();
    const verifier = randomString(32);
    const state = randomString(16);
    const nonce = randomString(16);
    const loop = await startLoopback();
    const redirectURI = `http://localhost:${loop.port}/callback`;
    const auth = new URL(meta.authorization_endpoint);
    const q = auth.searchParams;
    q.set('response_type', 'code');
    q.set('client_id', this.cfg.clientID);
    q.set('redirect_uri', redirectURI);
    q.set('scope', this.cfg.scope);
    q.set('state', state);
    q.set('nonce', nonce);
    q.set('code_challenge', b64url(sha256(verifier)));
    q.set('code_challenge_method', 'S256');
    log(`sign-in to ${this.cfg.host} needed: opening the browser. If it does not open, visit ${auth.href}`);
    if (this.cfg.openBrowser) openInBrowser(auth.href);

    let timer;
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new RelayError(`the browser sign-in was not completed within ${Math.round(this.cfg.loginTimeoutMs / 1000)} seconds`, ERR_SIGN_IN)), this.cfg.loginTimeoutMs);
    });
    const done = new Promise((resolve, reject) => {
      loop.onCallback = async (params, respond) => {
        if (params.get('state') !== state) {
          respond(400, page('Sign-in failed', 'This sign-in link is stale. Go back to Claude and try again.'));
          return;
        }
        if (params.get('error')) {
          const err = params.get('error') + (params.get('error_description') ? `: ${params.get('error_description').split('\n')[0]}` : '');
          respond(400, page('Sign-in failed', `${err}. You can close this tab.`));
          reject(new RelayError(err, ERR_SIGN_IN));
          return;
        }
        try {
          const tok = await this.exchange(meta, params.get('code'), redirectURI, verifier, nonce);
          respond(200, page('Signed in', `Claude is now connected to ${this.cfg.host}. You can close this tab and go back to Claude.`));
          resolve(tok);
        } catch (e) {
          respond(400, page('Sign-in failed', `${e.message}. You can close this tab and try again from Claude.`));
          reject(e);
        }
      };
    });
    done.catch(() => {});
    try {
      const tok = await Promise.race([done, timeout]);
      this.save(tok, null);
      this.rejected.clear();
      log(`signed in to ${this.cfg.host}`);
      return tok.access_token;
    } finally {
      clearTimeout(timer);
      loop.close();
    }
  }

  async exchange(meta, code, redirectURI, verifier, nonce) {
    if (!code) throw new RelayError('no authorization code in the redirect', ERR_SIGN_IN);
    const res = await fetch(meta.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: formBody({ grant_type: 'authorization_code', code, redirect_uri: redirectURI, client_id: this.cfg.clientID, code_verifier: verifier }),
      signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
    });
    const body = await readJSON(res);
    if (!res.ok || !body.access_token) throw new RelayError(`token request refused (${oauthError(body, res.status)})`, ERR_SIGN_IN);
    if (body.id_token) {
      const claims = decodeJWTPayload(body.id_token);
      if (!claims || claims.nonce !== nonce) throw new RelayError('the ID token nonce does not match', ERR_SIGN_IN);
    }
    return body;
  }
}

// startLoopback listens on an ephemeral port of 127.0.0.1 and, on the same
// port, ::1 when available, since browsers may resolve localhost to either.
function startLoopback() {
  const loop = { port: 0, onCallback: null, servers: [] };
  const handler = (req, res) => {
    const u = new URL(req.url, 'http://localhost');
    const respond = (status, html) => {
      res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(html);
    };
    if (req.method !== 'GET' || u.pathname !== '/callback' || !loop.onCallback) {
      respond(404, page('Not found', 'Nothing here.'));
      return;
    }
    loop.onCallback(u.searchParams, respond);
  };
  loop.close = () => loop.servers.forEach((s) => s.close());
  return new Promise((resolve, reject) => {
    const v4 = http.createServer(handler);
    v4.on('error', reject);
    v4.listen(0, '127.0.0.1', () => {
      loop.port = v4.address().port;
      loop.servers.push(v4);
      const v6 = http.createServer(handler);
      v6.on('error', () => resolve(loop));
      v6.listen(loop.port, '::1', () => {
        loop.servers.push(v6);
        resolve(loop);
      });
    });
  });
}

// parseSSE yields the data of each server-sent event of a response body.
async function* parseSSE(body) {
  const decoder = new TextDecoder();
  let buf = '';
  let data = [];
  for await (const chunk of body) {
    buf += decoder.decode(chunk, { stream: true });
    const lines = buf.split(/\r\n|\r|\n/);
    buf = lines.pop();
    for (const line of lines) {
      if (line === '') {
        if (data.length) yield data.join('\n');
        data = [];
      } else if (line.startsWith('data:')) {
        data.push(line.slice(line[5] === ' ' ? 6 : 5));
      }
    }
  }
  if (data.length) yield data.join('\n');
}

function gateMessage(text, status) {
  try {
    const b = JSON.parse(text);
    if (b && (b.message || b.reason)) return `${b.message || b.reason}${b.reason && b.message ? ` (${b.reason})` : ''}`;
  } catch {
    // not JSON
  }
  return `HTTP ${status}`;
}

// Relay bridges the stdio client and the gate.
class Relay {
  constructor(cfg, auth, write) {
    this.cfg = cfg;
    this.auth = auth;
    this.write = write;
    this.sessionID = null;
    this.protocolVersion = null;
    this.initParams = null;
    this.initialized = false; // upstream session initialized
    this.initializing = null;
    this.localInit = false; // initialize was answered by the relay
    this.listChangedSent = false;
    this.listening = false;
    this.closed = false;
  }

  reply(id, result) {
    this.write({ jsonrpc: '2.0', id, result });
  }

  fail(id, e) {
    if (id === undefined) return;
    const code = e instanceof RelayError ? e.code : ERR_GATE;
    const message =
      code === ERR_SIGN_IN
        ? `Sign-in to ${this.cfg.host} failed: ${e.message}. Ask again to restart the sign-in.`
        : `eurodns-gate (${this.cfg.host}): ${e.message}`;
    this.write({ jsonrpc: '2.0', id, error: { code, message } });
  }

  async handle(msg) {
    if (Array.isArray(msg)) {
      await Promise.all(msg.map((m) => this.handle(m)));
      return;
    }
    if (!msg || typeof msg !== 'object') {
      this.write({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } });
      return;
    }
    const isRequest = typeof msg.method === 'string' && msg.id !== undefined;
    if (isRequest && msg.method === 'initialize') return this.initialize(msg);
    if (isRequest && msg.method === 'ping') return this.reply(msg.id, {});
    if (msg.method === 'notifications/initialized') {
      if (this.initialized && !this.localInit) await this.forward(msg, false).catch(() => {});
      return;
    }
    if (!isRequest) {
      // Notifications and responses only matter to an existing session.
      if (this.initialized) await this.forward(msg, false).catch((e) => log(`forward failed: ${e.message}`));
      return;
    }
    try {
      await this.forward(msg, true);
    } catch (e) {
      this.fail(msg.id, e);
    }
  }

  // initialize goes to the gate when a token is available without the
  // browser; otherwise the relay answers itself and signs in on the first
  // request that needs the gate, so Claude never waits on a browser here.
  async initialize(msg) {
    this.initParams = msg.params || {};
    this.initialized = false;
    this.sessionID = null;
    let token = null;
    try {
      token = await this.auth.token(false);
    } catch {
      token = null;
    }
    if (token) {
      try {
        const res = await this.upstreamInit(false);
        this.localInit = false;
        this.write({ ...res, id: msg.id });
        return;
      } catch (e) {
        if (e.rpc) {
          this.write({ ...e.rpc, id: msg.id });
          return;
        }
        log(`gate not reachable yet (${e.message}), will retry on the next request`);
      }
    }
    this.localInit = true;
    this.reply(msg.id, {
      protocolVersion: this.initParams.protocolVersion || DEFAULT_PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: true } },
      serverInfo: { name: RELAY_NAME, version: RELAY_VERSION },
      instructions: `Tools of the EuroDNS gate at ${this.cfg.host}. The first use opens the browser once to sign in.`,
    });
  }

  // upstreamInit opens the session with the gate using the client's
  // initialize parameters. internal: the client's notifications/initialized
  // was already consumed, so the relay sends its own.
  upstreamInit(internal) {
    if (!this.initializing) {
      this.initializing = (async () => {
        const id = `relay-init-${randomString(8)}`;
        const params = this.initParams || { protocolVersion: DEFAULT_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: RELAY_NAME, version: RELAY_VERSION } };
        const res = await this.post({ jsonrpc: '2.0', id, method: 'initialize', params }, { capture: id, interactive: false });
        if (!res) throw new RelayError('the gate did not answer initialize');
        if (res.error) {
          const e = new RelayError(res.error.message || 'initialize refused');
          e.rpc = res;
          throw e;
        }
        this.protocolVersion = (res.result && res.result.protocolVersion) || params.protocolVersion || null;
        this.initialized = true;
        if (internal) await this.post({ jsonrpc: '2.0', method: 'notifications/initialized' }, { interactive: false });
        this.listen();
        return res;
      })();
      this.initializing.then(
        () => (this.initializing = null),
        () => (this.initializing = null),
      );
    }
    return this.initializing;
  }

  async ensureSession(interactive) {
    const token = await this.auth.token(interactive);
    if (!token) throw new RelayError('not signed in', ERR_SIGN_IN);
    if (!this.initialized) await this.upstreamInit(true);
    if (this.localInit && !this.listChangedSent) {
      // Claude may have given up on tools/list while the user was signing
      // in: tell it the tools are there now.
      this.listChangedSent = true;
      setImmediate(() => this.write({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' }));
    }
  }

  async forward(msg, interactive) {
    await this.ensureSession(interactive);
    await this.post(msg, { interactive });
  }

  headers(token, accept) {
    const h = { Authorization: `Bearer ${token}`, Accept: accept, 'User-Agent': `${RELAY_NAME}-relay/${RELAY_VERSION}` };
    if (this.sessionID) h['Mcp-Session-Id'] = this.sessionID;
    if (this.protocolVersion) h['MCP-Protocol-Version'] = this.protocolVersion;
    return h;
  }

  // post sends one message to the gate and writes what comes back to the
  // client, except the response to opts.capture, which is returned.
  async post(msg, opts) {
    const token = await this.auth.token(opts.interactive);
    if (!token) throw new RelayError('not signed in', ERR_SIGN_IN);
    let res;
    try {
      res = await fetch(this.cfg.mcpURL, {
        method: 'POST',
        headers: { ...this.headers(token, 'application/json, text/event-stream'), 'Content-Type': 'application/json' },
        body: JSON.stringify(msg),
      });
    } catch (e) {
      throw new RelayError(`cannot reach the gate (${(e.cause && e.cause.code) || e.message})`);
    }
    const sid = res.headers.get('mcp-session-id');
    if (sid) this.sessionID = sid;
    if (res.status === 401 && !opts.retried) {
      await res.body?.cancel();
      this.auth.reject(token);
      return this.post(msg, { ...opts, retried: true });
    }
    if (res.status === 404 && this.sessionID && !sid && !this.initializing && !opts.retried) {
      // The session is gone: open a new one and send again.
      await res.body?.cancel();
      this.sessionID = null;
      this.initialized = false;
      await this.upstreamInit(true);
      return this.post(msg, { ...opts, retried: true });
    }
    if (res.status === 202 || res.status === 204) {
      await res.body?.cancel();
      return null;
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      const code = res.status === 401 ? ERR_SIGN_IN : ERR_GATE;
      throw new RelayError(`the gate answered ${res.status}: ${gateMessage(text, res.status)}`, code);
    }
    const target = opts.capture || msg.id;
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (ct.startsWith('text/event-stream')) return this.readSSE(res.body, target, opts.capture);
    const text = await res.text();
    if (!text.trim()) return null;
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new RelayError('the gate sent an invalid JSON response');
    }
    let captured = null;
    for (const m of Array.isArray(body) ? body : [body]) {
      if (opts.capture && m && m.id === opts.capture && !m.method) captured = m;
      else this.write(m);
    }
    return captured;
  }

  async readSSE(body, target, capture) {
    let captured = null;
    for await (const data of parseSSE(body)) {
      let m;
      try {
        m = JSON.parse(data);
      } catch {
        log('ignored a non-JSON event from the gate');
        continue;
      }
      const isTarget = target !== undefined && m && !m.method && m.id === target;
      if (capture && isTarget) captured = m;
      else this.write(m);
      if (isTarget) break; // the response ends the exchange
    }
    return captured;
  }

  // listen opens the optional GET stream for messages the gate sends on its
  // own. A gate that does not offer it (405) is left alone.
  async listen() {
    if (this.listening) return;
    this.listening = true;
    let delay = 1000;
    try {
      while (!this.closed && this.initialized) {
        const token = await this.auth.token(false).catch(() => null);
        if (!token) return;
        let res;
        try {
          res = await fetch(this.cfg.mcpURL, { method: 'GET', headers: this.headers(token, 'text/event-stream') });
        } catch {
          await new Promise((r) => setTimeout(r, delay).unref());
          delay = Math.min(delay * 2, 60_000);
          continue;
        }
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!res.ok || !ct.startsWith('text/event-stream')) {
          await res.body?.cancel();
          return;
        }
        delay = 1000;
        try {
          await this.readSSE(res.body);
        } catch {
          // stream cut: reconnect
        }
        await new Promise((r) => setTimeout(r, delay).unref());
      }
    } finally {
      this.listening = false;
    }
  }
}

function main() {
  let cfg;
  try {
    cfg = loadConfig(process.env);
  } catch (e) {
    log(`configuration error: ${e.message}`);
    process.exit(1);
  }
  const write = (m) => process.stdout.write(JSON.stringify(m) + '\n');
  const relay = new Relay(cfg, new Auth(cfg), write);
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
      return;
    }
    relay.handle(msg).catch((e) => log(`unexpected error: ${e.message}`));
  });
  rl.on('close', () => {
    relay.closed = true;
    process.exit(0);
  });
  log(`relay ${RELAY_VERSION} for ${cfg.mcpURL}`);
}

if (require.main === module) main();

module.exports = { loadConfig, parseSSE, Relay, Auth };
