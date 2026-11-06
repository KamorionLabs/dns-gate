import { ApiError, createRequest, dnsWrites, issueToken } from './http';
import type {
  AdoptApply,
  AdoptPreview,
  AdoptResult,
  AdoptSelection,
  AuditPage,
  AuditQuery,
  Connect,
  EffectivePolicy,
  GateInfo,
  ExplainRequest,
  ExplainResponse,
  GeneratedKey,
  IssuedToken,
  Me,
  PlanResult,
  ProposeRequest,
  RevisionDetail,
  RevisionPage,
  RRsetChange,
  TerraformQuery,
  WhoCanResponse,
  ZoneInventory,
  ZoneSummary,
} from './types';

export { ApiError };

export interface Backend {
  me(): Promise<Me>;
  gateInfo(): Promise<GateInfo>;
  connect(): Promise<Connect>;
  zones(): Promise<ZoneSummary[]>;
  inventory(zone: string): Promise<ZoneInventory>;
  audit(q: AuditQuery): Promise<AuditPage>;
  policy(): Promise<EffectivePolicy>;
  revisions(q: { status?: string; limit?: number; cursor?: string }): Promise<RevisionPage>;
  revision(id: string): Promise<RevisionDetail>;
  propose(req: ProposeRequest): Promise<RevisionDetail>;
  approve(id: string, comment: string): Promise<RevisionDetail>;
  reject(id: string, comment: string): Promise<RevisionDetail>;
  activate(id: string): Promise<RevisionDetail>;
  rollback(id: string): Promise<RevisionDetail>;
  explain(req: ExplainRequest): Promise<ExplainResponse>;
  whoCan(q: { zone: string; host: string; type: string; action?: string }): Promise<WhoCanResponse>;
  generateKey(): Promise<GeneratedKey>;
  adoptPreview(zone: string, sel: AdoptSelection): Promise<AdoptPreview>;
  adopt(zone: string, req: AdoptApply): Promise<AdoptResult>;
  terraform(zone: string, q: TerraformQuery): Promise<string>;
  plan(zone: string, changes: RRsetChange[]): Promise<PlanResult>;
  apply(zone: string, planId: string): Promise<PlanResult>;
  issueToken(): Promise<IssuedToken>;
}

export function loginURL(reauth = false): string {
  const back = window.location.pathname + window.location.search + window.location.hash;
  return '/auth/login?' + (reauth ? 'reauth=1&' : '') + 'return_to=' + encodeURIComponent(back);
}

/** Called before a reauth redirect so editors can stash unsaved work. */
const beforeReauth: (() => void)[] = [];
export function onBeforeReauth(fn: () => void): () => void {
  beforeReauth.push(fn);
  return () => {
    const i = beforeReauth.indexOf(fn);
    if (i >= 0) beforeReauth.splice(i, 1);
  };
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)gate_csrf=([^;]+)/);
  return m?.[1] ? decodeURIComponent(m[1]) : '';
}

const request = createRequest({
  fetch: (input, init) => fetch(input, init),
  csrf: csrfToken,
  onUnauthenticated: () => window.location.assign(loginURL()),
  onReauth: () => {
    for (const fn of beforeReauth) fn();
    window.location.assign(loginURL(true));
  },
});
const writes = dnsWrites(request);

function query(q: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== '' && v !== null) p.set(k, String(v));
  }
  const s = p.toString();
  return s ? '?' + s : '';
}

const rev = (id: string) => '/api/v1/policy/revisions/' + encodeURIComponent(id);

const http: Backend = {
  me: () => request('GET', '/api/v1/me'),
  gateInfo: () => request('GET', '/.well-known/dns-gate'),
  connect: () => request('GET', '/api/v1/connect'),
  zones: () => request('GET', '/api/v1/zones'),
  // An alias RRset has no values: the Go side may send null.
  inventory: (zone) =>
    request<ZoneInventory>('GET', `/api/v1/zones/${encodeURIComponent(zone)}/rrsets`).then((z) => ({
      ...z,
      rrsets: (z.rrsets ?? []).map((r) => ({ ...r, values: r.values ?? [] })),
    })),
  audit: (q) => request('GET', '/api/v1/audit' + query(q)),
  policy: () => request('GET', '/api/v1/policy'),
  revisions: (q) => request('GET', '/api/v1/policy/revisions' + query(q)),
  revision: (id) => request('GET', rev(id)),
  propose: (req) => request('POST', '/api/v1/policy/revisions', req),
  approve: (id, comment) => request('POST', rev(id) + '/approve', { comment }),
  reject: (id, comment) => request('POST', rev(id) + '/reject', { comment }),
  activate: (id) => request('POST', rev(id) + '/activate', {}),
  rollback: (id) => request('POST', rev(id) + '/rollback', {}),
  explain: (req) => request('POST', '/api/v1/policy/explain', req),
  whoCan: (q) => request('GET', '/api/v1/policy/who-can' + query(q)),
  generateKey: () => request('POST', '/api/v1/policy/virtual-keys/generate', {}),
  adoptPreview: (zone, sel) => request('POST', `/api/v1/zones/${encodeURIComponent(zone)}/adopt/preview`, sel),
  adopt: (zone, req) => request('POST', `/api/v1/zones/${encodeURIComponent(zone)}/adopt`, req),
  terraform: (zone, q) =>
    request(
      'GET',
      `/api/v1/zones/${encodeURIComponent(zone)}/terraform` +
        query({ team: q.team, hosts: q.hosts?.join(','), types: q.types?.join(',') }),
      undefined,
      true,
    ),
  plan: writes.plan,
  apply: writes.apply,
  issueToken: () => issueToken(request),
};

export const usingFixtures = import.meta.env.VITE_FIXTURES === '1';

let backend: Promise<Backend> = Promise.resolve(http);
if (usingFixtures) {
  backend = import('./fixtures').then((m) => m.fixtureBackend);
}

export const exportURL = (id: string) => rev(id) + '/export';

// Every method forwards to the selected backend (HTTP or fixtures).
export const api = new Proxy({} as Backend, {
  get:
    (_t, name: keyof Backend) =>
    async (...args: unknown[]) => {
      const b = await backend;
      return (b[name] as (...a: unknown[]) => Promise<unknown>)(...args);
    },
});
