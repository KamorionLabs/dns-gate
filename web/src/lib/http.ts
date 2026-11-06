// JSON client of /api/v1, independent of the browser globals so it can be
// tested with a mock fetch.
import type { IssuedToken, PlanResult, RRsetChange, TeamDetail, TeamList, Transfer, TransferPage, TransferProposal, TransferQuery, ValidationError } from './types';

export class ApiError extends Error {
  readonly status: number;
  readonly reason: string;
  readonly errors: ValidationError[];
  readonly details?: unknown;
  constructor(status: number, reason: string, message: string, errors: ValidationError[] = [], details?: unknown) {
    super(message);
    this.status = status;
    this.reason = reason;
    this.errors = errors;
    this.details = details;
  }
}

export type Method = 'GET' | 'POST' | 'PUT' | 'DELETE';

export interface HttpDeps {
  fetch: typeof fetch;
  /** Value of the gate_csrf cookie. */
  csrf: () => string;
  /** 401: sign in again. */
  onUnauthenticated: () => void;
  /** 403 reauth_required: step-up sign-in. */
  onReauth: () => void;
}

export type Request = <T>(method: Method, path: string, body?: unknown, text?: boolean) => Promise<T>;

export function createRequest(deps: HttpDeps): Request {
  return async function request<T>(method: Method, path: string, body?: unknown, text = false): Promise<T> {
    const headers: Record<string, string> = { Accept: text ? 'text/plain' : 'application/json' };
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      headers['X-Gate-CSRF'] = deps.csrf();
    }
    const res = await deps.fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401) {
      deps.onUnauthenticated();
      throw new ApiError(401, 'unauthenticated', 'Redirecting to sign-in');
    }
    if (!res.ok) {
      let reason = 'error';
      let message = res.statusText || `HTTP ${res.status}`;
      let errors: ValidationError[] = [];
      let details: unknown;
      try {
        const b = (await res.json()) as { reason?: string; message?: string; errors?: ValidationError[]; details?: unknown };
        reason = b.reason ?? reason;
        message = b.message ?? message;
        errors = b.errors ?? [];
        details = b.details;
      } catch {
        // non-JSON error body
      }
      if (res.status === 403 && reason === 'reauth_required') deps.onReauth();
      throw new ApiError(res.status, reason, message, errors, details);
    }
    return (text ? await res.text() : await res.json()) as T;
  };
}

/** A gate token for the signed-in browser session (403 session_required for a bearer caller). */
export const issueToken = (request: Request) => request<IssuedToken>('POST', '/api/v1/tokens', {});

const zonePath = (zone: string) => '/api/v1/zones/' + encodeURIComponent(zone);

/**
 * DNS writes: a plan (dry run, returns the diff and a plan_id), then the apply of exactly that plan.
 * team, one of the user's teams, is the team the plan is made for; without it, the default team.
 */
export function dnsWrites(request: Request) {
  // the Go side may send a null list
  const norm = (r: PlanResult): PlanResult => ({ ...r, changes: r.changes ?? [] });
  return {
    plan: (zone: string, changes: RRsetChange[], team?: string) =>
      request<PlanResult>('POST', zonePath(zone) + '/plan', team ? { changes, team } : { changes }).then(norm),
    apply: (zone: string, planId: string, team?: string) =>
      request<PlanResult>('POST', zonePath(zone) + '/apply', team ? { plan_id: planId, team } : { plan_id: planId }).then(norm),
  };
}

function query(q: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== '' && v !== null) p.set(k, String(v));
  }
  const s = p.toString();
  return s ? '?' + s : '';
}

/** Teams and ownership transfers. */
export function teamsApi(request: Request) {
  // the Go side may send null lists
  const normT = (t: Transfer): Transfer => ({ ...t, rrsets: t.rrsets ?? [] });
  const tr = '/api/v1/transfers/';
  return {
    teams: () => request<TeamList>('GET', '/api/v1/teams').then((l) => ({ ...l, teams: (l.teams ?? []).map((t) => ({ ...t, roles: t.roles ?? [] })) })),
    team: (name: string) =>
      request<TeamDetail>('GET', '/api/v1/teams/' + encodeURIComponent(name)).then((d) => ({
        ...d,
        roles: d.roles ?? [],
        owned: d.owned ?? [],
        transfers: (d.transfers ?? []).map(normT),
      })),
    transfers: (q: TransferQuery) =>
      request<TransferPage>('GET', '/api/v1/transfers' + query(q)).then((p) => ({ ...p, transfers: (p.transfers ?? []).map(normT) })),
    transfer: (id: string) => request<Transfer>('GET', tr + encodeURIComponent(id)).then(normT),
    proposeTransfer: (zone: string, req: TransferProposal) => request<Transfer>('POST', zonePath(zone) + '/transfers', req).then(normT),
    decideTransfer: (id: string, approve: boolean, comment: string) =>
      request<Transfer>('POST', tr + encodeURIComponent(id) + (approve ? '/approve' : '/reject'), { comment }).then(normT),
    renameTeam: (team: string, to: string, comment: string) =>
      request<Transfer>('POST', '/api/v1/teams/' + encodeURIComponent(team) + '/rename', { to, comment }).then(normT),
  };
}
