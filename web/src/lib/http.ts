// JSON client of /api/v1, independent of the browser globals so it can be
// tested with a mock fetch.
import type { IssuedToken, PlanResult, RRsetChange, ValidationError } from './types';

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

/** DNS writes: a plan (dry run, returns the diff and a plan_id), then the apply of exactly that plan. */
export function dnsWrites(request: Request) {
  // the Go side may send a null list
  const norm = (r: PlanResult): PlanResult => ({ ...r, changes: r.changes ?? [] });
  return {
    plan: (zone: string, changes: RRsetChange[]) => request<PlanResult>('POST', zonePath(zone) + '/plan', { changes }).then(norm),
    apply: (zone: string, planId: string) => request<PlanResult>('POST', zonePath(zone) + '/apply', { plan_id: planId }).then(norm),
  };
}
