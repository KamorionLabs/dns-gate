// Hash router: #/ (zones), #/zones/<zone>?..., #/journal?..., #/connect, #/teams[/<team>], #/transfers[/<id>]
// Hash routing keeps deep links working without server-side fallbacks.

export type Route =
  | { name: 'zones' }
  | { name: 'zone'; zone: string }
  | { name: 'journal' }
  | { name: 'connect' }
  | { name: 'teams' }
  | { name: 'team'; team: string }
  | { name: 'transfers' }
  | { name: 'transfer'; id: string }
  | { name: 'policy'; tab: 'overview' | 'edit' | 'proposals' | 'simulate' }
  | { name: 'proposal'; id: string };

function parse(hash: string): { route: Route; params: URLSearchParams } {
  const raw = hash.replace(/^#/, '') || '/';
  const [path = '/', qs = ''] = raw.split('?');
  const params = new URLSearchParams(qs);
  const parts = path.split('/').filter(Boolean).map(decodeURIComponent);
  if (parts[0] === 'zones' && parts[1]) return { route: { name: 'zone', zone: parts[1] }, params };
  if (parts[0] === 'journal') return { route: { name: 'journal' }, params };
  if (parts[0] === 'connect') return { route: { name: 'connect' }, params };
  if (parts[0] === 'teams') return { route: parts[1] ? { name: 'team', team: parts[1] } : { name: 'teams' }, params };
  if (parts[0] === 'transfers') return { route: parts[1] ? { name: 'transfer', id: parts[1] } : { name: 'transfers' }, params };
  if (parts[0] === 'policy') {
    if (parts[1] === 'proposals' && parts[2]) return { route: { name: 'proposal', id: parts[2] }, params };
    const tab = parts[1] === 'edit' || parts[1] === 'proposals' || parts[1] === 'simulate' ? parts[1] : 'overview';
    return { route: { name: 'policy', tab }, params };
  }
  return { route: { name: 'zones' }, params };
}

class Router {
  route = $state<Route>({ name: 'zones' });
  params = $state(new URLSearchParams());

  constructor() {
    this.sync();
    window.addEventListener('hashchange', () => this.sync());
  }

  private sync() {
    const { route, params } = parse(window.location.hash);
    this.route = route;
    this.params = params;
  }

  /** Replace query params on the current route without adding history entries. */
  setParams(update: Record<string, string | undefined>, push = false) {
    const next = new URLSearchParams(this.params);
    for (const [k, v] of Object.entries(update)) {
      if (v === undefined || v === '') next.delete(k);
      else next.set(k, v);
    }
    const path = (window.location.hash.replace(/^#/, '').split('?')[0]) || '/';
    const qs = next.toString();
    const url = '#' + path + (qs ? '?' + qs : '');
    if (push) window.location.hash = url;
    else {
      history.replaceState(null, '', url);
      this.sync();
    }
  }
}

export const router = new Router();

export function href(path: string, params?: Record<string, string | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) if (v) p.set(k, v);
  const qs = p.toString();
  return '#' + path + (qs ? '?' + qs : '');
}

export const zoneHref = (zone: string, params?: Record<string, string | undefined>) =>
  href('/zones/' + encodeURIComponent(zone), params);
export const journalHref = (params?: Record<string, string | undefined>) => href('/journal', params);
export const connectHref = (tab?: string) => href('/connect', { tab });
export const policyHref = (tab?: 'edit' | 'proposals' | 'simulate', params?: Record<string, string | undefined>) =>
  href('/policy' + (tab ? '/' + tab : ''), params);
export const proposalHref = (id: string) => href('/policy/proposals/' + encodeURIComponent(id));
export const teamsHref = () => href('/teams');
export const teamHref = (team: string) => href('/teams/' + encodeURIComponent(team));
export const transfersHref = (params?: Record<string, string | undefined>) => href('/transfers', params);
export const transferHref = (id: string) => href('/transfers/' + encodeURIComponent(id));
