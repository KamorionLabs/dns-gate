// URL forwards (HTTP redirects): the RRsets of type URLFWD, their form, its
// validation, and the words that describe a forward and the HTTPS status of
// the forwards of a zone.
import type { Actor, Forward, ForwardMode, HTTPSRedirect, HTTPSStatus, RRset } from './types';
import { displayName, normalizeHost, validateHost } from './records';
import { identityLabel } from './identity';

/** Pseudo type of the URL forward of a host. */
export const URLFWD = 'URLFWD';

export const isForward = (r: { type: string }) => r.type.toUpperCase() === URLFWD;

export const FORWARD_MODES = ['301', '302', 'frame'] as const;
export type KnownMode = (typeof FORWARD_MODES)[number];

export const isKnownMode = (m: string): m is KnownMode => (FORWARD_MODES as readonly string[]).includes(m);

export const modeSpecs: Record<KnownMode, { title: string; help: string }> = {
  '301': {
    title: 'Permanent redirect',
    help: 'Browsers and search engines remember the new address. For a name that moved for good.',
  },
  '302': {
    title: 'Temporary redirect',
    help: 'Visitors are sent to the URL on every visit and nothing is remembered. For campaigns and maintenance pages.',
  },
  frame: {
    title: 'Frame',
    help: 'The address bar keeps this name while a page shows the URL in a frame. Title, keywords and description describe that page.',
  },
};

/** "Permanent redirect (301)", "Temporary redirect (302)", "Frame"; an unknown mode as read. */
export function modeLabel(mode: ForwardMode): string {
  if (mode === 'frame') return modeSpecs.frame.title;
  if (isKnownMode(mode)) return `${modeSpecs[mode].title} (${mode})`;
  return `Unknown (${mode || 'no type'})`;
}

/** A record type for people: URLFWD reads "URL forward". */
export const typeLabel = (t: string) => (t.toUpperCase() === URLFWD ? 'URL forward' : t);

/** One line: "301 → https://www.example.com/". */
export const forwardText = (f: Forward) => `${f.type} → ${f.url}`;

/** The lines of a forward in a diff: the redirect, then the frame fields that are set. */
export function forwardLines(f?: Forward | null): string[] {
  if (!f) return [];
  const out = [forwardText(f)];
  if (f.title) out.push(`title: ${f.title}`);
  if (f.keywords) out.push(`keywords: ${f.keywords}`);
  if (f.description) out.push(`description: ${f.description}`);
  return out;
}

const norm = (f?: Forward | null) =>
  f ? [f.type.toLowerCase(), f.url.trim(), (f.title ?? '').trim(), (f.keywords ?? '').trim(), (f.description ?? '').trim()].join('\n') : '';

/** Whether two forwards are the same (mode, URL and frame fields). */
export const sameForward = (a?: Forward | null, b?: Forward | null) => norm(a) === norm(b);

/** Limits of the gate: frame fields in characters, the URL in bytes. */
export const MAX_TITLE = 200;
export const MAX_KEYWORDS = 500;
export const MAX_DESCRIPTION = 1000;
export const MAX_URL = 2048;

const CONTROL = /[\u0000-\u001f\u007f-\u009f]|\p{Cf}/u;

/** Why a target URL is refused, null when the gate accepts it: an absolute http:// or https:// URL, without user information nor characters to percent-encode. */
export function urlError(raw: string): string | null {
  const s = raw.trim();
  if (!s) return 'The target URL is required';
  if (/\s/.test(s) || CONTROL.test(s)) return 'A URL has no spaces';
  if (new TextEncoder().encode(s).length > MAX_URL) return `A URL has at most ${MAX_URL} bytes`;
  if (!/^https?:\/\//.test(s)) return 'Type the URL in full, starting with https:// or http://';
  if (/[<>"'`\\{}|^]/.test(s)) return 'Percent-encode < > " \' ` \\ { } | ^ in the URL';
  try {
    const u = new URL(s);
    if (!u.hostname) return 'The URL has no host name';
    if (u.username || u.password) return 'The URL must not hold a user name or a password';
  } catch {
    return 'Not a valid URL (for example https://www.example.com/)';
  }
  return null;
}

/** Why a frame field is refused, null when it is plain text within max characters. */
export function textError(label: string, v: string, max: number): string | null {
  if ([...v].length > max) return `${label} has at most ${max} characters`;
  if (CONTROL.test(v) || /[<>"'`]/.test(v)) return `${label} is plain text, without < > " ' \``;
  return null;
}

/** A forward being written in the form. */
export interface ForwardDraft {
  host: string;
  mode: KnownMode;
  url: string;
  title: string;
  keywords: string;
  description: string;
  /** Refuse the change unless the forwards of the zone answer HTTPS (checked, not stored). */
  requireHttps: boolean;
}

export const newForwardDraft = (): ForwardDraft => ({ host: '', mode: '301', url: '', title: '', keywords: '', description: '', requireHttps: false });

export function draftFromForward(host: string, f: Forward | undefined, requireHttps = false): ForwardDraft {
  return {
    host,
    mode: f && isKnownMode(f.type) ? f.type : '301',
    url: f?.url ?? '',
    title: f?.title ?? '',
    keywords: f?.keywords ?? '',
    description: f?.description ?? '',
    requireHttps,
  };
}

/** The forward a draft produces: trimmed, frame fields only on a frame and only when set. */
export function forwardOf(d: ForwardDraft): Forward {
  const f: Forward = { type: d.mode, url: d.url.trim() };
  if (d.mode === 'frame') {
    if (d.title.trim()) f.title = d.title.trim();
    if (d.keywords.trim()) f.keywords = d.keywords.trim();
    if (d.description.trim()) f.description = d.description.trim();
  }
  return f;
}

export interface ForwardCheck {
  host?: string;
  url?: string;
  form: string[];
  ok: boolean;
}

/**
 * Validates a draft. `existing` is every forward of the zone after the staged
 * changes, `editing` the host of the forward being edited.
 */
export function checkForward(d: ForwardDraft, zone: string, existing: { host: string; type: string }[], editing?: string): ForwardCheck {
  const host = normalizeHost(d.host, zone);
  const c: ForwardCheck = { form: [], ok: true };
  const hostErr = d.host.trim() === '' ? 'Type a name, or @ for the zone itself' : validateHost(host);
  if (hostErr) c.host = hostErr;
  const u = urlError(d.url);
  if (u) c.url = u;
  if (!isKnownMode(d.mode)) c.form.push('Choose a permanent redirect, a temporary redirect or a frame');
  if (d.mode === 'frame') {
    for (const [label, v, max] of [['The title', d.title, MAX_TITLE], ['The keywords', d.keywords, MAX_KEYWORDS], ['The description', d.description, MAX_DESCRIPTION]] as const) {
      const e = textError(label, v.trim(), max);
      if (e) c.form.push(e);
    }
  }
  if (!c.host && editing === undefined && existing.some((n) => isForward(n) && n.host === host)) {
    c.form.push(`${displayName(host, zone)} already has a URL forward: a name has one, open it in the list to change it`);
  }
  c.ok = !c.host && !c.url && !c.form.length;
  return c;
}

/** What the form will write, for people: "http://go.example.com/ → 302 → https://…". */
export const forwardPreview = (host: string, zone: string, f: Forward) => `http://${displayName(host, zone)}/  →  ${f.type}  →  ${f.url}`;

/** Whether require_https would pass for this status (undefined: not known, the gate decides). */
export function httpsServes(status?: HTTPSStatus): boolean | undefined {
  if (!status || status === 'unknown') return undefined;
  return status === 'active' || status === 'no_forward';
}

export type Tone = 'ok' | 'warn' | 'muted';

/** The HTTPS status of the forwards of a zone in one sentence; null when the provider has no forwards. */
export function httpsNote(h?: HTTPSRedirect, until?: (iso: string) => string): { tone: Tone; text: string } | null {
  if (!h || h.status === 'unsupported') return null;
  const exp = h.expires_at ? ` until ${until ? until(h.expires_at) : h.expires_at}` : '';
  switch (h.status) {
    case 'active':
      return { tone: 'ok', text: `Forwards answer HTTP and HTTPS: HTTPS redirect subscription active${exp}.` };
    case 'no_forward':
      return { tone: 'ok', text: `HTTPS redirect subscription active${exp}: forwards will answer HTTPS too.` };
    case 'pending':
      return { tone: 'warn', text: 'HTTPS redirect subscription ordered, certificate not issued yet: forwards answer HTTP only for now.' };
    case 'inactive':
      return { tone: 'warn', text: 'Forwards answer HTTP only: no HTTPS redirect subscription on this domain.' };
    default:
      return { tone: 'muted', text: `The HTTPS status of the forwards could not be read${h.message ? ` (${h.message})` : ''}.` };
  }
}

/**
 * Whether the zone shows its URL forwards section: always when it has
 * forwards, otherwise only when its provider has forwards and the zone is
 * managed (where one can be added).
 */
export function forwardsVisible(o: { count: number; provider?: string; https?: HTTPSRedirect; unmanaged?: boolean }): boolean {
  if (o.count > 0) return true;
  if (o.unmanaged || o.provider?.toLowerCase() === 'route53') return false;
  if (o.https) return o.https.status !== 'unsupported';
  return o.provider?.toLowerCase() === 'eurodns';
}

/** The record sets of a zone apart from its forwards. */
export function splitForwards(rrsets: RRset[]): { records: RRset[]; forwards: RRset[] } {
  const records: RRset[] = [];
  const forwards: RRset[] = [];
  for (const r of rrsets) (isForward(r) ? forwards : records).push(r);
  return { records, forwards };
}

/** Forwards matching the search text (host, target, frame fields, owner, actors) and the owner filter. */
export function filterForwards(list: RRset[], q: string, owner = ''): RRset[] {
  const n = q.trim().toLowerCase();
  return list.filter((r) => {
    if (owner && r.owner !== owner) return false;
    if (!n) return true;
    const who = [r.created_by, r.updated_by].flatMap((a?: Actor) => (a ? [a.name, identityLabel(a).label] : []));
    const f = r.forward;
    const hay = [r.host, r.owner ?? '', f?.type ?? '', f?.url ?? '', f?.title ?? '', ...who].join(' ').toLowerCase();
    return hay.includes(n);
  });
}
