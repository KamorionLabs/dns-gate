// Record forms in plain words: one set of fields per record type, the
// values they produce (zone-file presentation format), and their validation.
import type { RRset } from './types';

export const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

export const isRecordType = (t: string): t is RecordType => (RECORD_TYPES as readonly string[]).includes(t);

export interface FieldSpec {
  key: string;
  label: string;
  placeholder?: string;
  options?: string[];
  narrow?: boolean;
}

export interface TypeSpec {
  /** What the type is for, in a few words. */
  title: string;
  help: string;
  fields: FieldSpec[];
  /** Only one value is allowed (CNAME). */
  single?: boolean;
  /** Label of one value, for "Add another …". */
  noun: string;
}

export const typeSpecs: Record<RecordType, TypeSpec> = {
  A: {
    title: 'IPv4 address',
    help: 'Sends the name to a server by its IPv4 address. Several addresses share the traffic.',
    fields: [{ key: 'address', label: 'IPv4 address', placeholder: '203.0.113.10' }],
    noun: 'address',
  },
  AAAA: {
    title: 'IPv6 address',
    help: 'Sends the name to a server by its IPv6 address.',
    fields: [{ key: 'address', label: 'IPv6 address', placeholder: '2001:db8::10' }],
    noun: 'address',
  },
  CNAME: {
    title: 'Alias of another name',
    help: 'Makes the name an alias of another name (a load balancer, a CDN, a SaaS). It must be the only record at this name.',
    fields: [{ key: 'target', label: 'Target name', placeholder: 'app.example.net' }],
    single: true,
    noun: 'target',
  },
  TXT: {
    title: 'Text',
    help: 'Free text read by other services: domain verification, SPF, DKIM, DMARC. Type the text without quotes.',
    fields: [{ key: 'text', label: 'Text', placeholder: 'v=spf1 include:_spf.example.net -all' }],
    noun: 'text',
  },
  MX: {
    title: 'Mail server',
    help: 'Where mail for this name is delivered. The lowest priority is tried first.',
    fields: [
      { key: 'priority', label: 'Priority', placeholder: '10', narrow: true },
      { key: 'server', label: 'Mail server', placeholder: 'mx1.example.net' },
    ],
    noun: 'mail server',
  },
  SRV: {
    title: 'Service location',
    help: 'Where a service (SIP, XMPP, LDAP…) runs. The name usually looks like _service._tcp.',
    fields: [
      { key: 'priority', label: 'Priority', placeholder: '10', narrow: true },
      { key: 'weight', label: 'Weight', placeholder: '5', narrow: true },
      { key: 'port', label: 'Port', placeholder: '5060', narrow: true },
      { key: 'target', label: 'Server', placeholder: 'sip.example.net' },
    ],
    noun: 'server',
  },
  CAA: {
    title: 'Allowed certificate authority',
    help: 'Which certificate authorities may issue certificates for this name.',
    fields: [
      { key: 'flags', label: 'Flags', placeholder: '0', narrow: true },
      { key: 'tag', label: 'Kind', options: ['issue', 'issuewild', 'iodef'] },
      { key: 'value', label: 'Authority', placeholder: 'letsencrypt.org' },
    ],
    noun: 'authority',
  },
};

export type ValueFields = Record<string, string>;

export const emptyValue = (type: RecordType): ValueFields =>
  Object.fromEntries(typeSpecs[type].fields.map((f) => [f.key, f.key === 'tag' ? 'issue' : f.key === 'flags' ? '0' : '']));

/** Quoted strings of a TXT or CAA value: "a" "b" → ['a', 'b']; an unquoted value is one string. */
export function unquote(raw: string): string[] {
  const s = raw.trim();
  if (!s.startsWith('"')) return [s];
  const out: string[] = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') {
      i++;
      continue;
    }
    let cur = '';
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) i++;
      cur += s[i];
      i++;
    }
    out.push(cur);
    i++;
  }
  return out;
}

const quote = (s: string) => '"' + s.replaceAll('\\', '\\\\').replaceAll('"', '\\"') + '"';

/** A TXT value in presentation format: quoted, split in strings of 255 characters at most. */
export function txtValue(text: string): string {
  const chunks: string[] = [];
  for (let i = 0; i < text.length; i += 255) chunks.push(text.slice(i, i + 255));
  return (chunks.length ? chunks : ['']).map(quote).join(' ');
}

/** Absolute name with its trailing dot: "app.example.net" → "app.example.net.". */
export const absolute = (name: string) => {
  const n = name.trim().toLowerCase();
  return n === '' || n.endsWith('.') ? n : n + '.';
};

const words = (raw: string) => raw.trim().split(/\s+/);

/** Fields of an existing value, for editing. */
export function parseValue(type: RecordType, raw: string): ValueFields {
  const w = words(raw);
  switch (type) {
    case 'A':
    case 'AAAA':
      return { address: raw.trim() };
    case 'CNAME':
      return { target: raw.trim() };
    case 'TXT':
      return { text: unquote(raw).join('') };
    case 'MX':
      return { priority: w[0] ?? '', server: w[1] ?? '' };
    case 'SRV':
      return { priority: w[0] ?? '', weight: w[1] ?? '', port: w[2] ?? '', target: w[3] ?? '' };
    case 'CAA': {
      const m = raw.trim().match(/^(\d+)\s+(\S+)\s+(.*)$/);
      return m ? { flags: m[1]!, tag: m[2]!, value: unquote(m[3]!).join('') } : { flags: '0', tag: 'issue', value: raw.trim() };
    }
  }
}

/** The value a set of fields produces. */
export function serializeValue(type: RecordType, f: ValueFields): string {
  const v = (k: string) => (f[k] ?? '').trim();
  switch (type) {
    case 'A':
    case 'AAAA':
      return v('address').toLowerCase();
    case 'CNAME':
      return absolute(v('target'));
    case 'TXT':
      return txtValue(f.text ?? '');
    case 'MX':
      return `${v('priority')} ${absolute(v('server'))}`;
    case 'SRV':
      return `${v('priority')} ${v('weight')} ${v('port')} ${absolute(v('target'))}`;
    case 'CAA':
      return `${v('flags')} ${v('tag')} ${quote(v('value'))}`;
  }
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export function isIPv4(s: string): boolean {
  return IPV4.test(s);
}

export function isIPv6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.split('::').length > 2) return false;
  let groups = s.split(':');
  const last = groups[groups.length - 1] ?? '';
  let max = 8;
  if (last.includes('.')) {
    if (!isIPv4(last)) return false;
    groups = groups.slice(0, -1);
    max = 6;
  }
  const filled = groups.filter((g) => g !== '');
  if (filled.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false;
  return s.includes('::') ? filled.length < max : filled.length === max;
}

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/i;

/** A full host name: labels of letters, digits, hyphens and underscores, optional trailing dot. */
export function isHostname(s: string): boolean {
  const n = s.trim().replace(/\.$/, '');
  if (!n || n.length > 253) return false;
  return n.split('.').every((l) => LABEL.test(l));
}

const isInt = (s: string, min: number, max: number) => /^\d+$/.test(s) && Number(s) >= min && Number(s) <= max;

/** Errors of one value, by field key. */
export function validateValue(type: RecordType, f: ValueFields): Record<string, string> {
  const e: Record<string, string> = {};
  const v = (k: string) => (f[k] ?? '').trim();
  const need = (k: string, label: string) => {
    if (!v(k)) e[k] = `${label} is required`;
    return !!v(k);
  };
  const name = (k: string, label: string) => {
    if (!need(k, label)) return;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v(k))) e[k] = `${label} must be a name, not an IP address`;
    else if (!isHostname(v(k))) e[k] = `${label} is not a valid name (letters, digits, hyphens, dots)`;
  };
  const number = (k: string, label: string, max: number) => {
    if (need(k, label) && !isInt(v(k), 0, max)) e[k] = `${label} is a number from 0 to ${max}`;
  };
  switch (type) {
    case 'A':
      if (need('address', 'The address') && !isIPv4(v('address'))) e.address = 'Not an IPv4 address (for example 203.0.113.10)';
      break;
    case 'AAAA':
      if (need('address', 'The address') && !isIPv6(v('address'))) e.address = 'Not an IPv6 address (for example 2001:db8::10)';
      break;
    case 'CNAME':
      name('target', 'The target');
      break;
    case 'TXT':
      if (!(f.text ?? '').length) e.text = 'The text is required';
      else if ((f.text ?? '').length > 4000) e.text = 'The text is too long (4000 characters at most)';
      break;
    case 'MX':
      number('priority', 'Priority', 65535);
      name('server', 'The mail server');
      break;
    case 'SRV':
      number('priority', 'Priority', 65535);
      number('weight', 'Weight', 65535);
      if (need('port', 'Port') && !isInt(v('port'), 1, 65535)) e.port = 'Port is a number from 1 to 65535';
      name('target', 'The server');
      break;
    case 'CAA':
      number('flags', 'Flags', 255);
      if (!['issue', 'issuewild', 'iodef'].includes(v('tag'))) e.tag = 'Choose issue, issuewild or iodef';
      need('value', 'The authority');
      break;
  }
  return e;
}

/** Host relative to the zone as the gate stores it: lowercase, no trailing dot, "@" for the apex. */
export function normalizeHost(input: string, zone: string): string {
  const h = input.trim().toLowerCase().replace(/\.$/, '');
  const z = zone.toLowerCase().replace(/\.$/, '');
  if (h === '' || h === '@' || h === z) return '@';
  return h.endsWith('.' + z) ? h.slice(0, -(z.length + 1)) : h;
}

export function validateHost(host: string): string | null {
  if (host === '@') return null;
  const labels = host.split('.');
  if (labels.some((l, i) => (l === '*' ? i !== 0 : !LABEL.test(l)))) return 'Use letters, digits, hyphens and underscores, labels separated by dots ("*" only first)';
  if (host.length > 200) return 'The name is too long';
  return null;
}

export const TTL_PRESETS: { seconds: number; label: string }[] = [
  { seconds: 60, label: '1 minute' },
  { seconds: 300, label: '5 minutes' },
  { seconds: 600, label: '10 minutes' },
  { seconds: 3600, label: '1 hour' },
  { seconds: 86400, label: '1 day' },
];

export function validateTTL(ttl: number): string | null {
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 604800) return 'The TTL is a number of seconds from 1 to 604800 (7 days)';
  return null;
}

/** A record set being written in the form. */
export interface RecordDraft {
  host: string;
  type: RecordType;
  ttl: number;
  values: ValueFields[];
}

export const newDraft = (type: RecordType = 'A'): RecordDraft => ({ host: '', type, ttl: 3600, values: [emptyValue(type)] });

export function draftFromRRset(rr: RRset): RecordDraft {
  const type = rr.type as RecordType;
  return { host: rr.host, type, ttl: rr.ttl, values: rr.values.length ? rr.values.map((v) => parseValue(type, v)) : [emptyValue(type)] };
}

/** The values of a draft, in order, duplicates kept (validation reports them). */
export const draftValues = (d: RecordDraft) => d.values.map((f) => serializeValue(d.type, f));

export interface DraftCheck {
  host?: string;
  ttl?: string;
  /** Errors of each value, by field key. */
  values: Record<string, string>[];
  /** Errors about the record set as a whole. */
  form: string[];
  ok: boolean;
}

/** Another record set at a name, for the CNAME exclusivity rule. */
export interface Neighbour {
  host: string;
  type: string;
}

/**
 * Validates a draft. `existing` is every record set of the zone (after the
 * staged changes), `editing` the key of the record set being edited.
 */
export function checkDraft(d: RecordDraft, zone: string, existing: Neighbour[], editing?: Neighbour): DraftCheck {
  const host = normalizeHost(d.host, zone);
  const c: DraftCheck = { values: d.values.map((v) => validateValue(d.type, v)), form: [], ok: true };
  const hostErr = d.host.trim() === '' ? 'Type a name, or @ for the zone itself' : validateHost(host);
  if (hostErr) c.host = hostErr;
  const ttlErr = validateTTL(d.ttl);
  if (ttlErr) c.ttl = ttlErr;
  if (!d.values.length) c.form.push('Add at least one value');
  const spec = typeSpecs[d.type];
  if (spec.single && d.values.length > 1) c.form.push(`A ${d.type} record set has a single ${spec.noun}`);
  if (d.type === 'CNAME' && host === '@') c.host = 'A CNAME cannot be at the zone apex: use an A or AAAA record';
  const vals = draftValues(d);
  vals.forEach((v, i) => {
    if (vals.indexOf(v) !== i && Object.keys(c.values[i] ?? {}).length === 0) c.values[i] = { _: 'Same value twice' };
  });
  if (!c.host) {
    const others = existing.filter((n) => n.host === host && !(editing && n.host === editing.host && n.type === editing.type));
    if (!editing && others.some((n) => n.type === d.type)) c.form.push(`${displayName(host, zone)} already has ${d.type} records: a name has one record set per type, open it in the list to change it`);
    else if (d.type === 'CNAME' && others.length) c.form.push(`${displayName(host, zone)} already has other records (${[...new Set(others.map((o) => o.type))].join(', ')}): a CNAME must be alone at its name`);
    else if (d.type !== 'CNAME' && others.some((n) => n.type === 'CNAME')) c.form.push(`${displayName(host, zone)} is a CNAME: no other record can be added at this name`);
  }
  c.ok = !c.host && !c.ttl && !c.form.length && c.values.every((v) => Object.keys(v).length === 0);
  return c;
}

export const displayName = (host: string, zone: string) => (host === '@' ? zone : `${host}.${zone}`);
