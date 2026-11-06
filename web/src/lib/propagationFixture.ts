// Demo answers of the propagation check (`VITE_FIXTURES=1`): the resolvers
// pick the new content up one after the other within half a minute of the
// first check of a record set.
import type { Propagation, PropagationAnswer, PropagationStatus, RRset } from './types';

const servers: Omit<PropagationAnswer, 'status' | 'values' | 'latency_ms'>[] = [
  { kind: 'authoritative', name: 'ns1.eurodns.com', address: '199.167.66.107' },
  { kind: 'authoritative', name: 'ns2.eurodns.com', address: '104.37.178.107' },
  { kind: 'resolver', name: 'Cloudflare', address: '1.1.1.1', location: 'Anycast', country: 'US', region: 'anycast' },
  { kind: 'resolver', name: 'Google Public DNS', address: '8.8.8.8', location: 'Anycast', country: 'US', region: 'anycast' },
  { kind: 'resolver', name: 'Quad9', address: '9.9.9.9', location: 'Anycast', country: 'CH', region: 'anycast' },
  { kind: 'resolver', name: 'OpenDNS (Cisco)', address: '208.67.222.222', location: 'Anycast', country: 'US', region: 'anycast' },
  { kind: 'resolver', name: 'AdGuard DNS (unfiltered)', address: '94.140.14.140', location: 'Anycast', country: 'CY', region: 'anycast' },
  { kind: 'resolver', name: 'DNS4EU (unfiltered)', address: '86.54.11.100', location: 'European Union', country: 'EU', region: 'europe' },
  { kind: 'resolver', name: 'FDN', address: '80.67.169.12', location: 'Paris', country: 'FR', region: 'europe' },
  { kind: 'resolver', name: 'Yandex DNS', address: '77.88.8.8', location: 'Moscow', country: 'RU', region: 'europe' },
  { kind: 'resolver', name: 'CIRA Canadian Shield (private)', address: '149.112.121.10', location: 'Canada', country: 'CA', region: 'north-america' },
  { kind: 'resolver', name: 'AliDNS (Alibaba)', address: '223.5.5.5', location: 'Hangzhou', country: 'CN', region: 'asia' },
  { kind: 'resolver', name: 'Quad101 (TWNIC)', address: '101.101.101.101', location: 'Taipei', country: 'TW', region: 'asia' },
];

const firstSeen = new Map<string, number>();

export function fixturePropagation(zone: string, host: string, type: string, rr: RRset | undefined): Propagation {
  const key = `${zone}/${host}/${type}/${rr?.hash ?? 'absent'}`;
  const start = firstSeen.get(key) ?? Date.now();
  firstSeen.set(key, start);
  const elapsed = (Date.now() - start) / 1000;
  const exists = !!rr && rr.status !== 'missing';
  const values = exists ? (rr.alias ? ['198.51.100.7'] : [...rr.values].sort()) : [];
  const ttl = rr?.ttl || 3600;
  const answers = servers.map((s, i): PropagationAnswer => {
    const at = s.kind === 'authoritative' ? 0 : (i * 7) % 30;
    let status: PropagationStatus = elapsed >= at ? 'match' : 'stale';
    if (s.name === 'OpenDNS (Cisco)') status = 'error';
    if (status === 'stale' && i % 4 === 0 && exists) status = 'missing';
    const ttlLeft = status === 'match' ? ttl - Math.floor(elapsed % ttl) : Math.max(1, Math.round(at - elapsed));
    return {
      ...s,
      status,
      values: status === 'match' ? values : status === 'stale' ? ['192.0.2.200'] : [],
      ttl_left: status === 'error' ? undefined : ttlLeft,
      rcode: status === 'error' ? 'REFUSED' : status === 'missing' ? 'NXDOMAIN' : 'NOERROR',
      error: status === 'error' ? 'refused (censored)' : undefined,
      latency_ms: s.kind === 'authoritative' ? 12 + i : 8 + ((i * 37) % 240),
    };
  });
  const count = (st: PropagationStatus) => answers.filter((a) => a.status === st).length;
  const pending = answers.filter((a) => a.status === 'stale' || a.status === 'missing');
  return {
    zone,
    host,
    type,
    name: (host === '@' ? '' : host + '.') + zone + '.',
    query_type: type === 'APEX' ? 'A' : type,
    expected: { exists, hash: rr?.hash, ttl: rr?.ttl, values: rr?.alias ? [] : values, alias_target: rr?.alias?.target },
    checked_at: new Date().toISOString(),
    cached: false,
    summary: {
      total: answers.length,
      match: count('match'),
      stale: count('stale'),
      missing: count('missing'),
      error: count('error'),
      converged: pending.length === 0 && count('match') > 0,
      max_ttl_left: Math.max(0, ...pending.map((a) => a.ttl_left ?? 0)),
    },
    answers,
  };
}
