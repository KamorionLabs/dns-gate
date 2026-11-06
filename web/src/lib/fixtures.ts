// Demo data for `VITE_FIXTURES=1`: lets the UI be judged without a running gate.
import type {
  AdoptApply,
  AdoptCandidate,
  AdoptPreview,
  AdoptResult,
  AdoptSelection,
  Actor,
  AuditEntry,
  AuditPage,
  AuditQuery,
  Binding,
  Connect,
  EffectivePolicy,
  ExplainRequest,
  Forward,
  ForwardList,
  HTTPSRedirect,
  ExplainResponse,
  GeneratedKey,
  ImpactItem,
  Me,
  PlanChange,
  PlanResult,
  RRsetChange,
  PolicyDocument,
  ProposeRequest,
  RevisionDetail,
  RevisionSummary,
  Role,
  RRset,
  TeamDetail,
  TeamInfo,
  TeamList,
  TerraformQuery,
  Transfer,
  TransferPage,
  TransferProposal,
  TransferQuery,
  ValidationError,
  WhoCanResponse,
  ZoneInventory,
  ZoneSummary,
} from './types';
import { teamLabel } from './team';
import { ApiError } from './api';
import { toYAML } from './yaml';
import { claimMatch, hostMatch, zoneMatch } from './glob';
import { rbacAllows } from './rights';
import { URLFWD, isForward, urlError } from './forwards';

const now = Date.now();
const ago = (minutes: number) => new Date(now - minutes * 60_000).toISOString();
const ahead = (minutes: number) => new Date(now + minutes * 60_000).toISOString();
const H = 60;
const D = 24 * H;

const ciApp: Actor = { subject: 'aws:arn:aws:iam::111111111111:role/ci-app', name: 'role/ci-app', category: 'pipeline' };
const ciCorp: Actor = { subject: 'aws:arn:aws:iam::111111111111:role/ci-corporate', name: 'role/ci-corporate', category: 'pipeline' };
const ghWeb: Actor = { subject: 'github:repo:acme/web:ref:refs/heads/main', name: 'acme/web @ main', category: 'pipeline' };
const alice: Actor = { subject: 'entra:alice@example.com', name: 'alice@example.com', category: 'human' };
const bob: Actor = { subject: 'entra:bob@example.com', name: 'bob@example.com', category: 'human' };
const acmeKey: Actor = { subject: 'key:acme-solver', name: 'acme-solver', category: 'key' };
const reconciler: Actor = { subject: 'gate:reconciler', name: 'reconciler', category: 'system' };
const carol: Actor = { subject: 'entra:carol@example.com', name: 'carol@example.com', category: 'human' };
const dave: Actor = { subject: 'entra:dave@example.com', name: 'dave@example.com', category: 'human' };
// Azure DevOps service connection: the subject carries no display name.
const adoDeploy: Actor = { subject: 'ado:sc://example-org/platform/dns-deploy', name: 'sc://example-org/platform/dns-deploy', category: 'pipeline' };

// ?as=reader in the page URL switches to a read-only user.
const asReader = new URLSearchParams(window.location.search).get('as') === 'reader';

const me: Me = asReader
  ? {
      subject: 'entra:carol@example.com',
      name: 'carol@example.com',
      category: 'human',
      roles: ['viewer'],
      teams: ['ops'],
      default_team: 'ops',
      groups: ['dns-viewers'],
      permissions: [{ role: 'viewer', zones: ['*'], actions: ['dns.read', 'ui.read', 'policy.read'], hosts: [], types: [] }],
    }
  : {
      subject: 'entra:alice@example.com',
      name: 'alice@example.com',
      category: 'human',
      roles: ['viewer', 'policy-admin', 'app-cname-writer', 'edge-writer', 'adopter', 'redirect-writer'],
      teams: ['web', 'platform'],
      default_team: 'web',
      groups: ['policy-admins', 'web-humans'],
      permissions: [
        {
          role: 'app-cname-writer',
          zones: ['example.com'],
          actions: ['dns.read', 'dns.record.write'],
          hosts: ['*', '*.staging', '_*.*'],
          types: ['CNAME', 'TXT'],
        },
        { role: 'edge-writer', zones: ['edge.example.org'], actions: ['dns.read', 'dns.record.write'], hosts: [], types: ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'] },
        { role: 'adopter', zones: ['example.com', 'acme.example', 'cloud.example'], actions: ['dns.record.adopt'], hosts: [], types: [] },
        { role: 'redirect-writer', zones: ['example.com', 'brand.example'], actions: ['dns.forward.write'], hosts: [], types: [] },
        { role: 'policy-admin', zones: ['*'], actions: ['policy.read', 'policy.propose', 'policy.approve'], hosts: [], types: [] },
        { role: 'viewer', zones: ['*'], actions: ['dns.read', 'ui.read', 'policy.read'], hosts: [], types: [] },
      ],
    };

// ?mcp=readonly or ?mcp=off in the page URL changes the MCP state of the Connect page.
const mcpMode = new URLSearchParams(window.location.search).get('mcp');
const GATE = 'https://dns-gate.example.com';
const UI_CLIENT_ID = '3f2a1b0c-9d8e-4f7a-b6c5-d4e3f2a1b0c9';
const connect: Connect = {
  base_url: GATE,
  mcp: { enabled: mcpMode !== 'off', url: GATE + '/mcp', allow_writes: mcpMode !== 'readonly' && mcpMode !== 'off' },
  issuer: {
    url: 'https://login.microsoftonline.com/7c1e2d3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f/v2.0',
    kind: 'entra',
    tenant_id: '7c1e2d3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f',
  },
  client_id: UI_CLIENT_ID,
  cli_scope: `api://${UI_CLIENT_ID}/.default`,
  claude_desktop_extension_url: mcpMode === 'off' ? '' : GATE + '/api/v1/connect/claude-desktop.mcpb',
  // ?tokens=off: no gate issuer, no "Get an API token"
  tokens_url: new URLSearchParams(window.location.search).get('tokens') === 'off' ? undefined : GATE + '/api/v1/tokens',
};

const foreign = (host: string, type: string, ttl: number, values: string[], prot = false): RRset => ({
  host, type, ttl, values, status: 'foreign', protected: prot, adopted: false,
});

/** A URL forward: not managed unless the overrides say otherwise. */
const fwd = (host: string, forward: Forward, o: Partial<RRset> = {}): RRset => ({ ...foreign(host, URLFWD, 0, []), forward, ...o });

/** Whether the forwards of each zone answer HTTPS (GET /forwards); the zones not listed have no subscription. */
const httpsOf: Record<string, HTTPSRedirect> = {
  'example.com': { status: 'inactive' },
  'acme.example': { status: 'active', subscription: '771204', expires_at: ahead(200 * D) },
  'brand.example': { status: 'pending', subscription: '771388' },
};

const inventories: ZoneInventory[] = [
  {
    zone: 'example.com',
    last_synced_at: ago(3),
    tombstones: [
      { host: 'promo', type: 'CNAME', team: 'web', deleted_by: ghWeb, deleted_at: ago(2 * D), expires_at: ahead(5 * D) },
      { host: 'old-careers', type: 'CNAME', team: 'corporate', deleted_by: ciCorp, deleted_at: ago(6 * H), expires_at: ahead(7 * D - 6 * H) },
    ],
    rrsets: [
      foreign('@', 'SOA', 86400, ['ns1.eurodns.com. hostmaster.eurodns.com. 2026110201 10800 3600 604800 600']),
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.', 'ns3.eurodns.com.', 'ns4.eurodns.com.'], true),
      foreign('@', 'A', 3600, ['203.0.113.10'], true),
      foreign('@', 'MX', 3600, ['10 mx1.example.com.', '20 mx2.example.com.'], true),
      foreign('@', 'TXT', 3600, ['"v=spf1 include:_spf.example.net -all"', '"google-site-verification=3fQ9…"'], true),
      foreign('_dmarc', 'TXT', 3600, ['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'], true),
      {
        host: 'www', type: 'CNAME', ttl: 600, values: ['d111111abcdef8.cloudfront.net.'], status: 'managed', protected: false,
        owner: 'web', created_by: ciApp, created_at: ago(9 * D), updated_by: ghWeb, updated_at: ago(2 * H), adopted: false,
        last_request_id: 'req_01JBX7Q4M2',
      },
      {
        host: '_3f1c9a7b2d.www', type: 'CNAME', ttl: 600, values: ['_8e2d41c0b9.mhbtsbpdnt.acm-validations.aws.'], status: 'managed',
        protected: false, owner: 'web', created_by: ciApp, created_at: ago(9 * D), adopted: false, last_request_id: 'req_01JAVK2N7T',
      },
      {
        host: 'staging', type: 'CNAME', ttl: 600, values: ['staging.edge.example.net.'], status: 'managed', protected: false,
        owner: 'web', created_by: alice, created_at: ago(21 * D), updated_by: ciApp, updated_at: ago(26 * H), adopted: false,
        last_request_id: 'req_01JBQ0Z8C1',
      },
      {
        host: 'api.staging', type: 'CNAME', ttl: 900, values: ['alb-api-stg.eu-central-1.elb.example.net.'], status: 'managed',
        protected: false, owner: 'platform', created_by: ciApp, created_at: ago(14 * D), adopted: false, last_request_id: 'req_01JB2W9QHD',
      },
      {
        host: 'shop', type: 'CNAME', ttl: 600, values: ['shop-old.hosting.example.org.'], status: 'tainted', protected: false,
        owner: 'web', created_by: ciApp, created_at: ago(30 * D), updated_by: ciApp, updated_at: ago(6 * D), adopted: false,
        last_request_id: 'req_01JAMR4E0P',
      },
      {
        host: 'status', type: 'CNAME', ttl: 600, values: ['status.statuspage.example.net.'], status: 'pending', protected: false,
        owner: 'platform', created_by: ciCorp, created_at: ago(1), adopted: false, last_request_id: 'req_01JBXA0003',
      },
      {
        host: 'docs', type: 'CNAME', ttl: 3600, values: ['docs.pages.example.net.'], status: 'missing', protected: false,
        owner: 'web', created_by: ghWeb, created_at: ago(40 * D), adopted: false, last_request_id: 'req_01J9ZP3K5S',
      },
      {
        host: 'assets', type: 'CNAME', ttl: 3600, values: ['assets.cdn.example.net.'], status: 'managed', protected: false,
        owner: 'web', created_by: bob, created_at: ago(5 * D), adopted: true, last_request_id: 'req_01JBF1D6XW',
      },
      {
        host: '_acme-challenge.intranet', type: 'TXT', ttl: 600, values: ['"Zm9vYmFyLWNoYWxsZW5nZS10b2tlbi0xMjM0"'],
        status: 'managed', protected: false, owner: 'security', created_by: acmeKey, created_at: ago(40), adopted: false,
        expires_at: ahead(23 * H + 20), last_request_id: 'req_01JBX9AC3M',
      },
      foreign('legacy', 'A', 3600, ['198.51.100.7']),
      foreign('mail', 'CNAME', 3600, ['mail.hosted.example.org.']),
      foreign('autodiscover', 'CNAME', 3600, ['autodiscover.outlook.com.']),
      foreign('intranet', 'CNAME', 3600, ['gateway']),
      foreign('vpn', 'A', 3600, ['198.51.100.21', '198.51.100.22']),
      foreign('crm', 'CNAME', 1800, ['acme.crm.example.net.']),
      foreign('crm', 'TXT', 3600, ['"crm-domain-verification=6c1f0b"']),
      { ...foreign('@', 'URL', 0, ['https://www.example.com/']), read_only: 'forward_record' },
      fwd('@', { type: '301', url: 'https://www.example.com/' }, {
        status: 'managed', owner: 'web', created_by: ghWeb, created_at: ago(20 * D), updated_by: alice, updated_at: ago(3 * D), last_request_id: 'req_01JBF0FWD1',
      }),
      fwd('go', { type: '302', url: 'https://www.example.com/autumn-sale?utm_source=go' }, {
        status: 'managed', owner: 'platform', created_by: alice, created_at: ago(5 * H), last_request_id: 'req_01JBXF0WD2',
      }),
      fwd('careers', { type: '301', url: 'https://careers.example.org/acme' }, {
        status: 'managed', owner: 'corporate', created_by: ciCorp, created_at: ago(11 * D), last_request_id: 'req_01JB4F0WD3',
      }),
      fwd('old-shop', { type: '301', url: 'http://shop-old.hosting.example.org/' }, {
        status: 'tainted', owner: 'web', created_by: bob, created_at: ago(60 * D), updated_by: bob, updated_at: ago(9 * D), last_request_id: 'req_01J8F0WD4',
      }),
      fwd('boutique', { type: 'frame', url: 'https://shop.example.net/fr/', title: 'Example boutique', keywords: 'gifts, shop', description: 'Gifts delivered in 48 hours' }),
      fwd('deals', { type: 'http307', url: 'https://www.example.com/deals' }, { read_only: 'unsupported_forward' }),
    ],
  },
  {
    zone: 'acme.example',
    last_synced_at: ago(4),
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      {
        host: '@', type: 'APEX', ttl: 600, values: ['d222222fedcba9.cloudfront.net.'], status: 'managed', protected: false,
        owner: 'corporate', created_by: ciCorp, created_at: ago(12 * D), updated_by: ciCorp, updated_at: ago(3 * D), adopted: true,
        last_request_id: 'req_01JBA7S2LK',
      },
      {
        host: 'www', type: 'CNAME', ttl: 600, values: ['d222222fedcba9.cloudfront.net.'], status: 'managed', protected: false,
        owner: 'corporate', created_by: ciCorp, created_at: ago(12 * D), adopted: false, last_request_id: 'req_01JAZZ1P4E',
      },
      {
        host: 'careers', type: 'CNAME', ttl: 1800, values: ['acme.careers.example.org.'], status: 'managed', protected: false,
        owner: 'corporate', created_by: bob, created_at: ago(2 * D), adopted: false, last_request_id: 'req_01JBRM5V8N',
      },
      {
        host: '_acme-challenge', type: 'TXT', ttl: 600, values: ['"aW50ZXJuYWwtdG9rZW4tYWJjZGVm"', '"c2Vjb25kLXRva2VuLWZvci13aWxkY2FyZA"'],
        status: 'managed', protected: false, owner: 'security', created_by: acmeKey, created_at: ago(12), adopted: false,
        expires_at: ahead(23 * H + 48), last_request_id: 'req_01JBXA0001',
      },
      foreign('@', 'MX', 3600, ['10 mx.acme.example.'], true),
      foreign('@', 'CAA', 3600, ['0 issue "amazon.com"', '0 issue "letsencrypt.org"'], true),
    ],
  },
  {
    zone: 'brand.example',
    last_synced_at: ago(6),
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      foreign('@', 'A', 3600, ['192.0.2.44']),
      foreign('www', 'CNAME', 3600, ['brand.example.']),
      foreign('@', 'MX', 3600, ['10 mx.brand.example.'], true),
      foreign('@', 'TXT', 3600, ['"v=spf1 -all"'], true),
    ],
  },
];

// Zones of the account that zone discovery found. shop.example is managed by
// the active managed revision; example.net and legacy.example are not managed.
inventories.push(
  {
    zone: 'shop.example',
    last_synced_at: ago(9),
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      foreign('@', 'A', 3600, ['198.51.100.20']),
      {
        host: 'checkout', type: 'CNAME', ttl: 600, values: ['shop-lb.example.net.'], status: 'managed', protected: false,
        owner: 'gh-shop', created_by: ghWeb, created_at: ago(2 * D), adopted: false, last_request_id: 'req_01JBY0SHOP',
      },
    ],
  },
  {
    zone: 'example.net',
    last_synced_at: ago(25),
    rrsets: [
      foreign('@', 'SOA', 86400, ['ns1.eurodns.com. hostmaster.eurodns.com. 2026103001 10800 3600 604800 600']),
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      foreign('@', 'MX', 3600, ['10 mx.example.net.'], true),
      foreign('shop-lb', 'A', 300, ['198.51.100.21', '198.51.100.22']),
      foreign('status', 'CNAME', 3600, ['status-page.example.org.']),
    ],
  },
  {
    zone: 'legacy.example',
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      foreign('@', 'A', 3600, ['192.0.2.200']),
    ],
  },
);

// Deterministic pseudo-random data, so screenshots stay stable.
function rng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(20261103);
const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;
const hex = (n: number) => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(rand() * 16)]).join('');
const letters = (n: number) => Array.from({ length: n }, () => 'abcdefghijklmnopqrstuvwxyz'[Math.floor(rand() * 26)]).join('');

// cloud.example: a large zone (1551 record sets) with long ACM validation
// names and values, 16 of them managed by a pipeline.
function cloudZone(): ZoneInventory {
  const zone = 'cloud.example';
  const services = ['api', 'auth', 'billing', 'catalog', 'checkout', 'search', 'media', 'events', 'reports', 'partners', 'status', 'docs'];
  const regions = ['eu-central', 'eu-west', 'us-east', 'ap-south'];
  const rrsets: RRset[] = [
    foreign('@', 'SOA', 86400, ['ns1.eurodns.com. hostmaster.eurodns.com. 2026110301 10800 3600 604800 600']),
    foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.', 'ns3.eurodns.com.', 'ns4.eurodns.com.'], true),
    foreign('@', 'MX', 3600, ['10 mx1.mail.example.net.', '20 mx2.mail.example.net.', '30 mx3.mail.example.net.'], true),
    foreign('@', 'TXT', 3600, [
      '"v=spf1 include:_spf.mail.example.net include:_spf.crm.example.net include:_spf.helpdesk.example.org ip4:198.51.100.0/24 -all"',
      '"site-verification=Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8"',
    ], true),
    foreign('selector1._domainkey', 'TXT', 3600, [
      '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu2bq7mL0yXk3d9JZr4m1vTqP8sH2nE5cW6aG0fR3tY7uI1oP9lK4jH6gF2dS8aQ0wE3rT5yU7iO9pL1kJ3hG5fD7sA9zX2cV4bN6mM8qW0eR2tY4uI6oP8lK0jH2gF4dS6aQ8wE0rT2yU4iO6pL8kJ0hG2fD4sA6zX8cV0bN2mM4qW6eR8tY0uI2oP4lK6jH8gF0dS2aQ4wIDAQAB"',
    ]),
  ];
  const seen = new Set(rrsets.map((r) => `${r.host}/${r.type}`));
  const add = (r: RRset) => {
    const k = `${r.host}/${r.type}`;
    if (seen.has(k)) return;
    seen.add(k);
    rrsets.push(r);
  };
  // Managed by the platform pipeline (an Azure DevOps service connection).
  const managedHosts = ['api', 'auth', 'billing', 'catalog', 'checkout', 'search', 'media', 'status'];
  managedHosts.forEach((svc, i) => {
    add({
      host: `${svc}.eu-central`, type: 'CNAME', ttl: 300, values: [svc === 'status' ? 'status-page.hosted.example.org.' : `${svc}-alb-${hex(8)}.eu-central-1.elb.example.net.`], status: 'managed',
      protected: false, owner: 'platform', created_by: adoDeploy, created_at: ago((20 + i) * D), updated_by: adoDeploy, updated_at: ago(i * 3 * H + 30),
      adopted: false, last_request_id: `req_01JC${hex(6).toUpperCase()}`,
    });
    add({
      host: `_${hex(32)}.${svc}.eu-central`, type: 'CNAME', ttl: 300, values: [`_${hex(32)}.${letters(10)}.acm-validations.aws.`], status: 'managed',
      protected: false, owner: 'platform', created_by: adoDeploy, created_at: ago((20 + i) * D), adopted: false, last_request_id: `req_01JC${hex(6).toUpperCase()}`,
    });
  });
  // Everything else exists at EuroDNS, not managed by the gate.
  while (rrsets.length < 1551) {
    const kind = rand();
    const svc = pick(services);
    const region = pick(regions);
    const n = Math.floor(rand() * 90) + 1;
    if (kind < 0.42) {
      add(foreign(`_${hex(32)}.${svc}-${n}.${region}`, 'CNAME', 300, [`_${hex(32)}.${letters(10)}.acm-validations.aws.`]));
    } else if (kind < 0.7) {
      const ips = Array.from({ length: 1 + Math.floor(rand() * 4) }, () => `${pick(['198.51.100', '203.0.113', '192.0.2'])}.${Math.floor(rand() * 254) + 1}`);
      add(foreign(`${svc}-${n}.${region}`, 'A', pick([60, 300, 3600]), [...new Set(ips)]));
    } else if (kind < 0.85) {
      add(foreign(`${svc}-${n}.${region}`, 'CNAME', pick([300, 3600]), [`${svc}-${n}-${hex(10)}.${region}-1.lb.example.net.`]));
    } else if (kind < 0.95) {
      add(foreign(`${svc}-${n}.${region}`, 'TXT', 3600, [`"${letters(6)}-verification=${hex(48)}"`]));
    } else {
      add(foreign(`${svc}-${n}.${region}`, 'AAAA', 300, [`2001:db8:${hex(4)}::${hex(4)}`, `2001:db8:${hex(4)}::${hex(4)}`]));
    }
  }
  return { zone, last_synced_at: ago(2), rrsets };
}

inventories.push(
  cloudZone(),
  {
    zone: 'mail.example',
    last_synced_at: ago(5),
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      foreign('@', 'MX', 3600, ['10 mx.mail.example.'], true),
      {
        host: 'autoconfig', type: 'CNAME', ttl: 3600, values: ['autoconfig.provider.example.net.'], status: 'managed', protected: false,
        owner: 'platform', created_by: adoDeploy, created_at: ago(8 * D), adopted: true, last_request_id: 'req_01JC0MAIL1',
      },
      foreign('webmail', 'CNAME', 3600, ['webmail.provider.example.net.']),
    ],
  },
  {
    zone: 'static.example.net',
    last_synced_at: ago(7),
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      {
        host: 'cdn', type: 'CNAME', ttl: 600, values: ['d333333abcdef1.cloudfront.net.'], status: 'managed', protected: false,
        owner: 'web', created_by: ghWeb, created_at: ago(11 * D), updated_by: ghWeb, updated_at: ago(4 * D), adopted: false, last_request_id: 'req_01JC0CDN01',
      },
    ],
  },
  {
    zone: 'internal.example',
    last_synced_at: ago(3),
    rrsets: [
      foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
      foreign('vpn', 'A', 3600, ['198.51.100.30']),
      foreign('wiki', 'CNAME', 3600, ['wiki.hosted.example.org.']),
    ],
  },
);

// edge.example.org: a Route53 hosted zone, with alias records (no values,
// a target) and record sets using a routing policy, read-only for the gate.
const r53 = (o: Partial<RRset> & Pick<RRset, 'host' | 'type'>): RRset => ({ ttl: 300, values: [], status: 'foreign', protected: false, adopted: false, ...o });
inventories.push({
  zone: 'edge.example.org',
  provider: 'route53',
  last_synced_at: ago(2),
  rrsets: [
    r53({ host: '@', type: 'SOA', ttl: 900, values: ['ns-1536.awsdns-00.co.uk. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400'], read_only: 'server_managed' }),
    r53({ host: '@', type: 'NS', ttl: 172800, values: ['ns-1536.awsdns-00.co.uk.', 'ns-0.awsdns-00.com.', 'ns-1024.awsdns-00.org.', 'ns-512.awsdns-00.net.'], read_only: 'server_managed' }),
    r53({
      host: '@', type: 'A', ttl: 0, alias: { target: 'd444444abcdef8.cloudfront.net.', hosted_zone_id: 'Z2FDTNDATAQYW2', evaluate_target_health: false },
      status: 'managed', owner: 'web', created_by: ciApp, created_at: ago(30 * D), adopted: true, last_request_id: 'req_01JD0EDGE01',
    }),
    r53({
      host: '@', type: 'AAAA', ttl: 0, alias: { target: 'd444444abcdef8.cloudfront.net.', hosted_zone_id: 'Z2FDTNDATAQYW2', evaluate_target_health: false },
    }),
    r53({
      host: 'www', type: 'CNAME', ttl: 300, values: ['d444444abcdef8.cloudfront.net.'], status: 'managed', owner: 'web',
      created_by: ciApp, created_at: ago(30 * D), updated_by: alice, updated_at: ago(3 * D), adopted: false, last_request_id: 'req_01JD0EDGE02',
    }),
    r53({
      host: 'app', type: 'A', ttl: 60, values: ['198.51.100.40', '198.51.100.41'], status: 'managed', owner: 'web',
      created_by: alice, created_at: ago(6 * D), adopted: false, last_request_id: 'req_01JD0EDGE03',
    }),
    r53({
      host: 'app', type: 'AAAA', ttl: 60, values: ['2001:db8:40::1'], status: 'managed', owner: 'web',
      created_by: alice, created_at: ago(6 * D), adopted: false, last_request_id: 'req_01JD0EDGE04',
    }),
    r53({
      host: '@', type: 'MX', ttl: 3600, values: ['10 inbound-smtp.eu-west-1.amazonaws.com.'], status: 'managed', owner: 'platform',
      created_by: adoDeploy, created_at: ago(40 * D), adopted: true, last_request_id: 'req_01JD0EDGE05',
    }),
    r53({
      host: '@', type: 'TXT', ttl: 3600, values: ['"v=spf1 include:amazonses.com -all"', '"google-site-verification=edgeQ9x"'], status: 'managed', owner: 'web',
      created_by: alice, created_at: ago(12 * D), adopted: false, last_request_id: 'req_01JD0EDGE06',
    }),
    r53({
      host: '@', type: 'CAA', ttl: 3600, values: ['0 issue "amazon.com"', '0 issue "letsencrypt.org"'], status: 'managed', owner: 'web',
      created_by: alice, created_at: ago(12 * D), adopted: false, last_request_id: 'req_01JD0EDGE07',
    }),
    r53({
      host: '_sip._tcp', type: 'SRV', ttl: 3600, values: ['10 5 5060 sip.edge.example.org.'], status: 'managed', owner: 'web',
      created_by: alice, created_at: ago(9 * D), adopted: false, last_request_id: 'req_01JD0EDGE08',
    }),
    r53({
      host: 'reports', type: 'CNAME', ttl: 300, values: ['reports.bi.example.net.'], status: 'managed', owner: 'data',
      created_by: carol, created_at: ago(15 * D), adopted: false, last_request_id: 'req_01JD0EDGE09',
    }),
    r53({
      host: 'old', type: 'CNAME', ttl: 300, values: ['legacy.hosting.example.net.'], status: 'tainted', owner: 'web',
      created_by: alice, created_at: ago(50 * D), adopted: false, last_request_id: 'req_01JD0EDGE10',
    }),
    r53({ host: 'api', type: 'CNAME', ttl: 60, values: ['api-eu.edge.example.org.'], read_only: 'routing_policy' }),
    r53({ host: 'geo', type: 'A', ttl: 60, values: ['198.51.100.60'], read_only: 'routing_policy' }),
    r53({ host: 'mail', type: 'CNAME', ttl: 3600, values: ['mail.hosted.example.net.'] }),
  ],
});

// The rest of the account: hundreds of zones that are not managed. Their
// content is generated when a zone is opened.
const words = ['north', 'river', 'alpha', 'summit', 'harbor', 'maple', 'cedar', 'atlas', 'nova', 'orbit', 'pixel', 'meadow', 'granite', 'lumen', 'vertex', 'willow', 'ember', 'falcon', 'quartz', 'tundra'];
const suffixes = ['', '-shop', '-labs', '-group', '-media', '-store', '-cloud', '-app'];
const tlds = ['.example', '.example.net', '.example.org'];
const generated: string[] = [];
for (const t of tlds) for (const w of words) for (const x of suffixes) generated.push(w + x + t);
const discovered: string[] = [...new Set([...inventories.map((i) => i.zone), ...generated.slice(0, 449 - inventories.length)])].sort();

function findInv(zone: string): ZoneInventory | undefined {
  let inv = inventories.find((i) => i.zone === zone);
  if (!inv && discovered.includes(zone)) {
    const r = rng(zone.length * 7919 + zone.charCodeAt(0));
    const ip = () => `192.0.2.${Math.floor(r() * 254) + 1}`;
    inv = {
      zone,
      rrsets: [
        foreign('@', 'SOA', 86400, [`ns1.eurodns.com. hostmaster.eurodns.com. 2026${String(Math.floor(r() * 1e6)).padStart(6, '0')} 10800 3600 604800 600`]),
        foreign('@', 'NS', 86400, ['ns1.eurodns.com.', 'ns2.eurodns.com.'], true),
        foreign('@', 'A', 3600, [ip()]),
        foreign('www', 'CNAME', 3600, [zone + '.']),
        foreign('@', 'MX', 3600, ['10 mx.mail.example.net.'], true),
      ],
    };
    inventories.push(inv);
  }
  return inv;
}

// Unmanaged zones whose content the gate has read (on demand, when opened).
const readZones = new Set(['example.net']);

// ?calm=1: nothing needs attention (to see the "All good" state).
const calm = new URLSearchParams(window.location.search).get('calm') === '1';
// ?discovery=error: the last zone listing failed.
const discoveryError = new URLSearchParams(window.location.search).get('discovery') === 'error';

function summarize(inv: ZoneInventory, lastWrite?: string): ZoneSummary {
  const count = (s: string) => inv.rrsets.filter((r) => r.status === s).length;
  return {
    zone: inv.zone,
    provider: inv.provider ?? 'eurodns',
    rrsets: inv.rrsets.length,
    managed: count('managed'),
    tainted: calm ? 0 : count('tainted') + count('missing'),
    pending: calm ? 0 : count('pending'),
    foreign: count('foreign'),
    last_synced_at: inv.last_synced_at,
    last_write_at: lastWrite,
  };
}

const mcpRead = (minutes: number, tool: string, zone?: string): AuditEntry => ({
  time: ago(minutes), request_id: `mcp_${tool}_${minutes}`, actor: alice, teams: ['web', 'platform'], action: `mcp.${tool}`, zone, decision: 'allow',
});

const audit: AuditEntry[] = [
  mcpRead(0.5, 'list_zones'),
  mcpRead(0.6, 'list_rrsets', 'example.com'),
  mcpRead(0.7, 'get_rrset', 'example.com'),
  {
    time: ago(0.8), request_id: 'req_01JC0RETYPE', actor: adoDeploy, teams: ['platform'], action: 'saveDnsZone', zone: 'cloud.example',
    decision: 'allow', snapshot_id: '884301',
    changes: [
      { op: 'delete', host: 'status.eu-central', type: 'A', old_ttl: 300, old_values: ['198.51.100.40', '198.51.100.41'] },
      { op: 'create', host: 'status.eu-central', type: 'CNAME', new_ttl: 300, new_values: ['status-page.hosted.example.org.'] },
    ],
  },
  mcpRead(0.9, 'plan_rrset_change', 'cloud.example'),
  ...Array.from({ length: 18 }, (_, i) => mcpRead(1.1 + i * 0.05, i % 2 ? 'list_rrsets' : 'get_rrset', i % 3 ? 'cloud.example' : 'example.com')),
  {
    time: ago(30), request_id: 'req_01JC0CLD16', actor: adoDeploy, teams: ['platform'], action: 'saveDnsZone', zone: 'cloud.example',
    decision: 'allow', snapshot_id: '884250',
    changes: [{
      op: 'update', host: 'api.eu-central', type: 'CNAME', old_ttl: 300, old_values: ['api-alb-old.eu-central-1.elb.example.net.'],
      new_ttl: 300, new_values: ['api-alb-3f9c2a1b.eu-central-1.elb.example.net.'],
    }],
  },
  {
    time: ago(5 * H), request_id: 'req_01JBXF0WD2', actor: alice, teams: ['web', 'platform'], action: 'applyRRsets', zone: 'example.com',
    decision: 'allow', snapshot_id: '884199',
    changes: [{ op: 'create', host: 'go', type: 'URLFWD', new_forward: { type: '302', url: 'https://www.example.com/autumn-sale?utm_source=go' } }],
  },
  {
    time: ago(3 * D), request_id: 'req_01JBF0FWD1', actor: alice, teams: ['web', 'platform'], action: 'api.forward.put', zone: 'example.com',
    decision: 'allow', snapshot_id: '883907',
    changes: [{
      op: 'update', host: '@', type: 'URLFWD',
      old_forward: { type: 'frame', url: 'https://www.example.com/', title: 'Example' }, new_forward: { type: '301', url: 'https://www.example.com/' },
    }],
  },
  {
    time: ago(1), request_id: 'req_01JBXA0003', actor: ciCorp, teams: ['corporate', 'platform'], action: 'addDnsRecords',
    zone: 'example.com', decision: 'allow',
    changes: [{ op: 'create', host: 'status', type: 'CNAME', new_ttl: 600, new_values: ['status.statuspage.example.net.'] }],
  },
  {
    time: ago(7), request_id: 'req_01JBXA0002', actor: acmeKey, teams: ['security'], action: 'saveDnsZone', zone: 'example.com',
    decision: 'deny', reason: 'foreign_rrset',
    changes: [{ op: 'create', host: 'mail', type: 'TXT', new_ttl: 600, new_values: ['"dGVzdA"'] }],
  },
  {
    time: ago(12), request_id: 'req_01JBXA0001', actor: acmeKey, teams: ['security'], action: 'saveDnsZone', zone: 'acme.example',
    decision: 'allow', snapshot_id: '884213',
    changes: [{
      op: 'create', host: '_acme-challenge', type: 'TXT', new_ttl: 600,
      new_values: ['"aW50ZXJuYWwtdG9rZW4tYWJjZGVm"', '"c2Vjb25kLXRva2VuLWZvci13aWxkY2FyZA"'],
    }],
  },
  {
    time: ago(40), request_id: 'req_01JBX9AC3M', actor: acmeKey, teams: ['security'], action: 'saveDnsZone', zone: 'example.com',
    decision: 'allow', snapshot_id: '884190',
    changes: [{ op: 'create', host: '_acme-challenge.intranet', type: 'TXT', new_ttl: 600, new_values: ['"Zm9vYmFyLWNoYWxsZW5nZS10b2tlbi0xMjM0"'] }],
  },
  {
    time: ago(2 * H), request_id: 'req_01JBX7Q4M2', actor: ghWeb, teams: ['web'], action: 'saveDnsZone', zone: 'example.com',
    decision: 'allow', snapshot_id: '884102',
    changes: [{
      op: 'update', host: 'www', type: 'CNAME', old_ttl: 3600, old_values: ['www-legacy.hosting.example.org.'],
      new_ttl: 600, new_values: ['d111111abcdef8.cloudfront.net.'],
    }],
  },
  {
    time: ago(2 * H + 4), request_id: 'req_01JBX7P0ZZ', actor: ciCorp, teams: ['corporate'], action: 'saveDnsZone', zone: 'example.com',
    decision: 'deny', reason: 'not_owner',
    changes: [{
      op: 'update', host: 'www', type: 'CNAME', old_ttl: 3600, old_values: ['www-legacy.hosting.example.org.'],
      new_ttl: 600, new_values: ['d222222fedcba9.cloudfront.net.'],
    }],
  },
  {
    time: ago(5 * H), request_id: 'req_01JBWZ8R1D', actor: ciApp, teams: ['web', 'platform'], action: 'saveDnsZone',
    zone: 'example.com', decision: 'error', reason: 'upstream',
  },
  {
    time: ago(5 * H + 2), request_id: 'req_01JBWZ7T9Q', actor: ciApp, teams: ['web', 'platform'], action: 'saveDnsZone',
    zone: 'example.com', decision: 'deny', reason: 'precondition',
  },
  {
    time: ago(26 * H), request_id: 'req_01JBQ0Z8C1', actor: ciApp, teams: ['web', 'platform'], action: 'saveDnsZone',
    zone: 'example.com', decision: 'allow', snapshot_id: '883551',
    changes: [{
      op: 'update', host: 'staging', type: 'CNAME', old_ttl: 600, old_values: ['staging-v1.edge.example.net.'],
      new_ttl: 600, new_values: ['staging.edge.example.net.'],
    }],
  },
  {
    time: ago(30 * H), request_id: 'req_01JBP4H6A2', actor: alice, teams: ['web', 'platform'], action: 'saveDnsZone',
    zone: 'example.com', decision: 'deny', reason: 'forbidden',
    changes: [{ op: 'update', host: '@', type: 'MX', old_ttl: 3600, old_values: ['10 mx1.example.com.', '20 mx2.example.com.'], new_ttl: 3600, new_values: ['10 mx.newmail.example.net.'] }],
  },
  {
    time: ago(30 * H + 9), request_id: 'req_01JBP4F1KQ', actor: ghWeb, teams: ['web'], action: 'saveDnsZone',
    zone: 'example.com', decision: 'deny', reason: 'too_many_changes',
  },
  {
    time: ago(2 * D), request_id: 'req_01JBRM5V8N', actor: bob, teams: ['corporate'], action: 'addDnsRecords', zone: 'acme.example',
    decision: 'allow', snapshot_id: '882990',
    changes: [{ op: 'create', host: 'careers', type: 'CNAME', new_ttl: 1800, new_values: ['acme.careers.example.org.'] }],
  },
  {
    time: ago(2 * D + 3 * H), request_id: 'rec_01JBR0EXP1', actor: reconciler, action: 'reconcile', zone: 'example.com',
    decision: 'allow',
    changes: [{ op: 'expire', host: '_acme-challenge.intranet', type: 'TXT', old_ttl: 600, old_values: ['"b2xkLXRva2Vu"'] }],
  },
  {
    time: ago(3 * D), request_id: 'req_01JBA7S2LK', actor: ciCorp, teams: ['corporate'], action: 'saveDnsZone', zone: 'acme.example',
    decision: 'allow', snapshot_id: '882100',
    changes: [{ op: 'update', host: '@', type: 'APEX', old_ttl: 3600, old_values: ['acme-old.hosting.example.org.'], new_ttl: 600, new_values: ['d222222fedcba9.cloudfront.net.'] }],
  },
  {
    time: ago(5 * D), request_id: 'req_01JBF1D6XW', actor: bob, teams: ['web'], action: 'adopt', zone: 'example.com',
    decision: 'allow',
    changes: [{ op: 'adopt', host: 'assets', type: 'CNAME', new_ttl: 3600, new_values: ['assets.cdn.example.net.'] }],
  },
  {
    time: ago(6 * D - 30), request_id: 'rec_01JBD2TNT0', actor: reconciler, action: 'reconcile', zone: 'example.com',
    decision: 'allow',
    changes: [{
      op: 'taint', host: 'shop', type: 'CNAME', old_ttl: 600, old_values: ['shop.edge.example.net.'],
      new_ttl: 600, new_values: ['shop-old.hosting.example.org.'],
    }],
  },
  {
    time: ago(6 * D), request_id: 'req_01JAMR4E0P', actor: ciApp, teams: ['web'], action: 'saveDnsZone', zone: 'example.com',
    decision: 'allow', snapshot_id: '880771',
    changes: [{ op: 'update', host: 'shop', type: 'CNAME', old_ttl: 3600, old_values: ['shop-v1.edge.example.net.'], new_ttl: 600, new_values: ['shop.edge.example.net.'] }],
  },
  {
    time: ago(9 * D), request_id: 'req_01JAVK2N7T', actor: ciApp, teams: ['web'], action: 'addDnsRecords', zone: 'example.com',
    decision: 'allow', snapshot_id: '879400',
    changes: [
      { op: 'create', host: 'www', type: 'CNAME', new_ttl: 3600, new_values: ['www-legacy.hosting.example.org.'] },
      { op: 'create', host: '_3f1c9a7b2d.www', type: 'CNAME', new_ttl: 600, new_values: ['_8e2d41c0b9.mhbtsbpdnt.acm-validations.aws.'] },
    ],
  },
  {
    time: ago(12 * D), request_id: 'req_01JAZZ1P4E', actor: ciCorp, teams: ['corporate'], action: 'addDnsRecords', zone: 'acme.example',
    decision: 'allow', snapshot_id: '878002',
    changes: [{ op: 'create', host: 'www', type: 'CNAME', new_ttl: 600, new_values: ['d222222fedcba9.cloudfront.net.'] }],
  },
  {
    time: ago(14 * D), request_id: 'req_01JB2W9QHD', actor: ciApp, teams: ['platform'], action: 'addDnsRecords', zone: 'example.com',
    decision: 'allow', snapshot_id: '877310',
    changes: [{ op: 'create', host: 'api.staging', type: 'CNAME', new_ttl: 900, new_values: ['alb-api-stg.eu-central-1.elb.example.net.'] }],
  },
  {
    time: ago(21 * D), request_id: 'req_01JAQ7B2ZR', actor: alice, teams: ['web'], action: 'addDnsRecords', zone: 'example.com',
    decision: 'allow', snapshot_id: '875533',
    changes: [{ op: 'create', host: 'staging', type: 'CNAME', new_ttl: 600, new_values: ['staging-v1.edge.example.net.'] }],
  },
  {
    time: ago(21 * D + 10), request_id: 'req_01JAQ79XXA', actor: alice, teams: ['web'], action: 'deleteDnsRecord', zone: 'example.com',
    decision: 'deny', reason: 'foreign_rrset',
    changes: [{ op: 'delete', host: 'legacy', type: 'A', old_ttl: 3600, old_values: ['198.51.100.7'] }],
  },
  {
    time: ago(40 * D), request_id: 'req_01J9ZP3K5S', actor: ghWeb, teams: ['web'], action: 'addDnsRecords', zone: 'example.com',
    decision: 'allow', snapshot_id: '870020',
    changes: [{ op: 'create', host: 'docs', type: 'CNAME', new_ttl: 3600, new_values: ['docs.pages.example.net.'] }],
  },
];

audit.sort((a, b) => b.time.localeCompare(a.time));

const delay = <T>(v: T, ms = 180) => new Promise<T>((r) => setTimeout(() => r(structuredClone(v)), ms));

function matches(e: AuditEntry, q: AuditQuery): boolean {
  if (q.zone && e.zone !== q.zone) return false;
  if (q.decision && e.decision !== q.decision) return false;
  if (q.category && e.actor.category !== q.category) return false;
  if (q.subject) {
    const needle = q.subject.toLowerCase();
    if (!e.actor.subject.toLowerCase().includes(needle) && !e.actor.name.toLowerCase().includes(needle)) return false;
  }
  if (q.host || q.type) {
    const hit = (e.changes ?? []).some((c) => (!q.host || c.host === q.host) && (!q.type || c.type === q.type));
    if (!hit) return false;
  }
  if (q.since && e.time < q.since) return false;
  if (q.until && e.time > q.until) return false;
  return true;
}


// ---------------------------------------------------------------- policy

const ENTRA = 'entra';
const base: EffectivePolicy['base'] = {
  config_hash: 'sha256:9f2c4e1ab07d5c3e88a1f0b6d2e4c7a9b1d3f5e7a9c1b3d5e7f9a1c3e5b7d9f1',
  loaded_at: ago(3 * D + 2 * H),
  zones: ['example.com', 'acme.example', 'brand.example', 'cloud.example', 'mail.example', 'static.example.net', 'internal.example', 'edge.example.org'],
  zones_discovery: {
    enabled: true,
    include: ['*'],
    exclude: ['*.test'],
    refresh: '1h0m0s',
    loaded: true,
    count: 449,
    last_refresh_at: ago(14),
    error: discoveryError ? 'searchDomains: EuroDNS answered 503 Service Unavailable' : undefined,
  },
  issuers: [
    {
      name: 'aws',
      issuer: 'https://3f8a1c2e-0b7d-4e9a-a1c3-5d7f9b1e3a5c.tokens.sts.global.api.aws',
      audiences: ['dns-gate'],
      bound_claims: { 'https://sts.amazonaws.com/org_id': ['o-a1b2c3d4e5'] },
      subject_claim: 'sub',
      category: 'pipeline',
    },
    {
      name: 'github',
      issuer: 'https://token.actions.githubusercontent.com',
      audiences: ['dns-gate'],
      bound_claims: { repository_owner: ['acme'] },
      subject_claim: 'sub',
      category: 'pipeline',
    },
    {
      name: ENTRA,
      issuer: 'https://login.microsoftonline.com/7c1e2d3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f/v2.0',
      audiences: ['api://dns-gate'],
      subject_claim: 'preferred_username',
      category: 'human',
    },
    {
      name: 'ado',
      issuer: 'https://vstoken.dev.azure.com/00000000-0000-0000-0000-000000000000',
      audiences: ['api://AzureADTokenExchange'],
      subject_claim: 'sub',
      category: 'pipeline',
    },
    {
      name: 'k8s',
      issuer: 'https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE',
      audiences: ['dns-gate'],
      category: 'pipeline',
    },
  ],
  protected: [
    { zones: ['*'], hosts: ['@'], types: ['NS', 'SOA', 'MX', 'CAA'] },
    { zones: ['*'], hosts: ['_dmarc', '@'], types: ['TXT'] },
  ],
  bounds: {
    zones: ['example.com', 'acme.example', 'brand.example', 'cloud.example', 'mail.example', 'internal.example', 'shop.example', '*.example', '*.example.net', '*.example.org'],
    actions: ['dns.read', 'ui.read', 'dns.record.write', 'dns.forward.write', 'dns.record.adopt'],
  },
  delegations: [
    {
      name: 'ci-pipelines',
      description: 'Gate roles and bindings of the pipelines created by the CI stack',
      subjects: [{ issuer: 'github', claims: { sub: ['repo:acme/ci-stack:environment:production'] } }],
      allow: {
        zones: ['example.com', 'shop.example'],
        actions: ['dns.read', 'dns.record.write', 'dns.record.adopt'],
        records: { hosts: ['**'], types: ['A', 'AAAA', 'CNAME', 'TXT'] },
        binding_subjects: [{ issuer: 'github', claims: { sub: ['repo:acme/*:environment:production'] } }],
        teams: { names: ['web'], from_subject: { claim: 'sub', regex: '^repo:acme/([a-z0-9-]+):environment:production$', prefix: 'gh-' } },
        max_objects: 100,
      },
    },
  ],
  document: {
    groups: {
      'policy-admins': {
        description: 'Entra app role PolicyAdmin',
        members: [{ issuer: ENTRA, claims: { roles: ['PolicyAdmin'] } }],
      },
      'dns-viewers': {
        description: 'Anyone in the DNS readers group',
        members: [{ issuer: ENTRA, claims: { groups: ['5b8e2c1a-dns-readers'] } }],
      },
    },
    roles: {
      viewer: { description: 'Read zones, records and the journal', rules: [{ zones: ['*'], actions: ['dns.read', 'ui.read', 'policy.read'] }] },
      'policy-admin': {
        description: 'Propose and approve managed policy revisions',
        rules: [{ zones: ['*'], actions: ['policy.read', 'policy.propose', 'policy.approve'] }],
      },
      'acme-solver': {
        description: 'DNS-01 challenges only',
        rules: [{ zones: ['*'], actions: ['dns.read', 'dns.record.write'], records: { hosts: ['_acme-challenge', '_acme-challenge.**'], types: ['TXT'] } }],
        rebase_on_save: true,
        ephemeral_ttl: '24h',
      },
    },
    bindings: [
      { role: 'viewer', team: 'ops', groups: ['dns-viewers', 'policy-admins'] },
      { role: 'policy-admin', team: 'security', groups: ['policy-admins'] },
    ],
    virtual_keys: [
      {
        id: 'acme-solver',
        app_id: 'vk_acme_7Q2M',
        key_sha256: 'a3f1c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0',
        description: 'Caddy and lego hosts for internal certificates',
        roles: ['acme-solver'],
        teams: ['security'],
        expires_at: ahead(83 * D),
        allowed_cidrs: ['10.20.0.0/16'],
      },
    ],
  },
};

const activeDoc: PolicyDocument = {
  zones: ['shop.example'],
  groups: {
    'web-pipelines': {
      description: 'CI that deploys the web front',
      members: [
        { issuer: 'aws', claims: { sub: ['arn:aws:iam::111111111111:role/ci-app'] } },
        { issuer: 'github', claims: { repository: ['acme/web'], ref: ['refs/heads/main'] } },
      ],
    },
    'web-humans': { members: [{ issuer: ENTRA, claims: { groups: ['2d4f6a8c-web-team'] } }] },
    'corporate-pipelines': { members: [{ issuer: 'aws', claims: { sub: ['arn:aws:iam::111111111111:role/ci-corporate'] } }] },
    platform: { members: [{ issuer: 'aws', claims: { sub: ['arn:aws:iam::222222222222:role/platform-*'] } }] },
    'platform-pipelines': {
      description: 'Azure DevOps service connections of the platform project',
      members: [{ issuer: 'ado', claims: { sub: ['sc://example-org/platform/*'] } }],
    },
  },
  roles: {
    'app-cname-writer': {
      description: 'Application CNAMEs and validation records',
      rules: [{ zones: ['example.com'], actions: ['dns.read', 'dns.record.write'], records: { hosts: ['*', '*.staging', '_*.*'], types: ['CNAME', 'TXT'] } }],
      max_changes_per_request: 20,
    },
    'corporate-writer': {
      rules: [{ zones: ['acme.example'], actions: ['dns.read', 'dns.record.write'], records: { types: ['A', 'AAAA', 'CNAME', 'APEX', 'TXT'] } }],
    },
    adopter: { description: 'Bring existing records under gate management', rules: [{ zones: ['example.com', 'acme.example', 'cloud.example'], actions: ['dns.record.adopt'] }] },
    'platform-writer': {
      description: 'Platform services: load balancer names and their certificate validation records',
      rules: [{ zones: ['cloud.example', 'mail.example'], actions: ['dns.read', 'dns.record.write'], records: { hosts: ['*.eu-central', '_*.*.eu-central', '*'], types: ['A', 'AAAA', 'CNAME', 'TXT'] } }],
      max_changes_per_request: 50,
    },
    'edge-writer': {
      description: 'Web team records of the edge zone (Route53)',
      rules: [{ zones: ['edge.example.org'], actions: ['dns.read', 'dns.record.write'], records: { types: ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV', 'CAA'] } }],
    },
    'redirect-writer': {
      description: 'URL forwards of the marketing names',
      rules: [{ zones: ['example.com', 'brand.example'], actions: ['dns.read', 'dns.forward.write'] }],
    },
    'shop-pipeline': {
      description: 'Shop deployment pipelines, each one in its own team',
      rules: [{ zones: ['shop.example'], actions: ['dns.read', 'dns.record.write'], records: { types: ['A', 'AAAA', 'CNAME', 'TXT'] } }],
    },
  },
  bindings: [
    { role: 'app-cname-writer', team: 'web', groups: ['web-pipelines', 'web-humans'] },
    { role: 'app-cname-writer', team: 'platform', groups: ['platform'] },
    { role: 'corporate-writer', team: 'corporate', groups: ['corporate-pipelines'], subjects: [{ issuer: ENTRA, claims: { preferred_username: ['bob@example.com'] } }] },
    { role: 'adopter', team: 'web', subjects: [{ issuer: ENTRA, claims: { preferred_username: ['bob@example.com', 'alice@example.com'] } }] },
    { role: 'platform-writer', team: 'platform', groups: ['platform-pipelines'] },
    { role: 'edge-writer', team: 'web', groups: ['web-humans'] },
    { role: 'redirect-writer', team: 'web', groups: ['web-humans'] },
    {
      role: 'shop-pipeline',
      team: '',
      team_from: { claim: 'sub', regex: '^repo:acme/([a-z0-9-]+):environment:production$', prefix: 'gh-' },
      subjects: [{ issuer: 'github', claims: { sub: ['repo:acme/shop-*:environment:production'] } }],
    },
  ],
  virtual_keys: [],
  delegated: {
    roles: {
      'gh-docs-site': {
        description: 'DNS names written by the docs-site pipeline.',
        rules: [{ zones: ['example.com'], actions: ['dns.read', 'dns.record.write', 'dns.record.adopt'], records: { hosts: ['docs', '_*.docs'], types: ['CNAME'] } }],
        owner: {
          delegation: 'ci-pipelines',
          managed_by: 'terraform',
          created_by: 'github:repo:acme/ci-stack:environment:production',
          created_at: '2026-10-30T09:12:00Z',
          updated_by: 'github:repo:acme/ci-stack:environment:production',
          updated_at: '2026-10-30T09:12:00Z',
        },
      },
    },
    bindings: {
      'gh-docs-site': {
        role: 'gh-docs-site',
        team: 'web',
        subjects: [{ issuer: 'github', claims: { sub: ['repo:acme/docs-site:environment:production'] } }],
        owner: {
          delegation: 'ci-pipelines',
          managed_by: 'terraform',
          created_by: 'github:repo:acme/ci-stack:environment:production',
          created_at: '2026-10-30T09:12:00Z',
          updated_by: 'github:repo:acme/ci-stack:environment:production',
          updated_at: '2026-10-30T09:12:00Z',
        },
      },
    },
  },
};

const clone = <T>(v: T): T => structuredClone(v);

const proposedDoc = clone(activeDoc);
proposedDoc.bindings.push({ role: 'app-cname-writer', team: 'corporate', groups: ['corporate-pipelines'] });
(proposedDoc.roles['app-cname-writer'] as Role).rules[0]!.records!.hosts = ['*', '*.staging', '_*.*', 'www'];
proposedDoc.groups['platform'] = { members: [{ issuer: 'aws', claims: { sub: ['arn:aws:iam::222222222222:role/platform-dns'] } }] };

const rejectedDoc = clone(activeDoc);
rejectedDoc.bindings = rejectedDoc.bindings.filter((b) => b.team !== 'platform');

interface Rev {
  s: RevisionSummary;
  doc: PolicyDocument;
  impact: ImpactItem[];
}

const revs: Rev[] = [
  {
    s: {
      id: 'rev_0009', parent_id: 'rev_0007', status: 'proposed', author: bob, created_at: ago(50),
      comment: 'Let corporate CI point www at the new CloudFront distribution; narrow platform to its DNS role.',
    },
    doc: proposedDoc,
    impact: [
      { kind: 'gain', who: 'corporate', role: 'app-cname-writer', zones: ['example.com'], actions: ['dns.record.write'], message: 'team corporate gains write on CNAME/TXT in example.com (via corporate-pipelines)' },
      { kind: 'loss', who: 'platform', role: 'app-cname-writer', zones: ['example.com'], actions: ['dns.record.write'], message: 'group platform no longer matches arn:aws:iam::222222222222:role/platform-ci (used 14 times in the last 30 days)' },
      { kind: 'warning', who: 'corporate', role: 'app-cname-writer', zones: ['example.com'], message: 'team corporate may create RRsets next to 9 owned by team web; ownership still applies' },
    ],
  },
  {
    s: {
      id: 'rev_0008', parent_id: 'rev_0006', status: 'rejected', author: dave, created_at: ago(4 * D),
      comment: 'Remove the platform binding, unused since the migration.',
      approvals: [{ by: alice, at: ago(4 * D - 3 * H), decision: 'reject', comment: 'Still used by platform-dns for api.staging.' }],
    },
    doc: rejectedDoc,
    impact: [
      { kind: 'loss', who: 'platform', role: 'app-cname-writer', zones: ['example.com'], actions: ['dns.read', 'dns.record.write'], message: 'team platform loses write on 2 owned RRsets (api.staging, status)' },
    ],
  },
  {
    s: {
      id: 'rev_0007', parent_id: 'rev_0006', status: 'active', author: alice, created_at: ago(6 * D),
      comment: 'Add the adopter role for bob (assets migration).',
      approvals: [{ by: bob, at: ago(6 * D - 2 * H), decision: 'approve', comment: 'OK, scoped to two zones.' }],
      activated_at: ago(6 * D - 2 * H + 5), activated_by: bob,
    },
    doc: activeDoc,
    impact: [{ kind: 'gain', who: 'bob@example.com', role: 'adopter', zones: ['example.com', 'acme.example'], actions: ['dns.record.adopt'], message: 'bob@example.com gains adopt on example.com and acme.example' }],
  },
  {
    s: {
      id: 'rev_0006', parent_id: 'rev_0005', status: 'superseded', author: alice, created_at: ago(15 * D),
      comment: 'Corporate team onto acme.example.',
      approvals: [{ by: dave, at: ago(15 * D - 1 * H), decision: 'approve' }],
      activated_at: ago(15 * D - 50), activated_by: alice,
    },
    doc: (() => { const d = clone(activeDoc); delete d.roles['adopter']; d.bindings = d.bindings.filter((b) => b.role !== 'adopter'); return d; })(),
    impact: [],
  },
  {
    s: {
      id: 'rev_0005', status: 'superseded', author: alice, created_at: ago(32 * D), comment: 'Initial managed policy.',
      approvals: [{ by: dave, at: ago(32 * D - 2 * H), decision: 'approve' }], activated_at: ago(32 * D - 2 * H), activated_by: alice,
    },
    doc: { groups: { 'web-pipelines': activeDoc.groups['web-pipelines']! }, roles: { 'app-cname-writer': activeDoc.roles['app-cname-writer']! }, bindings: [activeDoc.bindings[0]!], virtual_keys: [] },
    impact: [],
  },
];

const settings: EffectivePolicy['settings'] = { editable: true, require_approval: true, edit_max_age: '15m0s', require_amr: ['mfa'] };
const activeRev = () => revs.find((r) => r.s.status === 'active');

function lineDiff(a: string, b: string): string {
  const x = a.split('\n');
  const y = b.split('\n');
  const n = x.length;
  const m = y.length;
  const L: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--) L[i]![j] = x[i] === y[j] ? L[i + 1]![j + 1]! + 1 : Math.max(L[i + 1]![j]!, L[i]![j + 1]!);
  const out: string[] = ['--- active', '+++ proposed'];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && x[i] === y[j]) out.push(' ' + x[i++]), j++;
    else if (j < m && (i >= n || L[i]![j + 1]! > L[i + 1]![j]!)) out.push('+' + y[j++]);
    else out.push('-' + x[i++]);
  }
  // keep 3 lines of context around changes
  const keep = new Set<number>();
  out.forEach((l, k) => {
    if (k > 1 && (l[0] === '+' || l[0] === '-')) for (let c = k - 3; c <= k + 3; c++) keep.add(c);
  });
  const res: string[] = [out[0]!, out[1]!];
  let gap = false;
  for (let k = 2; k < out.length; k++) {
    if (keep.has(k)) {
      if (gap) res.push('@@');
      res.push(out[k]!);
      gap = false;
    } else gap = true;
  }
  return res.join('\n');
}

function detail(r: Rev): RevisionDetail {
  const parent = revs.find((p) => p.s.id === r.s.parent_id) ?? activeRev();
  const active = activeRev();
  return clone({
    ...r.s,
    document: r.doc,
    diff_yaml: parent && parent !== r ? lineDiff(toYAML(parent.doc), toYAML(r.doc)) : lineDiff('', toYAML(r.doc)),
    impact: r.impact,
    stale: r.s.status !== 'active' && r.s.status !== 'superseded' && !!active && r.s.parent_id !== active.s.id,
  });
}

function validate(doc: PolicyDocument): ValidationError[] {
  const errs: ValidationError[] = [];
  const baseRoles = Object.keys(base.document.roles);
  const allRoles = new Set([...baseRoles, ...Object.keys(doc.roles)]);
  const allGroups = new Set([...Object.keys(base.document.groups), ...Object.keys(doc.groups)]);
  for (const [name, g] of Object.entries(doc.groups)) {
    if (base.document.groups[name]) errs.push({ path: `groups.${name}`, message: `"${name}" is defined in the base layer` });
    if (!g.members.length) errs.push({ path: `groups.${name}.members`, message: 'a group needs at least one member' });
    g.members.forEach((m, i) => {
      if (!base.issuers.some((x) => x.name === m.issuer)) errs.push({ path: `groups.${name}.members[${i}].issuer`, message: `unknown issuer "${m.issuer}"` });
    });
  }
  for (const [name, r] of Object.entries(doc.roles)) {
    if (baseRoles.includes(name)) errs.push({ path: `roles.${name}`, message: `"${name}" is defined in the base layer` });
    r.rules.forEach((rule, i) => {
      rule.actions.forEach((a, k) => {
        if (a.startsWith('policy.')) errs.push({ path: `roles.${name}.rules[${i}].actions[${k}]`, message: 'policy.* actions can only be granted in the base layer' });
        else if (!base.bounds.actions.includes(a)) errs.push({ path: `roles.${name}.rules[${i}].actions[${k}]`, message: `"${a}" is outside the policy bounds` });
      });
      rule.zones.forEach((z, k) => {
        if (!base.bounds.zones.some((b) => zoneMatch(b, z))) errs.push({ path: `roles.${name}.rules[${i}].zones[${k}]`, message: `zone "${z}" is outside the policy bounds` });
      });
      if (!rule.zones.length) errs.push({ path: `roles.${name}.rules[${i}].zones`, message: 'at least one zone' });
      if (!rule.actions.length) errs.push({ path: `roles.${name}.rules[${i}].actions`, message: 'at least one action' });
    });
    if (r.ephemeral_ttl && !/^\d+(ns|us|ms|s|m|h)$/.test(r.ephemeral_ttl)) errs.push({ path: `roles.${name}.ephemeral_ttl`, message: 'Go duration expected, e.g. 24h' });
  }
  doc.bindings.forEach((b, i) => {
    if (!allRoles.has(b.role)) errs.push({ path: `bindings[${i}].role`, message: `unknown role "${b.role}"` });
    else if (b.role in base.document.roles && base.document.roles[b.role]!.rules.some((r) => r.actions.some((a) => a.startsWith('policy.')))) errs.push({ path: `bindings[${i}].role`, message: 'roles granting policy.* are bound in the base layer only' });
    if (b.team && b.team_from) errs.push({ path: `bindings[${i}].team`, message: 'team and team_from are exclusive' });
    else if (!b.team && !b.team_from) errs.push({ path: `bindings[${i}].team`, message: 'team is required' });
    if (b.team_from) {
      const at = `bindings[${i}].team_from`;
      if (!b.team_from.claim) errs.push({ path: `${at}.claim`, message: 'claim is required' });
      const re = b.team_from.regex;
      if (!re.startsWith('^') || !re.endsWith('$')) errs.push({ path: `${at}.regex`, message: 'the regex must be anchored with ^ and $' });
      else {
        try {
          const groups = (new RegExp(re + '|').exec('')?.length ?? 1) - 1;
          if (groups !== 1) errs.push({ path: `${at}.regex`, message: `exactly one capture group is required, found ${groups}` });
        } catch {
          errs.push({ path: `${at}.regex`, message: 'invalid regular expression' });
        }
      }
      if (b.team_from.prefix && !/^[a-z0-9][a-z0-9._-]*$/.test(b.team_from.prefix)) errs.push({ path: `${at}.prefix`, message: 'prefix must be lowercase letters, digits, . _ -' });
    }
    (b.groups ?? []).forEach((g, k) => {
      if (!allGroups.has(g)) errs.push({ path: `bindings[${i}].groups[${k}]`, message: `unknown group "${g}"` });
    });
    if (!b.groups?.length && !b.subjects?.length) errs.push({ path: `bindings[${i}]`, message: 'bind at least one group or subject' });
  });
  const seen = new Set<string>();
  (doc.zones ?? []).forEach((z, i) => {
    const at = `zones[${i}]`;
    if (seen.has(z)) errs.push({ path: at, message: `zone "${z}" is listed twice` });
    seen.add(z);
    if (!base.bounds.zones.some((b) => zoneMatch(b, z))) errs.push({ path: at, message: `zone "${z}" is outside policy.bounds.zones` });
    else if (!discovered.includes(z)) errs.push({ path: at, message: `zone "${z}" was not found in the account by zone discovery` });
  });
  doc.virtual_keys.forEach((k, i) => {
    if (!k.id) errs.push({ path: `virtual_keys[${i}].id`, message: 'id is required' });
    if (!k.key_sha256) errs.push({ path: `virtual_keys[${i}].key_sha256`, message: 'generate a key first' });
    k.roles.forEach((r, j) => {
      if (!allRoles.has(r)) errs.push({ path: `virtual_keys[${i}].roles[${j}]`, message: `unknown role "${r}"` });
    });
  });
  return errs;
}

let nextRev = 10;

const managedZones = () => new Set([...base.zones, ...(activeRev()?.doc.zones ?? [])]);

function zoneImpact(before: string[], after: string[]): ImpactItem[] {
  const items: ImpactItem[] = [];
  for (const z of after.filter((x) => !before.includes(x)))
    items.push({ kind: 'gain', who: 'zone ' + z, zones: [z], message: `zone ${z} becomes managed: its records stay foreign until adopted` });
  for (const z of before.filter((x) => !after.includes(x))) {
    const owned = inventories.find((i) => i.zone === z)?.rrsets.filter((r) => r.owner).length ?? 0;
    items.push({ kind: 'loss', who: 'zone ' + z, zones: [z], message: `zone ${z} is no longer managed` });
    if (owned) items.push({ kind: 'warning', who: 'zone ' + z, zones: [z], message: `zone ${z} stops being managed while ${owned} RRset(s) are owned there: they become read-only through the gate` });
  }
  return items;
}

function find(id: string): Rev {
  const r = revs.find((x) => x.s.id === id);
  if (!r) throw new ApiError(404, 'not_found', `revision ${id} not found`);
  return r;
}

function groupsOf(issuer: string, claims: Record<string, string[]>, doc: PolicyDocument): string[] {
  const all = { ...base.document.groups, ...doc.groups };
  const matches = (m: { issuer: string; claims?: Record<string, string[]> }) =>
    m.issuer === issuer &&
    Object.entries(m.claims ?? {}).every(([k, globs]) => (claims[k] ?? []).some((v) => globs.some((g) => claimMatch(g, v))));
  return Object.entries(all).filter(([, g]) => g.members.some(matches)).map(([n]) => n);
}

function ruleCovers(role: Role, action: string, zone: string, host?: string, type?: string): number {
  return role.rules.findIndex(
    (r) =>
      r.actions.includes(action) &&
      r.zones.some((z) => zoneMatch(z, zone)) &&
      (!host || !r.records?.hosts?.length || r.records.hosts.some((h) => hostMatch(h, host))) &&
      (!type || action === 'dns.forward.write' || !r.records?.types?.length || r.records.types.includes(type)),
  );
}

function protectedHit(zone: string, host?: string, type?: string) {
  if (!host || !type) return undefined;
  return base.protected.find((p) => p.zones.some((z) => zoneMatch(z, zone)) && p.hosts.some((h) => hostMatch(h, host)) && p.types.includes(type));
}

function derivedTeam(b: Binding, claims: Record<string, string[]>): string | undefined {
  if (!b.team_from) return undefined;
  const v = claims[b.team_from.claim]?.[0] ?? '';
  const m = new RegExp(b.team_from.regex).exec(v);
  return m?.[1] ? (b.team_from.prefix ?? '') + m[1].toLowerCase() : teamLabel('', b.team_from);
}

function explain(req: ExplainRequest): ExplainResponse {
  const doc = req.revision_id ? find(req.revision_id).doc : (activeRev()?.doc ?? { groups: {}, roles: {}, bindings: [], virtual_keys: [] });
  const claims = req.subject.claims ?? {};
  const groups = groupsOf(req.subject.issuer, claims, doc);
  const matchesSubject = (b: Binding) =>
    (b.groups ?? []).some((g) => groups.includes(g)) ||
    (b.subjects ?? []).some((m) => m.issuer === req.subject.issuer && Object.entries(m.claims ?? {}).every(([k, gl]) => (claims[k] ?? []).some((v) => gl.some((g) => claimMatch(g, v)))));
  const layers: [string, Binding[], Record<string, Role>][] = [
    ['base', base.document.bindings, base.document.roles],
    ['managed', doc.bindings, { ...base.document.roles, ...doc.roles }],
  ];
  const bindings: string[] = [];
  let matched: string | undefined;
  let layer: string | undefined;
  for (const [ln, bs, roles] of layers) {
    for (const b of bs.filter(matchesSubject)) {
      bindings.push(`${b.role}@${derivedTeam(b, claims) ?? b.team}`);
      const role = roles[b.role];
      if (!matched && role) {
        const i = ruleCovers(role, req.action, req.zone, req.host, req.type);
        if (i >= 0) {
          matched = `roles.${b.role}.rules[${i}]`;
          layer = ln;
        }
      }
    }
  }
  const prot = req.action === 'dns.record.write' ? protectedHit(req.zone, req.host, req.type) : undefined;
  if (prot) {
    return { allowed: false, groups, bindings, denied: `protected: zones=${prot.zones.join(',')} hosts=${prot.hosts.join(',')} types=${prot.types.join(',')}`, layer: 'base' };
  }
  if (!matched) return { allowed: false, groups, bindings, denied: bindings.length ? 'no rule of the bound roles covers this action and record' : 'no binding matches this subject' };
  return { allowed: true, groups, bindings, matched, layer };
}

function whoCan(q: { zone: string; host: string; type: string; action?: string }): WhoCanResponse {
  const action = q.action ?? 'dns.record.write';
  const doc = activeRev()?.doc ?? { groups: {}, roles: {}, bindings: [], virtual_keys: [] };
  const roles = { ...base.document.roles, ...doc.roles };
  const prot = action === 'dns.record.write' && !!protectedHit(q.zone, q.host, q.type);
  const entries: WhoCanResponse['entries'] = [];
  if (!prot) {
    for (const [layer, bs] of [['base', base.document.bindings], ['managed', doc.bindings]] as const) {
      for (const b of bs) {
        const role = roles[b.role];
        if (role && ruleCovers(role, action, q.zone, q.host, q.type) >= 0) {
          const keys = [...base.document.virtual_keys, ...doc.virtual_keys].filter((k) => k.roles.includes(b.role) && k.teams.includes(b.team)).map((k) => k.id);
          entries.push({ role: b.role, team: b.team, team_from: b.team_from, layer, groups: b.groups, subjects: b.subjects, virtual_keys: keys.length ? keys : undefined });
        }
      }
    }
  }
  return { protected: prot, entries };
}

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function randomToken(n: number): string {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return [...a].map((b) => 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 56]).join('');
}

function needRight(right: 'propose' | 'approve') {
  if (asReader) throw new ApiError(403, 'forbidden', `policy.${right} is required`);
}

// ---------------------------------------------------------------- adoption

const zoneVersion: Record<string, number> = {};
// ?conflict=1 makes the first adoption fail as if the zone changed meanwhile.
let conflictPending = new URLSearchParams(window.location.search).get('conflict') === '1';

const isProtected = (zone: string, r: RRset) =>
  r.protected || base.protected.some((p) => p.zones.some((z) => zoneMatch(z, zone)) && p.hosts.some((h) => hostMatch(h, r.host)) && p.types.includes(r.type));

function candidate(zone: string, r: RRset, owner: string): AdoptCandidate {
  const c: AdoptCandidate = { host: r.host, type: r.type, ttl: r.ttl, values: [...r.values], forward: r.forward, status: r.status, adoptable: false };
  if (r.status !== 'foreign') c.reason = r.owner === owner ? 'already_owned' : 'owned_by_other_team';
  else if (r.type === 'SOA') c.reason = 'server_managed';
  else if (r.read_only) c.reason = r.read_only;
  else if (isProtected(zone, r)) c.reason = 'protected';
  else if (r.type === 'CNAME' && r.values.some((v) => !v.endsWith('.'))) c.reason = 'relative_target';
  else c.adoptable = true;
  return c;
}

function select(zone: string, sel: AdoptSelection): RRset[] {
  const inv = managedZones().has(zone) ? findInv(zone) : undefined;
  if (!inv) throw new ApiError(404, 'not_found', `zone ${zone} is not managed`);
  const explicit = new Set((sel.rrsets ?? []).map((r) => `${r.host}/${r.type}`));
  const byFilter = (r: RRset) =>
    (sel.hosts?.length || sel.types?.length) &&
    (!sel.hosts?.length || sel.hosts.some((h) => hostMatch(h, r.host))) &&
    (!sel.types?.length || sel.types.includes(r.type));
  return inv.rrsets.filter((r) => explicit.has(`${r.host}/${r.type}`) || byFilter(r));
}

function adoptPreview(zone: string, sel: AdoptSelection): AdoptPreview {
  if (asReader) throw new ApiError(403, 'forbidden', 'dns.record.adopt is required');
  const owner = sel.owner || me.teams[0] || '';
  const v = zoneVersion[zone] ?? 1;
  return { zone, owner, candidates: select(zone, sel).map((r) => candidate(zone, r, owner)), preview_token: `pt_${zone}_${v}` };
}

function adoptApply(zone: string, req: AdoptApply): AdoptResult {
  if (asReader) throw new ApiError(403, 'forbidden', 'dns.record.adopt is required');
  if (!req.comment.trim()) throw new ApiError(400, 'invalid', 'a comment is required');
  const v = zoneVersion[zone] ?? 1;
  if (conflictPending || req.preview_token !== `pt_${zone}_${v}`) {
    conflictPending = false;
    zoneVersion[zone] = v + 1;
    throw new ApiError(409, 'adopt_conflict', 'the zone changed since the preview');
  }
  const owner = req.owner || me.teams[0] || '';
  const rrs = select(zone, { rrsets: req.rrsets });
  if (rrs.some((r) => !candidate(zone, r, owner).adoptable)) throw new ApiError(409, 'adopt_conflict', 'a selected record set is no longer adoptable');
  const actor: Actor = { subject: me.subject, name: me.name, category: me.category };
  const requestId = 'req_' + randomToken(10).toUpperCase();
  const now = new Date().toISOString();
  for (const r of rrs) Object.assign(r, { status: 'managed', owner, adopted: true, created_by: actor, created_at: now, last_request_id: requestId });
  audit.unshift({
    time: now, request_id: requestId, actor, teams: [owner], action: 'adopt', zone, decision: 'allow',
    changes: rrs.map((r) => ({ op: 'adopt' as const, host: r.host, type: r.type, new_ttl: r.ttl, new_values: r.forward ? undefined : [...r.values], new_forward: r.forward })),
  });
  zoneVersion[zone] = v + 1;
  return { zone, owner, adopted: rrs.map((r) => ({ host: r.host, type: r.type })), request_id: requestId };
}

const tfName = (r: RRset) =>
  ((r.host === '@' ? 'apex' : r.host).replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'apex') + '_' + r.type.toLowerCase();

function terraform(zone: string, q: TerraformQuery): string {
  const inv = managedZones().has(zone) ? findInv(zone) : undefined;
  if (!inv) throw new ApiError(404, 'not_found', `zone ${zone} is not managed`);
  const rrs = inv.rrsets.filter(
    (r) =>
      r.status === 'managed' &&
      (!q.team || r.owner === q.team) &&
      (!q.hosts?.length || q.hosts.some((h) => hostMatch(h, r.host))) &&
      (!q.types?.length || q.types.includes(r.type)),
  );
  const lines = [
    `# dns-gate export of ${zone}${q.team ? ` for team ${q.team}` : ''}, ${new Date().toISOString().slice(0, 10)}`,
    '# Provider: registry.terraform.io/KamorionLabs/dnsgate.',
    '',
  ];
  for (const r of rrs) {
    const n = tfName(r);
    if (r.forward) {
      const f = r.forward;
      lines.push(
        'import {',
        `  to = dnsgate_url_forward.${n}`,
        `  id = "${zone}/${r.host}"`,
        '}',
        '',
        `resource "dnsgate_url_forward" "${n}" {`,
        `  zone = "${zone}"`,
        `  name = "${r.host}"`,
        `  type = "${f.type}"`,
        `  url  = ${JSON.stringify(f.url)}`,
        ...(f.title ? [`  title = ${JSON.stringify(f.title)}`] : []),
        ...(f.keywords ? [`  keywords = ${JSON.stringify(f.keywords)}`] : []),
        ...(f.description ? [`  description = ${JSON.stringify(f.description)}`] : []),
        '}',
        '',
      );
      continue;
    }
    lines.push(
      'import {',
      `  to = dnsgate_record_set.${n}`,
      `  id = "${zone}/${r.host}/${r.type}"`,
      '}',
      '',
      `resource "dnsgate_record_set" "${n}" {`,
      `  zone   = "${zone}"`,
      `  name   = "${r.host}"`,
      `  type   = "${r.type}"`,
      `  ttl    = ${r.ttl}`,
      `  values = [${r.values.map((v) => JSON.stringify(v)).join(', ')}]`,
      '}',
      '',
    );
  }
  if (!rrs.length) lines.push('# No record set held by the gate matches this export.');
  return lines.join('\n');
}

// ---------------------------------------------------------------- DNS writes

// Content hash of a record set (stands in for dns.ContentHash).
function contentHash(r: Pick<RRset, 'ttl' | 'values' | 'alias' | 'forward'>): string {
  const f = r.forward;
  const vals = f
    ? [`forward ${f.type} ${f.url} ${f.title ?? ''} ${f.keywords ?? ''} ${f.description ?? ''}`]
    : r.alias
      ? [`alias ${r.alias.hosted_zone_id} ${r.alias.target}`]
      : [...r.values].sort();
  let h = 0x811c9dc5;
  for (const ch of `ttl=${r.ttl}\n${vals.join('\n')}`) h = Math.imul(h ^ ch.charCodeAt(0), 0x01000193) >>> 0;
  return h.toString(16).padStart(8, '0');
}

/** Provider fields the inventory carries: SOA records are the provider's, every record set has its hash. */
function decorate(inv: ZoneInventory) {
  inv.provider ??= 'eurodns';
  for (const r of inv.rrsets) {
    if (r.type === 'SOA') r.read_only ??= 'server_managed';
    r.hash = contentHash(r);
  }
}

interface StoredPlan {
  zone: string;
  subject: string;
  version: number;
  changes: RRsetChange[];
  result: PlanResult;
}
const plans = new Map<string, StoredPlan>();
// ?writeconflict=1 makes the first apply fail as if the zone changed meanwhile.
let writeConflict = new URLSearchParams(window.location.search).get('writeconflict') === '1';

/** Whether the forwards of a zone answer HTTPS, as GET /forwards tells it. */
function httpsStatus(zone: string): HTTPSRedirect | undefined {
  const inv = findInv(zone);
  if (!inv || !managedZones().has(zone)) return undefined;
  if ((inv.provider ?? 'eurodns') === 'route53') return { status: 'unsupported' };
  const h = httpsOf[zone];
  if (h?.status === 'no_forward' || (h?.status === 'active' && !inv.rrsets.some(isForward))) return { ...h, status: 'no_forward' };
  return h ?? { status: 'inactive' };
}

function forwardRefusal(zone: string, c: RRsetChange): { reason: string; message: string } | null {
  if (!isForward(c) || c.delete) return null;
  if (httpsStatus(zone)?.status === 'unsupported') return { reason: 'invalid', message: 'the DNS provider of this zone has no URL forwards' };
  const f = c.forward;
  if (!f) return { reason: 'invalid_forward', message: 'a forward is required' };
  if (!['301', '302', 'frame'].includes(f.type)) return { reason: 'invalid_forward', message: `type "${f.type}" is not one of 301, 302, frame` };
  if (urlError(f.url)) return { reason: 'invalid_forward', message: `url "${f.url}" must be an absolute http:// or https:// URL` };
  if (f.type !== 'frame' && (f.title || f.keywords || f.description)) return { reason: 'invalid_forward', message: 'title, keywords and description only apply to frame forwards' };
  const st = httpsStatus(zone)?.status;
  if (c.require_https && st !== 'active' && st !== 'pending' && st !== 'no_forward') {
    return { reason: 'https_unavailable', message: `the forwards of ${zone} answer plain HTTP only (no HTTPS redirect subscription)` };
  }
  return null;
}

function refusal(c: RRsetChange, cur: RRset | undefined): { reason: string; message: string } | null {
  const fail = (reason: string, message: string) => ({ reason, message });
  if (c.must_not_exist && cur) return cur.status === 'foreign' ? fail('foreign_rrset', `${c.host} ${c.type} exists and is not managed by the gate`) : fail('precondition', `${c.host} ${c.type} already exists`);
  if (!c.must_not_exist && !cur) return fail('not_found', `${c.host} ${c.type} does not exist`);
  if (c.expected_hash && cur && cur.hash !== c.expected_hash) return fail('precondition', `${c.host} ${c.type} changed since it was read`);
  if (cur?.read_only) return fail('read_only', `${c.host} ${c.type} is read-only (${cur.read_only})`);
  if (cur?.protected) return fail('forbidden', `${c.host} ${c.type} is protected`);
  if (cur?.status === 'foreign') return fail('foreign_rrset', `${c.host} ${c.type} is not managed by the gate`);
  if (cur?.status === 'tainted' || cur?.status === 'missing') return fail('tainted', `${c.host} ${c.type} changed outside the gate`);
  if (cur?.owner && !me.teams.includes(cur.owner)) return fail('not_owner', `${c.host} ${c.type} is owned by team ${cur.owner}`);
  return null;
}

function planChanges(zone: string, input: RRsetChange[], team?: string): PlanResult {
  if (team && !me.teams.includes(team)) throw new ApiError(403, 'not_team_member', `team ${team} is not one of your teams`);
  // what goes over the wire: plain JSON
  const changes = JSON.parse(JSON.stringify(input)) as RRsetChange[];
  const inv = managedZones().has(zone) ? findInv(zone) : undefined;
  if (!inv) throw new ApiError(404, 'not_found', `zone ${zone} is not managed`);
  decorate(inv);
  if (!changes.length) throw new ApiError(400, 'invalid', 'between 1 and 100 changes are required');
  const out: PlanChange[] = [];
  let first: { reason: string; message: string } | null = null;
  for (const c of changes) {
    const cur = inv.rrsets.find((r) => r.host === c.host && r.type === c.type);
    const op = c.delete ? 'delete' : cur ? 'update' : 'create';
    const tomb = !cur ? (inv.tombstones ?? []).find((t) => t.host === c.host && t.type === c.type) : undefined;
    const why =
      forwardRefusal(zone, c) ??
      refusal(c, cur) ??
      (cur?.owner && team && cur.owner !== team ? { reason: 'not_owner', message: `${c.host} ${c.type} is owned by team ${cur.owner}, not ${team}` } : null) ??
      (tomb && !(team ? [team] : me.teams).includes(tomb.team) ? { reason: 'not_owner', message: `${c.host} ${c.type} was deleted recently and is reserved for team ${tomb.team}` } : null) ??
      (rbacAllows(me, zone, c.host, c.type)
        ? null
        : { reason: 'forbidden', message: `${isForward(c) ? 'dns.forward.write' : 'dns.record.write'} not granted on ${c.host} ${c.type}` });
    first ??= why;
    out.push({
      op,
      host: c.host,
      type: c.type,
      old: cur ? { ttl: cur.ttl, values: [...cur.values], alias: cur.alias, forward: cur.forward } : null,
      new: c.delete ? null : c.forward ? { ttl: 0, values: [], forward: c.forward } : { ttl: c.ttl ?? cur?.ttl ?? 3600, values: c.values ?? [], alias: c.alias },
      ...(why ?? {}),
    });
  }
  const version = zoneVersion[zone] ?? 1;
  const result: PlanResult = { zone, allowed: !first, reason: first?.reason, message: first?.message, changes: out, zone_version: version, team };
  if (!first) {
    result.plan_id = 'pl_' + randomToken(12);
    plans.set(result.plan_id, { zone, subject: me.subject, version, changes, result });
  }
  return result;
}

function applyPlan(zone: string, planId: string, team?: string): PlanResult {
  const p = plans.get(planId);
  if (!p || p.zone !== zone) throw new ApiError(404, 'plan_not_found', 'unknown or already used plan_id: plan again');
  if (team && p.result.team && team !== p.result.team) throw new ApiError(400, 'team_mismatch', `the plan was made for team ${p.result.team}, not ${team}`);
  plans.delete(planId);
  const inv = findInv(zone)!;
  const owner = p.result.team ?? team ?? me.default_team ?? me.teams[0];
  if (writeConflict || (zoneVersion[zone] ?? 1) !== p.version) {
    writeConflict = false;
    // someone else changed the first record set meanwhile
    const moved = inv.rrsets.find((r) => p.changes.some((c) => c.host === r.host && c.type === r.type));
    if (moved) {
      moved.ttl = moved.ttl === 300 ? 600 : 300;
      moved.updated_by = bob;
      moved.updated_at = new Date().toISOString();
      decorate(inv);
    }
    zoneVersion[zone] = (zoneVersion[zone] ?? 1) + 1;
    throw new ApiError(412, 'precondition', 'the zone changed since the plan was made');
  }
  const actor: Actor = { subject: me.subject, name: me.name, category: me.category };
  const requestId = 'req_' + randomToken(10).toUpperCase();
  const now = new Date().toISOString();
  for (const c of p.changes) {
    const i = inv.rrsets.findIndex((r) => r.host === c.host && r.type === c.type);
    if (c.delete) {
      if (i >= 0) {
        const gone = inv.rrsets[i]!;
        if (gone.owner) {
          inv.tombstones = [...(inv.tombstones ?? []).filter((t) => t.host !== gone.host || t.type !== gone.type), { host: gone.host, type: gone.type, team: gone.owner, deleted_by: actor, deleted_at: now, expires_at: ahead(7 * D) }];
        }
        inv.rrsets.splice(i, 1);
      }
    } else if (i >= 0) {
      Object.assign(inv.rrsets[i]!, { ttl: c.forward ? 0 : c.ttl, values: c.values ?? [], forward: c.forward, updated_by: actor, updated_at: now, last_request_id: requestId, status: 'managed' });
    } else {
      inv.tombstones = (inv.tombstones ?? []).filter((t) => t.host !== c.host || t.type !== c.type);
      inv.rrsets.push({
        host: c.host, type: c.type, ttl: c.forward ? 0 : (c.ttl ?? 3600), values: c.values ?? [], forward: c.forward, status: 'managed', protected: false, owner,
        created_by: actor, created_at: now, adopted: false, last_request_id: requestId,
      });
    }
  }
  decorate(inv);
  inv.last_synced_at = now;
  zoneVersion[zone] = p.version + 1;
  audit.unshift({
    time: now, request_id: requestId, actor, teams: me.teams, action: 'applyRRsets', zone, decision: 'allow',
    changes: p.result.changes.map((c) => ({
      op: c.op, host: c.host, type: c.type,
      old_ttl: c.old?.ttl, old_values: c.old?.forward ? undefined : c.old?.values, old_forward: c.old?.forward ?? undefined,
      new_ttl: c.new?.ttl, new_values: c.new?.forward ? undefined : c.new?.values, new_forward: c.new?.forward ?? undefined,
    })),
  });
  return { ...p.result, request_id: requestId };
}

// ------------------------------------------------------------ teams and transfers

const declaredTeams: Record<string, { description: string; roles: string[]; groups?: string[] }> = {
  web: { description: 'Web shop: people and deployment pipelines', roles: ['app-cname-writer', 'edge-writer'], groups: ['web-humans'] },
  platform: { description: 'Shared platform: load balancers, certificates', roles: ['edge-writer'], groups: ['platform-ops'] },
  corporate: { description: 'Corporate sites', roles: ['app-cname-writer'], groups: ['dns-corporate'] },
  security: { description: 'Certificates and ACME challenges', roles: ['acme'] },
  ops: { description: 'Operations, read-only on every zone', roles: ['viewer'], groups: ['dns-viewers'] },
};

function ownedCounts(): Record<string, Record<string, { rrsets: number; tombstones: number }>> {
  const out: Record<string, Record<string, { rrsets: number; tombstones: number }>> = {};
  const add = (team: string, zone: string, k: 'rrsets' | 'tombstones') => {
    out[team] ??= {};
    out[team][zone] ??= { rrsets: 0, tombstones: 0 };
    out[team][zone][k]++;
  };
  for (const inv of inventories) {
    if (!managedZones().has(inv.zone)) continue;
    for (const r of inv.rrsets) if (r.owner) add(r.owner, inv.zone, 'rrsets');
    for (const t of inv.tombstones ?? []) add(t.team, inv.zone, 'tombstones');
  }
  return out;
}

function teamInfos(): TeamInfo[] {
  const counts = ownedCounts();
  const total = (t: string) => Object.values(counts[t] ?? {}).reduce((n, z) => n + z.rrsets, 0);
  const canSeeMembers = me.permissions?.some((p) => p.actions.includes('policy.read')) ?? false;
  const out: TeamInfo[] = Object.entries(declaredTeams).map(([name, t]) => ({
    name, kind: 'declared', layer: name === 'corporate' ? 'managed' : 'base', description: t.description, roles: t.roles, rrsets: total(name),
    members: canSeeMembers ? { groups: t.groups ?? [], subjects: name === 'web' ? [{ issuer: 'github', claims: { sub: ['repo:acme/web:*'] } }] : [] } : undefined,
    virtual_keys: name === 'security' ? ['acme-solver'] : undefined,
  }));
  out.push({ name: 'ci-*', kind: 'family', family: { claim: 'sub', regex: '^repo:acme/([a-z0-9-]+):', prefix: 'ci-' }, roles: ['app-cname-writer'], rrsets: 0 });
  for (const name of Object.keys(counts).sort()) {
    if (declaredTeams[name]) continue;
    out.push({ name, kind: 'store', roles: [], rrsets: total(name), warning: 'owns RRsets but no binding, virtual key or declaration names it' });
  }
  return out;
}

interface StoredTransfer extends Transfer {
  requesterSubject: string;
}

// ?second=1 requires a second approver for transfers (ownership.require_second_approver).
const secondApprover = new URLSearchParams(window.location.search).get('second') === '1';

const transfers: StoredTransfer[] = [];
const addTransfer = (t: Omit<Transfer, 'can_decide'>) => transfers.push({ ...t, can_decide: false, requesterSubject: t.requester.subject });
addTransfer({
  id: 'tr-1762300000000-a1b2c3d4e5', kind: 'rrsets', zone: 'example.com', from_team: 'web', to_team: 'platform', status: 'proposed',
  rrsets: [{ host: '_3f1c9a7b2d.www', type: 'CNAME' }], comment: 'Certificate validation records move to the platform team, which renews the certificates now.',
  requester: bob, created_at: ago(5 * H), expires_at: ahead(7 * D - 5 * H),
});
addTransfer({
  id: 'tr-1762200000000-b2c3d4e5f6', kind: 'rrsets', zone: 'example.com', from_team: 'corporate', to_team: 'web', status: 'proposed',
  rrsets: [{ host: 'old-careers', type: 'CNAME', tombstone: true }], comment: 'The careers page is now part of the web shop.',
  requester: alice, created_at: ago(3 * H), expires_at: ahead(7 * D - 3 * H),
});
addTransfer({
  id: 'tr-1762100000000-c3d4e5f6a7', kind: 'rename', from_team: 'data', to_team: 'platform', status: 'proposed', rrsets: [],
  comment: 'The data team was merged into platform.', requester: dave, created_at: ago(D), expires_at: ahead(6 * D),
});
addTransfer({
  id: 'tr-1761900000000-d4e5f6a7b8', kind: 'rrsets', zone: 'example.com', from_team: 'platform', to_team: 'web', status: 'applied', moved: 1,
  rrsets: [{ host: 'shop', type: 'CNAME' }], comment: 'Records first adopted by the wrong team.', requester: carol, created_at: ago(4 * D),
  expires_at: ahead(3 * D), decided_by: alice, decided_at: ago(4 * D - 2 * H), decision_comment: 'Checked with the shop team.',
});
addTransfer({
  id: 'tr-1762000000000-f6a7b8c9d0', kind: 'rrsets', zone: 'edge.example.org', from_team: 'platform', to_team: 'web', status: 'applying',
  rrsets: [{ host: 'cdn', type: 'CNAME' }], comment: 'The CDN entry belongs to the web shop.', requester: carol, created_at: ago(2 * H),
  expires_at: ahead(7 * D), decided_by: bob, decided_at: ago(20), error: 'zone edge.example.org is locked by another write',
});
addTransfer({
  id: 'tr-1761800000000-e5f6a7b8c9', kind: 'rrsets', zone: 'example.com', from_team: 'web', to_team: 'corporate', status: 'failed',
  rrsets: [{ host: 'www', type: 'CNAME' }], comment: 'Move the homepage to corporate.', requester: dave, created_at: ago(6 * D),
  expires_at: ahead(D), decided_by: bob, decided_at: ago(6 * D - H), error: 'www CNAME changed since the request',
});

const ownershipApprover = (zone?: string) => !!zone && (me.permissions ?? []).some((p) => p.actions.includes('dns.ownership.approve') && p.zones.some((z) => zoneMatch(z, zone)));
const writes = (zone?: string) => !!zone && (me.permissions ?? []).some((p) => p.actions.includes('dns.record.write') && p.zones.some((z) => zoneMatch(z, zone)));
const policyApprover = () => (me.permissions ?? []).some((p) => p.actions.includes('policy.approve'));

function view(t: StoredTransfer): Transfer {
  const { requesterSubject, ...rest } = t;
  const mayDecide = t.kind === 'rename' ? policyApprover() : (me.teams.includes(t.from_team) && writes(t.zone)) || ownershipApprover(t.zone);
  const status = t.status === 'proposed' && new Date(t.expires_at).getTime() <= Date.now() ? 'expired' : t.status;
  const other = !secondApprover || requesterSubject !== me.subject;
  return {
    ...rest, status, can_decide: status === 'proposed' && other && me.category === 'human' && mayDecide,
    self_approved: !!t.decided_by && t.status !== 'rejected' && t.decided_by.subject === requesterSubject,
  };
}

function findTransfer(id: string): StoredTransfer {
  const t = transfers.find((x) => x.id === id);
  if (!t) throw new ApiError(404, 'not_found', `unknown transfer ${id}`);
  return t;
}

function listTransfers(q: TransferQuery): TransferPage {
  const all = [...transfers].sort((a, b) => b.created_at.localeCompare(a.created_at)).map(view);
  return { transfers: all.filter((t) => (!q.status || t.status === q.status) && (!q.zone || t.zone === q.zone)).slice(0, q.limit ?? 50) };
}

function teamDetail(name: string): TeamDetail {
  const info = teamInfos().find((t) => t.name === name);
  if (!info) throw new ApiError(404, 'not_found', `unknown team ${name}`);
  const counts = ownedCounts()[name] ?? {};
  const visible = me.permissions?.some((p) => p.actions.includes('policy.read')) || me.teams.includes(name);
  return {
    ...info,
    owned: Object.entries(counts).map(([zone, c]) => ({ zone, ...c })),
    transfers: transfers.filter((t) => t.status === 'proposed' && (t.from_team === name || t.to_team === name)).map(view),
    permissions: visible ? info.roles.flatMap((r) => rolePerms(r)) : undefined,
  };
}

function rolePerms(role: string) {
  const fromMe = (me.permissions ?? []).filter((p) => p.role === role);
  if (fromMe.length) return fromMe;
  const def = base.document.roles[role] ?? activeRev()?.doc.roles[role];
  return (def?.rules ?? []).map((r) => ({ role, zones: r.zones, actions: r.actions, hosts: r.records?.hosts ?? [], types: r.records?.types ?? [] }));
}

function proposeTransfer(zone: string, req: TransferProposal): Transfer {
  const inv = findInv(zone);
  if (!inv || !managedZones().has(zone)) throw new ApiError(404, 'not_found', 'zone not managed by the gate');
  if (!writes(zone) && !ownershipApprover(zone)) throw new ApiError(403, 'forbidden', `dns.record.write or dns.ownership.approve is required on ${zone}`);
  if (!req.comment.trim()) throw new ApiError(400, 'invalid', 'a comment is required');
  let from = '';
  const rrsets = req.rrsets.map((r) => {
    const cur = inv.rrsets.find((x) => x.host === r.host && x.type === r.type && x.status !== 'foreign');
    const tomb = (inv.tombstones ?? []).find((t) => t.host === r.host && t.type === r.type);
    const team = cur?.owner ?? tomb?.team;
    if (!team) throw new ApiError(404, 'not_found', `${r.host} ${r.type} is not owned by a team in ${zone}`);
    if (from && team !== from) throw new ApiError(400, 'invalid', `the RRsets of a transfer must belong to one team (${from} and ${team})`);
    from = team;
    return { host: r.host, type: r.type, hash: cur?.hash, tombstone: !cur };
  });
  if (from === req.to_team) throw new ApiError(400, 'invalid', `the RRsets already belong to team ${from}`);
  if (!ownershipApprover(zone) && !me.teams.includes(from) && !me.teams.includes(req.to_team)) {
    throw new ApiError(403, 'not_owner', `only members of team ${from} or ${req.to_team} (or dns.ownership.approve holders) may request this transfer`);
  }
  const t: StoredTransfer = {
    id: `tr-${Date.now()}-${randomToken(10).toLowerCase()}`, kind: 'rrsets', zone, from_team: from, to_team: req.to_team, rrsets, status: 'proposed',
    comment: req.comment, requester: { subject: me.subject, name: me.name, category: me.category }, requesterSubject: me.subject,
    created_at: new Date().toISOString(), expires_at: ahead(7 * D), can_decide: false,
  };
  transfers.push(t);
  if (req.apply) {
    if (secondApprover) throw new ApiError(400, 'invalid', 'apply: a second approver is required (ownership.require_second_approver)');
    return decideTransfer(t.id, true, req.comment);
  }
  return view(t);
}

function moveOwnership(t: Transfer): number {
  let moved = 0;
  for (const inv of inventories) {
    if (t.kind === 'rrsets' && inv.zone !== t.zone) continue;
    for (const r of inv.rrsets) {
      if (r.owner === t.from_team && (t.kind === 'rename' || t.rrsets.some((x) => !x.tombstone && x.host === r.host && x.type === r.type))) {
        r.owner = t.to_team;
        moved++;
      }
    }
    for (const tb of inv.tombstones ?? []) {
      if (tb.team === t.from_team && (t.kind === 'rename' || t.rrsets.some((x) => x.tombstone && x.host === tb.host && x.type === tb.type))) {
        tb.team = t.to_team;
        moved++;
      }
    }
  }
  return moved;
}

function decideTransfer(id: string, approve: boolean, comment: string): Transfer {
  const t = findTransfer(id);
  const v = view(t);
  if (v.status !== 'proposed') throw new ApiError(412, 'precondition', `transfer ${id} is ${v.status}`);
  const self = t.requesterSubject === me.subject;
  if (approve && self && secondApprover) throw new ApiError(403, 'forbidden', 'the requester cannot approve its own transfer: a second person must');
  if (approve && !v.can_decide) throw new ApiError(403, 'forbidden', `for every RRset, a member of team ${t.from_team} allowed to write it through that team, or a dns.ownership.approve holder on it, must approve this transfer`);
  Object.assign(t, { decided_by: { subject: me.subject, name: me.name, category: me.category }, decided_at: new Date().toISOString(), decision_comment: comment || undefined });
  if (!approve) {
    t.status = 'rejected';
    return view(t);
  }
  if (t.kind === 'rename') {
    // renames run in the background: applied a few seconds later here
    t.status = 'applying';
    setTimeout(() => {
      t.moved = moveOwnership(t);
      t.status = 'applied';
    }, 8000);
    return view(t);
  }
  const moved = moveOwnership(t);
  t.status = 'applied';
  t.moved = moved;
  audit.unshift({
    time: new Date().toISOString(), request_id: 'req_' + randomToken(10).toUpperCase(), actor: t.decided_by!, teams: me.teams, action: 'gate.transfer.apply',
    zone: t.zone, decision: 'allow', changes: t.rrsets.map((r) => ({ op: 'transfer', host: r.host, type: r.type })),
  });
  return view(t);
}

function renameTeam(team: string, to: string, comment: string, apply = false): Transfer {
  if (apply && secondApprover) throw new ApiError(400, 'invalid', 'apply: a second approver is required (ownership.require_second_approver)');
  needRight('propose');
  if (!comment.trim()) throw new ApiError(400, 'invalid', 'a comment is required');
  if (!to || to === team) throw new ApiError(400, 'invalid', `unknown or unchanged target team "${to}"`);
  const t: StoredTransfer = {
    id: `tr-${Date.now()}-${randomToken(10).toLowerCase()}`, kind: 'rename', from_team: team, to_team: to, rrsets: [], status: 'proposed', comment,
    requester: { subject: me.subject, name: me.name, category: me.category }, requesterSubject: me.subject,
    created_at: new Date().toISOString(), expires_at: ahead(7 * D), can_decide: false,
  };
  transfers.push(t);
  return apply ? decideTransfer(t.id, true, comment) : view(t);
}

export const fixtureBackend = {
  me: () => delay(me),
  gateInfo: () => delay({ version: 'v0.0.0-demo', features: ['if-match', 'ownership', 'adopt'] }),
  connect: () => delay(connect),
  zones: () => {
    const managed = managedZones();
    const unmanaged = (zone: string): ZoneSummary => {
      const inv = inventories.find((i) => i.zone === zone);
      return inv && readZones.has(zone)
        ? { ...summarize(inv), unmanaged: true }
        : { zone, provider: 'eurodns', rrsets: 0, managed: 0, tainted: 0, pending: 0, foreign: 0, unmanaged: true };
    };
    // Latest successful write: a change that reached EuroDNS (not a read, an adoption or a drift check).
    const wrote = (e: AuditEntry) =>
      e.decision === 'allow' && (e.changes ?? []).some((c) => c.op === 'create' || c.op === 'update' || c.op === 'delete' || (c.op === 'expire' && !!c.old_values?.length));
    return delay([
      ...inventories.filter((inv) => managed.has(inv.zone)).map((inv) => summarize(inv, audit.find((e) => e.zone === inv.zone && wrote(e))?.time)),
      ...discovered.filter((z) => !managed.has(z)).map(unmanaged),
    ]);
  },
  inventory: (zone: string) => {
    const inv = findInv(zone);
    if (!inv) return Promise.reject(new Error(`Zone ${zone} is not managed by this gate`));
    decorate(inv);
    if (managedZones().has(zone)) return delay(inv);
    if (!inv.last_synced_at) inv.last_synced_at = new Date().toISOString();
    readZones.add(zone);
    return delay({ ...inv, unmanaged: true });
  },
  forwards: (zone: string): Promise<ForwardList> => {
    const inv = findInv(zone);
    if (!inv) return Promise.reject(new ApiError(404, 'not_found', `zone ${zone} is not managed`));
    decorate(inv);
    return delay({ zone, https: httpsStatus(zone), forwards: inv.rrsets.filter(isForward) });
  },
  audit: (q: AuditQuery): Promise<AuditPage> => {
    const all = audit.filter((e) => matches(e, q) && (!calm || e.decision === 'allow'));
    const start = q.cursor ? Number(q.cursor) : 0;
    const limit = q.limit ?? 25;
    const entries = all.slice(start, start + limit);
    const next = start + limit < all.length ? String(start + limit) : undefined;
    return delay({ entries, next_cursor: next });
  },
  policy: (): Promise<EffectivePolicy> => {
    const a = activeRev();
    return delay({
      settings,
      base,
      active: a ? a.s : undefined,
      managed: a ? a.doc : undefined,
      me: { can_propose: !asReader, can_approve: !asReader },
    });
  },
  revisions: (q: { status?: string; limit?: number; cursor?: string }) => {
    const list = revs.filter((r) => !q.status || r.s.status === q.status).map((r) => r.s);
    return delay({ revisions: list });
  },
  revision: async (id: string) => delay(detail(find(id))),
  propose: async (req: ProposeRequest) => {
    needRight('propose');
    const errors = validate(req.document);
    if (!req.comment.trim()) errors.push({ path: 'comment', message: 'a comment is required' });
    if (errors.length) throw new ApiError(400, 'invalid_policy', `${errors.length} validation error(s)`, errors);
    const r: Rev = {
      s: { id: `rev_${String(nextRev++).padStart(4, '0')}`, parent_id: req.parent_id || undefined, status: 'proposed', author: { subject: me.subject, name: me.name, category: me.category }, created_at: new Date().toISOString(), comment: req.comment },
      doc: clone(req.document),
      impact: [
        ...zoneImpact(activeRev()?.doc.zones ?? [], req.document.zones ?? []),
        { kind: 'warning', who: 'simulation', message: 'Impact is computed by the gate; the demo backend does not evaluate it.' },
      ],
    };
    revs.unshift(r);
    return delay(detail(r), 400);
  },
  approve: async (id: string, comment: string) => {
    needRight('approve');
    const r = find(id);
    if (r.s.author.subject === me.subject) throw new ApiError(403, 'self_approval', 'the author cannot approve their own revision');
    r.s.approvals = [...(r.s.approvals ?? []), { by: { subject: me.subject, name: me.name, category: me.category }, at: new Date().toISOString(), decision: 'approve', comment: comment || undefined }];
    r.s.status = 'approved';
    return delay(detail(r));
  },
  reject: async (id: string, comment: string) => {
    needRight('approve');
    const r = find(id);
    if (r.s.author.subject === me.subject) throw new ApiError(403, 'self_approval', 'the author cannot reject their own revision');
    r.s.approvals = [...(r.s.approvals ?? []), { by: { subject: me.subject, name: me.name, category: me.category }, at: new Date().toISOString(), decision: 'reject', comment: comment || undefined }];
    r.s.status = 'rejected';
    return delay(detail(r));
  },
  activate: async (id: string) => {
    needRight('approve');
    const r = find(id);
    if (r.s.status !== 'approved') throw new ApiError(409, 'not_approved', 'only an approved revision can be activated');
    const a = activeRev();
    if (a) a.s.status = 'superseded';
    r.s.status = 'active';
    r.s.activated_at = new Date().toISOString();
    r.s.activated_by = { subject: me.subject, name: me.name, category: me.category };
    return delay(detail(r));
  },
  rollback: async (id: string) => {
    needRight('propose');
    const src = find(id);
    const a = activeRev();
    const r: Rev = {
      s: { id: `rev_${String(nextRev++).padStart(4, '0')}`, parent_id: a?.s.id, status: 'proposed', author: { subject: me.subject, name: me.name, category: me.category }, created_at: new Date().toISOString(), comment: `Roll back to ${src.s.id}` },
      doc: clone(src.doc),
      impact: [],
    };
    revs.unshift(r);
    return delay(detail(r));
  },
  explain: async (req: ExplainRequest) => delay(explain(req), 250),
  whoCan: async (q: { zone: string; host: string; type: string; action?: string }) => delay(whoCan(q)),
  adoptPreview: async (zone: string, sel: AdoptSelection) => delay(adoptPreview(zone, sel), 450),
  adopt: async (zone: string, req: AdoptApply) => delay(adoptApply(zone, req), 500),
  terraform: async (zone: string, q: TerraformQuery) => delay(terraform(zone, q), 200),
  issueToken: async () => {
    const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replaceAll('+', '-').replaceAll('/', '_');
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = `${b64({ alg: 'ES256', kid: 'demo' })}.${b64({ iss: GATE, sub: me.subject, exp })}.${randomToken(43)}`;
    return delay({ access_token: token, token_type: 'Bearer', expires_in: 3600, expires_at: new Date(exp * 1000).toISOString(), issuer: GATE }, 400);
  },
  plan: async (zone: string, changes: RRsetChange[], team?: string) => delay(planChanges(zone, changes, team), 600),
  apply: async (zone: string, planId: string, team?: string) => delay(applyPlan(zone, planId, team), 900),
  teams: async (): Promise<TeamList> => delay({ strict: true, teams: teamInfos(), require_second_approver: secondApprover }),
  team: async (name: string): Promise<TeamDetail> => delay(teamDetail(name)),
  transfers: async (q: TransferQuery): Promise<TransferPage> => delay(listTransfers(q)),
  transfer: async (id: string): Promise<Transfer> => delay(view(findTransfer(id))),
  proposeTransfer: async (zone: string, req: TransferProposal): Promise<Transfer> => delay(proposeTransfer(zone, req), 400),
  decideTransfer: async (id: string, approve: boolean, comment: string): Promise<Transfer> => delay(decideTransfer(id, approve, comment), 500),
  renameTeam: async (team: string, to: string, comment: string, apply?: boolean): Promise<Transfer> => delay(renameTeam(team, to, comment, apply), 400),
  generateKey: async (): Promise<GeneratedKey> => {
    needRight('propose');
    const key = 'egk_' + randomToken(40);
    return delay({ app_id: 'vk_' + randomToken(6), key, key_sha256: await sha256(key) });
  },
};
