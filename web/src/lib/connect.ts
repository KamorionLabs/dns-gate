// Snippets of the Connect page, built from GET /api/v1/connect.
import type { Connect } from './types';

/** Same-origin path of the Claude Desktop extension download (session cookie). */
export const CLAUDE_DESKTOP_EXTENSION_PATH = '/api/v1/connect/claude-desktop.mcpb';

export const TOKEN_COMMAND_PLACEHOLDER = '<command printing an access token>';

const entra = (c: Connect) => c.issuer?.kind === 'entra';
const scope = (c: Connect) => c.cli_scope || '<scope of the gate application>';
const tenant = (c: Connect) => c.issuer?.tenant_id || '<tenant-id>';

/** Shell command printing an access token for the gate on stdout. */
export function tokenCommand(c: Connect): string {
  return entra(c) ? `az account get-access-token --scope ${scope(c)} --query accessToken -o tsv` : TOKEN_COMMAND_PLACEHOLDER;
}

export function loginCommand(c: Connect): string {
  return `az login --tenant ${tenant(c)}`;
}

/** Prints {"Authorization":"Bearer <token>"}. Double quotes only: it travels
 *  inside the single-quoted JSON argument of `claude mcp add-json`. */
export function headersHelper(c: Connect): string {
  return `${tokenCommand(c)} | jq -Rc "{Authorization: (\\"Bearer \\" + .)}"`;
}

// POSIX single quoting.
const shq = (s: string) => `'${s.replaceAll("'", `'\\''`)}'`;

export function claudeCodeCommand(c: Connect): string {
  const server = JSON.stringify({ type: 'http', url: c.mcp.url, headersHelper: headersHelper(c) });
  return `claude mcp add-json dns-gate ${shq(server)} --scope user`;
}

export function desktopConfig(c: Connect): string {
  const server = {
    command: 'npx',
    args: ['-y', 'mcp-remote', c.mcp.url, '--header', 'Authorization:${AUTH_HEADER}'],
    env: { AUTH_HEADER: 'Bearer <paste the access token here>' },
  };
  return JSON.stringify({ mcpServers: { 'dns-gate': server } }, null, 2) + '\n';
}

/** Provider block and one record set of the dnsgate Terraform provider. */
export function terraformProvider(c: Connect, zone = 'example.com'): string {
  return [
    'terraform {',
    '  required_providers {',
    '    dnsgate = {',
    '      source = "KamorionLabs/dnsgate"',
    '    }',
    '  }',
    '}',
    '',
    'provider "dnsgate" {',
    `  endpoint = "${c.base_url}"`,
    '}',
    '',
    'resource "dnsgate_record_set" "www" {',
    `  zone   = "${zone}"`,
    '  name   = "www"',
    '  type   = "CNAME"',
    '  ttl    = 300',
    '  values = ["app.example.net."]',
    '}',
    '',
  ].join('\n');
}

/** curl examples of the REST API: who am I, the record sets of a zone, a plan then its apply. */
export function curlCommand(c: Connect, zone = 'example.com'): string {
  const z = `$GATE/api/v1/zones/${zone}`;
  const auth = '-H "Authorization: Bearer $TOKEN"';
  const json = '-H "Content-Type: application/json"';
  const change = JSON.stringify({ changes: [{ host: 'www', type: 'CNAME', ttl: 300, values: ['app.example.net.'] }] });
  return [
    tokenLine(c),
    `GATE=${c.base_url}`,
    '',
    '# Who am I: roles, teams and permissions',
    `curl ${auth} $GATE/api/v1/me`,
    '',
    '# Zones, then the record sets of one zone (with their owner and hash)',
    `curl ${auth} $GATE/api/v1/zones`,
    `curl ${auth} ${z}/rrsets`,
    '',
    '# Plan a change: the gate answers with the diff, its decision and a plan_id',
    `curl -X POST ${auth} ${json} \\`,
    `  -d '${change}' \\`,
    `  ${z}/plan`,
    '',
    '# Apply exactly that plan',
    `curl -X POST ${auth} ${json} -d '{"plan_id":"<plan_id>"}' ${z}/apply`,
    '',
  ].join('\n');
}

/** Environment variable the dnsgate Terraform provider reads its token from. */
export const TOKEN_ENV = 'DNSGATE_TOKEN';

/** Where a script gets its token: the Azure CLI with Entra, the console's "Get an API token" otherwise. */
export function tokenLine(c: Connect): string {
  if (!entra(c) && c.tokens_url) return `TOKEN='<paste the token from "Get an API token">'`;
  return `TOKEN=$(${tokenCommand(c)})`;
}

/** Ready-to-paste uses of a token the console just issued. */
export function tokenSnippets(c: Connect, token: string, zone = 'example.com'): { terraform: string; curl: string } {
  return {
    terraform: [`export ${TOKEN_ENV}=${shq(token)}`, 'terraform plan', ''].join('\n'),
    curl: [`curl -H "Authorization: Bearer ${token}" \\`, `  ${c.base_url}/api/v1/zones/${zone}/rrsets`, ''].join('\n'),
  };
}
