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
  return `claude mcp add-json eurodns-gate ${shq(server)} --scope user`;
}

export function desktopConfig(c: Connect): string {
  const server = {
    command: 'npx',
    args: ['-y', 'mcp-remote', c.mcp.url, '--header', 'Authorization:${AUTH_HEADER}'],
    env: { AUTH_HEADER: 'Bearer <paste the access token here>' },
  };
  return JSON.stringify({ mcpServers: { 'eurodns-gate': server } }, null, 2) + '\n';
}

export function terraformProvider(c: Connect): string {
  const auth = entra(c)
    ? [
        '    auth {',
        '      # Workstation and Azure-hosted runners: Azure CLI login, managed or workload identity.',
        '      azure_identity {',
        `        scope     = "${scope(c)}"`,
        `        tenant_id = "${tenant(c)}"`,
        '      }',
        '',
        '      # In an Azure DevOps pipeline, the OIDC token of a service connection takes',
        '      # precedence inside the job; azure_identity still applies locally.',
        '      # azure_devops { service_connection_id = "00000000-0000-0000-0000-000000000000" }',
        '    }',
      ]
    : ['    auth {', `      token_command = ["sh", "-c", "${TOKEN_COMMAND_PLACEHOLDER}"]`, '    }'];
  return [
    'terraform {',
    '  required_providers {',
    '    eurodns = {',
    '      source = "kamorionlabs/eurodns"',
    '    }',
    '  }',
    '}',
    '',
    'provider "eurodns" {',
    '  gate {',
    `    url = "${c.base_url}"`,
    '',
    ...auth,
    '  }',
    '}',
    '',
  ].join('\n');
}

export function curlCommand(c: Connect): string {
  return [`TOKEN=$(${tokenCommand(c)})`, `curl -H "Authorization: Bearer $TOKEN" ${c.base_url}/api/v1/me`, ''].join('\n');
}
