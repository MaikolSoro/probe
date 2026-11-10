// Audits the MCP servers configured in local AI clients (Claude Desktop,
// Claude Code, Cursor, VS Code, Windsurf): checks the config itself, then
// connects to each server and runs the static tool rules.
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { scanMcp } from './mcp-scan.mjs';
import { OWASP } from './rules.mjs';
import { checkFlows } from './flows.mjs';

const home = homedir();

export const KNOWN_CONFIGS = [
  ['Claude Desktop', join(home, 'Library/Application Support/Claude/claude_desktop_config.json')],
  ['Claude Desktop', join(process.env.APPDATA ?? join(home, 'AppData/Roaming'), 'Claude/claude_desktop_config.json')],
  ['Claude Desktop', join(home, '.config/Claude/claude_desktop_config.json')],
  ['Claude Code', join(home, '.claude.json')],
  ['Claude Code (project)', join(process.cwd(), '.mcp.json')],
  ['Cursor', join(home, '.cursor/mcp.json')],
  ['Cursor (project)', join(process.cwd(), '.cursor/mcp.json')],
  ['VS Code (project)', join(process.cwd(), '.vscode/mcp.json')],
  ['Windsurf', join(home, '.codeium/windsurf/mcp_config.json')],
];

const SECRET = /(sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})/;
const SECRET_NAME = /(key|token|secret|password|passwd|auth)/i;

// Claude Code keeps servers both at the top level and per project.
function serversIn(json) {
  const found = [];
  const add = (obj, scope) => {
    for (const [name, cfg] of Object.entries(obj ?? {})) found.push({ name: scope ? `${scope}:${name}` : name, cfg });
  };
  add(json.mcpServers);
  add(json.servers); // VS Code
  for (const [path, project] of Object.entries(json.projects ?? {})) add(project.mcpServers, path.split('/').pop());
  return found;
}

export function checkServerConfig(name, cfg) {
  const findings = [];
  const where = { tool: name };
  const args = cfg.args ?? [];

  for (const [k, v] of Object.entries(cfg.env ?? {})) {
    if (typeof v === 'string' && v && !v.startsWith('${') && (SECRET.test(v) || (SECRET_NAME.test(k) && v.length >= 12))) {
      findings.push({
        id: 'config-plaintext-secret',
        severity: 'medium',
        owasp: OWASP.LLM02,
        title: `Secret stored in plain text in the config (${k})`,
        detail: 'Any process or tool that can read this file gets the credential. Load it from the system keychain or an environment variable instead.',
        evidence: `${k}=${v.slice(0, 4)}…`,
        ...where,
      });
    }
  }
  const joined = [cfg.command, ...args].join(' ');
  if (SECRET.test(joined) || (cfg.url && SECRET.test(cfg.url))) {
    findings.push({
      id: 'config-plaintext-secret',
      severity: 'medium',
      owasp: OWASP.LLM02,
      title: 'Secret passed in plain text in the command line or URL',
      detail: 'Command lines and URLs end up in process lists and logs.',
      ...where,
    });
  }

  // npx/uvx without a pinned version runs whatever the registry serves next time.
  if (/^(npx|uvx|bunx|pnpm)$/.test(cfg.command ?? '')) {
    const pkg = args.find((a) => !a.startsWith('-') && a !== 'dlx');
    if (pkg && !/@\d|==\d/.test(pkg.replace(/^@/, ''))) {
      findings.push({
        id: 'config-unpinned-package',
        severity: 'low',
        owasp: 'LLM03:2025 Supply Chain',
        title: `Package runs without a pinned version (${pkg})`,
        detail: 'A new release, or a hijacked one, is picked up automatically. Pin an exact version and re-scan after updating.',
        ...where,
      });
    }
  }

  if (cfg.url && /^http:\/\//.test(cfg.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(cfg.url)) {
    findings.push({
      id: 'config-insecure-transport',
      severity: 'medium',
      owasp: OWASP.LLM02,
      title: 'Remote MCP server over plain HTTP',
      detail: 'Traffic, including tool results and tokens, can be read or altered in transit. Use HTTPS.',
      ...where,
    });
  }
  return findings;
}

export async function scanConfigs({ paths, connect = true, timeoutMs = 20000, pins, llm } = {}) {
  timeoutMs ??= 20000;
  const configs = paths ? paths.map((p) => ['Custom', p]) : KNOWN_CONFIGS;
  const sources = [];
  const findings = [];
  const servers = [];
  const connected = [];

  for (const [client, file] of configs) {
    if (!existsSync(file)) continue;
    let json;
    try {
      json = JSON.parse(readFileSync(file, 'utf8'));
    } catch {
      continue;
    }
    const list = serversIn(json);
    sources.push({ client, file, servers: list.length });
    for (const { name, cfg } of list) {
      const label = `${client} › ${name}`;
      findings.push(...checkServerConfig(label, cfg));
      const entry = { name: label, status: 'not scanned' };
      servers.push(entry);
      if (!connect || cfg.disabled) continue;
      try {
        const scan = await scanMcp(
          {
            ...(cfg.url ? { url: cfg.url } : { command: cfg.command, args: cfg.args ?? [], env: cfg.env }),
            timeoutMs,
            llm,
            pins: pins && { ...pins, key: label },
          },
        );
        entry.status = `ok · ${scan.tools.length} tools${scan.pins ? ` · ${scan.pins}` : ''}`;
        connected.push({ name: label, definitions: scan.definitions });
        findings.push(...scan.findings.map((f) => ({ ...f, tool: `${label} › ${f.tool}` })));
      } catch (err) {
        entry.status = `error: ${err.message}`;
      }
    }
  }

  findings.push(...checkFlows(connected));

  return { target: sources.map((s) => s.file).join(', ') || '(no MCP config found)', kind: 'config', sources, servers, findings };
}
