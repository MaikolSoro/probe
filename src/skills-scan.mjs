// Static scan of agent instruction files: Claude skills (SKILL.md), slash
// commands, CLAUDE.md / AGENTS.md, Cursor rules, hook configs and install
// scripts. These files are loaded straight into an agent's context or run on
// install, so they are a supply-chain entry point. Nothing is executed.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, basename, extname } from 'node:path';
import { OWASP } from './rules.mjs';

const TEXT_EXT = new Set(['.md', '.mdc', '.txt', '.json', '.yml', '.yaml', '.toml', '.sh', '.bash', '.zsh', '.ps1', '.py', '.js', '.mjs', '.ts']);
const NAMED = new Set(['CLAUDE.md', 'AGENTS.md', 'GEMINI.md', '.cursorrules', '.windsurfrules']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build']);
const MAX_BYTES = 1024 * 1024;

const isScript = (f) => ['.sh', '.bash', '.zsh', '.ps1', '.py', '.js', '.mjs', '.ts'].includes(extname(f));
const isConfig = (f) => ['.json', '.yml', '.yaml', '.toml'].includes(extname(f));
const isInstruction = (f) => !isScript(f) && !isConfig(f);

// Each rule says which kind of file it applies to. Offensive-security skill
// packs legitimately *describe* attacks, so instruction rules look for text
// aimed at the agent itself (hide from the user, send data somewhere), not for
// attack vocabulary.
const RULES = [
  {
    id: 'skill-hide-from-user',
    severity: 'critical',
    owasp: OWASP.LLM01,
    applies: isInstruction,
    pattern: /(do not|don't|never) (tell|mention|inform|reveal to|show|alert) (the )?user/i,
    title: 'Instruction file tells the agent to hide something from the user',
  },
  {
    id: 'skill-exfiltration',
    severity: 'critical',
    owasp: OWASP.LLM02,
    applies: isInstruction,
    // Local secrets of the person running the agent, not tokens of a target under test.
    pattern: /(send|post|upload|forward|exfiltrate|transmit|curl[^\n]{0,60}(-d|--data[a-z-]*|-F|-T|--upload-file))[^\n]{0,80}(@?(~|\$HOME|\/Users\/[^/\s]+|\/home\/[^/\s]+)\/\.(ssh|aws|env|config|netrc|npmrc|docker)|id_rsa|the user'?s (api )?(keys?|tokens?|credentials|passwords?|cookies))/i,
    title: 'Instruction file asks the agent to send secrets somewhere',
  },
  {
    id: 'invisible-characters',
    severity: 'high',
    owasp: OWASP.LLM01,
    applies: () => true,
    pattern: /[​-‏‪-‮⁠-⁤﻿]/,
    title: 'Invisible Unicode characters',
    evidence: () => '(hidden characters)',
  },
  {
    id: 'skill-sensitive-write',
    severity: 'high',
    owasp: OWASP.LLM06,
    applies: () => true,
    pattern: /(>>?|tee( -a)?|Add-Content|Set-Content|Out-File)\s+["']?(~|\$HOME|\$env:USERPROFILE)?\/?\.?(ssh\/authorized_keys|bashrc|zshrc|profile|bash_profile|aws\/credentials)/i,
    title: 'Writes to shell profiles, SSH keys or cloud credentials',
    // In docs or comments it is a suggestion for the reader, not something that runs.
    severityFor: (file, line) => (isScript(file) && !isComment(line) ? 'high' : 'low'),
  },
  {
    id: 'skill-pipe-to-shell',
    severity: 'medium',
    owasp: OWASP.LLM06,
    applies: () => true,
    pattern: /(curl|wget|iwr|Invoke-WebRequest)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|(iex|Invoke-Expression)\s*\(?\s*(iwr|irm|New-Object|Invoke-WebRequest|Invoke-RestMethod)/i,
    title: 'Downloads and runs a remote script (pipe to shell)',
    severityFor: (file, line) => (isScript(file) && !isComment(line) ? 'medium' : 'low'),
  },
  {
    id: 'skill-encoded-blob',
    severity: 'medium',
    owasp: OWASP.LLM01,
    applies: isInstruction,
    pattern: /[A-Za-z0-9+/]{160,}={0,2}/,
    title: 'Long encoded blob inside an instruction file',
    evidence: (m) => `${m.slice(0, 48)}… (${m.length} chars)`,
  },
  {
    id: 'skill-hook-command',
    severity: 'medium',
    owasp: OWASP.LLM06,
    applies: (f) => extname(f) === '.json',
    pattern: /"hooks"\s*:\s*\{[\s\S]{0,2000}?"command"\s*:\s*"([^"]{1,200})"/,
    title: 'Hook runs a command automatically on agent events',
    evidence: (m) => m.match(/"command"\s*:\s*"([^"]+)"/)?.[1] ?? m.slice(0, 80),
  },
  {
    id: 'skill-broad-tools',
    severity: 'low',
    owasp: OWASP.LLM06,
    applies: (f) => basename(f) === 'SKILL.md' || /commands\//.test(f),
    pattern: /^allowed-tools:.*\bBash\b(?!\()/m,
    title: 'Skill pre-approves unrestricted Bash',
  },
  {
    id: 'skill-mcp-install',
    severity: 'low',
    owasp: OWASP.LLM06,
    applies: () => true,
    pattern: /(claude mcp add|"mcpServers"\s*:)/,
    title: 'Adds or configures an MCP server',
  },
];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, out);
    else if ((TEXT_EXT.has(extname(name)) || NAMED.has(name)) && st.size <= MAX_BYTES) out.push(full);
  }
  return out;
}

const lineOf = (text, index) => text.slice(0, index).split('\n').length;
const lineText = (text, index) => text.slice(text.lastIndexOf('\n', index - 1) + 1, (text.indexOf('\n', index) + 1 || text.length + 1) - 1);
const isComment = (line) => /^\s*(#|\/\/|REM\b)/.test(line);

export function checkFile(file, text) {
  const findings = [];
  for (const rule of RULES) {
    if (!rule.applies(file)) continue;
    const m = rule.pattern.exec(text);
    if (!m) continue;
    const ev = rule.evidence ? rule.evidence(m[0]) : m[0].trim().slice(0, 160);
    findings.push({
      id: rule.id,
      severity: rule.severityFor ? rule.severityFor(file, lineText(text, m.index)) : rule.severity,
      owasp: rule.owasp,
      title: rule.title,
      detail: 'Review this file before installing it. Skills and instruction files are loaded into the agent with your permissions.',
      evidence: `line ${lineOf(text, m.index)}: ${ev}`,
      tool: file,
    });
  }
  return findings;
}

export function scanSkills(root) {
  const files = statSync(root).isDirectory() ? walk(root) : [root];
  const findings = [];
  const domains = new Set();
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(root, file) || basename(file);
    findings.push(...checkFile(rel, text));
    for (const [, host] of text.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi)) domains.add(host.toLowerCase());
  }
  return {
    target: root,
    kind: 'skills',
    files: files.length,
    skills: files.filter((f) => basename(f) === 'SKILL.md').length,
    domains: [...domains].sort(),
    findings,
  };
}
