// Turns a scan result into a terminal summary and a Markdown report.
export const ORDER = ['critical', 'high', 'medium', 'low'];

const KIND = {
  mcp: 'MCP server (static analysis of tool definitions)',
  agent: 'Chat agent (prompt-injection probes)',
  skills: 'Agent skills and instruction files (static analysis)',
  config: 'MCP client configuration and configured servers',
};

const COLOR = { critical: '\x1b[35m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m' };
const RESET = '\x1b[0m';

export function sortFindings(findings) {
  return [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
}

export function counts(findings) {
  return Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]));
}

export function printSummary(scan, { color = process.stdout.isTTY } = {}) {
  const paint = (sev, text) => (color ? `${COLOR[sev]}${text}${RESET}` : text);
  const lines = [`\nAVENZOQ Probe · ${scan.kind.toUpperCase()} · ${scan.target}`];
  if (scan.server) lines.push(`Server: ${scan.server} · ${scan.tools.length} tools`);
  if (scan.called) lines.push(`Read-only tools called: ${scan.called.length ? scan.called.map((c) => c.tool).join(', ') : 'none'}`);
  if (scan.kind === 'skills') lines.push(`Files: ${scan.files} · skills: ${scan.skills} · external domains: ${scan.domains.length}`);
  if (scan.kind === 'config') {
    for (const src of scan.sources) lines.push(`Config: ${src.client} · ${src.file} · ${src.servers} servers`);
    for (const srv of scan.servers) lines.push(`  ${srv.name}: ${srv.status}`);
  }
  if (scan.pins) lines.push(`Pins: ${scan.pins}`);
  if (scan.llm) lines.push(`LLM judge: ${scan.llm}`);
  if (scan.results) {
    const count = (s) => scan.results.filter((r) => r.status === s).length;
    const skipped = count('skipped');
    lines.push(`Target: ${scan.agent}`);
    lines.push(`Probes: ${scan.results.length - skipped} sent · ${count('vulnerable')} succeeded · ${count('resisted')} resisted${skipped ? ` · ${skipped} skipped` : ''}${count('error') ? ` · ${count('error')} errors` : ''}`);
  }
  lines.push('');
  for (const f of sortFindings(scan.findings)) {
    const judged = f.llm ? ` [llm ${f.llm.split(':')[0]}]` : '';
    lines.push(`${paint(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.tool.padEnd(22)} ${f.title}${judged}`);
  }
  // An inconclusive scan never ran, so "No findings" would be misleading.
  if (scan.inconclusive) {
    const warn = color ? `\x1b[33m${scan.inconclusive}${RESET}` : scan.inconclusive;
    lines.push(`⚠ INCONCLUSIVE — ${warn}`);
    return lines.join('\n');
  }
  if (!scan.findings.length) lines.push('No findings.');
  if (scan.suppressed) lines.push(`(${scan.suppressed} suppressed by .probeignore)`);
  const c = counts(scan.findings);
  lines.push('', ORDER.map((s) => `${s}: ${c[s]}`).join(' · '));
  return lines.join('\n');
}

export function toMarkdown(scan, date = new Date()) {
  const c = counts(scan.findings);
  const out = [
    `# AVENZOQ Probe report`,
    '',
    `- **Target:** \`${scan.target}\``,
    `- **Type:** ${KIND[scan.kind]}`,
    `- **Date:** ${date.toISOString().slice(0, 10)}`,
  ];
  if (scan.server) out.push(`- **Server:** ${scan.server} · tools: ${scan.tools.map((t) => `\`${t}\``).join(', ')}`);
  if (scan.called) out.push(`- **Read-only tools called:** ${scan.called.length ? scan.called.map((c) => `\`${c.tool}\` (${c.status})`).join(', ') : 'none'}`);
  if (scan.inconclusive) out.push('', `> ⚠️ **Inconclusive scan.** ${scan.inconclusive} These results do not mean the target is secure.`, '');
  out.push('', '## Summary', '', '| Critical | High | Medium | Low |', '|---|---|---|---|', `| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} |`, '');

  if (scan.kind === 'skills') out.push(`Files scanned: ${scan.files} (${scan.skills} skills). External domains referenced: ${scan.domains.join(', ') || 'none'}.`, '');
  if (scan.kind === 'config') {
    out.push('## Servers', '', '| Server | Status |', '|---|---|');
    for (const srv of scan.servers) out.push(`| ${srv.name} | ${srv.status} |`);
    out.push('');
  }
  if (scan.results) {
    out.push('## Probes', '', '| Probe | Result |', '|---|---|');
    for (const r of scan.results) out.push(`| ${r.probe} | ${r.status}${r.error ? ` (${r.error})` : ''} |`);
    out.push('');
  }

  out.push('## Findings', '');
  if (!scan.findings.length) out.push('No findings.');
  for (const f of sortFindings(scan.findings)) {
    out.push(`### [${f.severity.toUpperCase()}] ${f.title}`, '', `- **Where:** \`${f.tool}\``, `- **OWASP:** ${f.owasp}`);
    if (f.llm) out.push(`- **LLM judge:** ${f.llm}`);
    out.push('', f.detail);
    if (f.evidence) out.push('', '```', f.evidence, '```');
    out.push('');
  }
  out.push('---', '', 'A clean report does not prove a system is secure; it means these checks found nothing. Only scan systems you own or are authorized to test.');
  return out.join('\n');
}
