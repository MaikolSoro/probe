// Turns a scan result into a terminal summary and a Markdown report.
export const ORDER = ['critical', 'high', 'medium', 'low'];

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
  if (scan.results) {
    const vuln = scan.results.filter((r) => r.status === 'vulnerable').length;
    lines.push(`Probes: ${scan.results.length} sent · ${vuln} succeeded`);
  }
  lines.push('');
  for (const f of sortFindings(scan.findings)) {
    lines.push(`${paint(f.severity, f.severity.toUpperCase().padEnd(8))} ${f.tool.padEnd(22)} ${f.title}`);
  }
  if (!scan.findings.length) lines.push('No findings.');
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
    `- **Type:** ${scan.kind === 'mcp' ? 'MCP server (static analysis of tool definitions)' : 'Chat agent (prompt-injection probes)'}`,
    `- **Date:** ${date.toISOString().slice(0, 10)}`,
  ];
  if (scan.server) out.push(`- **Server:** ${scan.server} · tools: ${scan.tools.map((t) => `\`${t}\``).join(', ')}`);
  if (scan.called) out.push(`- **Read-only tools called:** ${scan.called.length ? scan.called.map((c) => `\`${c.tool}\` (${c.status})`).join(', ') : 'none'}`);
  out.push('', '## Summary', '', '| Critical | High | Medium | Low |', '|---|---|---|---|', `| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} |`, '');

  if (scan.results) {
    out.push('## Probes', '', '| Probe | Result |', '|---|---|');
    for (const r of scan.results) out.push(`| ${r.probe} | ${r.status}${r.error ? ` (${r.error})` : ''} |`);
    out.push('');
  }

  out.push('## Findings', '');
  if (!scan.findings.length) out.push('No findings.');
  for (const f of sortFindings(scan.findings)) {
    out.push(`### [${f.severity.toUpperCase()}] ${f.title}`, '', `- **Where:** \`${f.tool}\``, `- **OWASP:** ${f.owasp}`, '', f.detail);
    if (f.evidence) out.push('', '```', f.evidence, '```');
    out.push('');
  }
  out.push('---', '', 'A clean report does not prove a system is secure; it means these checks found nothing. Only scan systems you own or are authorized to test.');
  return out.join('\n');
}
