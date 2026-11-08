// Compares two scan results (report.json files) so you can show a client the
// value of a fix: "before, 5 risks; after, 0". A finding is the same across two
// scans when its rule id and location match.
import { ORDER, counts } from './report.mjs';

const keyOf = (f) => `${f.id}|${f.tool}`;
const dedupe = (findings = []) => {
  const map = new Map();
  for (const f of findings) if (!map.has(keyOf(f))) map.set(keyOf(f), f);
  return map;
};

export function diffScans(before, after) {
  const b = dedupe(before.findings);
  const a = dedupe(after.findings);
  const resolved = [...b.values()].filter((f) => !a.has(keyOf(f)));
  const added = [...a.values()].filter((f) => !b.has(keyOf(f)));
  const unchanged = [...a.values()].filter((f) => b.has(keyOf(f)));
  return { resolved, added, unchanged, before: [...b.values()], after: [...a.values()] };
}

const COLOR = { resolved: '\x1b[32m', added: '\x1b[31m', unchanged: '\x1b[33m', reset: '\x1b[0m' };
const line = (f) => `${f.severity.toUpperCase().padEnd(8)} ${String(f.tool).padEnd(22)} ${f.title}`;

export function printDiff(d, { color = process.stdout.isTTY } = {}) {
  const paint = (k, text) => (color ? `${COLOR[k]}${text}${COLOR.reset}` : text);
  const b = counts(d.before);
  const a = counts(d.after);
  const net = d.before.length - d.after.length;
  const verdict = net > 0 ? `${net} fewer finding${net === 1 ? '' : 's'}` : net < 0 ? `${-net} more finding${net === -1 ? '' : 's'}` : 'no net change';

  const out = ['\nAVENZOQ Probe · BEFORE/AFTER'];
  out.push(`Before: ${d.before.length} findings (${ORDER.map((s) => `${s} ${b[s]}`).join(' · ')})`);
  out.push(`After:  ${d.after.length} findings (${ORDER.map((s) => `${s} ${a[s]}`).join(' · ')})`);
  out.push(`Net:    ${verdict}`, '');

  out.push(paint('resolved', `✔ Resolved (${d.resolved.length})`));
  for (const f of d.resolved) out.push(`  ${paint('resolved', line(f))}`);
  out.push('', paint('added', `✘ New (${d.added.length})`));
  for (const f of d.added) out.push(`  ${paint('added', line(f))}`);
  out.push('', paint('unchanged', `● Still present (${d.unchanged.length})`));
  for (const f of d.unchanged) out.push(`  ${paint('unchanged', line(f))}`);
  return out.join('\n');
}

export function diffToMarkdown(d, date = new Date()) {
  const b = counts(d.before);
  const a = counts(d.after);
  const row = (title, list) => [`### ${title} (${list.length})`, '', list.length ? '' : '_None._', ...list.map((f) => `- **[${f.severity.toUpperCase()}]** \`${f.tool}\` — ${f.title}`), ''];
  return [
    '# AVENZOQ Probe — before/after',
    '',
    `- **Date:** ${date.toISOString().slice(0, 10)}`,
    `- **Before:** ${d.before.length} findings (${ORDER.map((s) => `${s}: ${b[s]}`).join(', ')})`,
    `- **After:** ${d.after.length} findings (${ORDER.map((s) => `${s}: ${a[s]}`).join(', ')})`,
    '',
    '| | Critical | High | Medium | Low | Total |',
    '|---|---|---|---|---|---|',
    `| Before | ${b.critical} | ${b.high} | ${b.medium} | ${b.low} | ${d.before.length} |`,
    `| After | ${a.critical} | ${a.high} | ${a.medium} | ${a.low} | ${d.after.length} |`,
    '',
    ...row('Resolved', d.resolved),
    ...row('New', d.added),
    ...row('Still present', d.unchanged),
  ].join('\n');
}
