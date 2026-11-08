// Rug-pull detection: remember a fingerprint of every tool the first time a
// server is scanned (trust on first use) and report tools that later change,
// appear or disappear. A server that turns malicious after you approved it
// usually does so by editing a tool description.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';

// Sorted keys so the same definition always hashes the same.
const stable = (v) =>
  Array.isArray(v)
    ? v.map(stable)
    : v && typeof v === 'object'
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable(v[k])]))
      : v;

export function fingerprint(tool) {
  const { name, description = '', inputSchema = {}, annotations = {} } = tool;
  return createHash('sha256').update(JSON.stringify(stable({ name, description, inputSchema, annotations }))).digest('hex').slice(0, 16);
}

export function readPins(file) {
  if (!existsSync(file)) return { version: 1, servers: {} };
  return JSON.parse(readFileSync(file, 'utf8'));
}

export function writePins(file, pins) {
  writeFileSync(file, `${JSON.stringify(pins, null, 2)}\n`);
}

const SUPPLY_CHAIN = 'LLM03:2025 Supply Chain';

// Returns findings for one server and mutates `pins` when the server is new or update is set.
export function comparePins(pins, serverKey, tools, { update = false } = {}) {
  const current = Object.fromEntries(tools.map((t) => [t.name, fingerprint(t)]));
  const known = pins.servers[serverKey];
  if (!known || update) {
    pins.servers[serverKey] = current;
    return { findings: [], status: known ? 'pins updated' : `pinned ${tools.length} tools` };
  }

  const findings = [];
  for (const [name, hash] of Object.entries(current)) {
    if (!(name in known)) {
      findings.push({
        id: 'tool-added',
        severity: 'medium',
        owasp: SUPPLY_CHAIN,
        title: 'New tool since the pinned scan',
        detail: 'The server now exposes a tool that was not there when it was approved. Review it, then accept with --update-pins.',
        tool: name,
      });
    } else if (known[name] !== hash) {
      findings.push({
        id: 'tool-definition-changed',
        severity: 'high',
        owasp: SUPPLY_CHAIN,
        title: 'Tool definition changed since the pinned scan',
        detail: 'The description, parameters or annotations changed after the server was approved. This is how a "rug pull" attack ships new instructions. Review the change, then accept with --update-pins.',
        evidence: `${known[name]} → ${hash}`,
        tool: name,
      });
    }
  }
  for (const name of Object.keys(known)) {
    if (!(name in current)) {
      findings.push({
        id: 'tool-removed',
        severity: 'low',
        owasp: SUPPLY_CHAIN,
        title: 'Tool removed since the pinned scan',
        detail: 'A tool disappeared. Usually harmless, but confirm the server is the one you expect.',
        tool: name,
      });
    }
  }
  return { findings, status: findings.length ? `${findings.length} change(s) since pinned` : 'matches pins' };
}
