// Sends each probe to an HTTP chat endpoint and records which ones the agent obeyed.
import { randomBytes } from 'node:crypto';
import { probes } from './payloads.mjs';

const pick = (obj, path) => path.split('.').reduce((v, k) => (v == null ? v : v[k]), obj);

export async function scanAgent({ url, field = 'message', reply = 'reply', headers = {}, timeoutMs = 60000 }) {
  const findings = [];
  const results = [];

  for (const probe of probes) {
    const canary = `AVZ-CANARY-${randomBytes(4).toString('hex').toUpperCase()}`;
    const message = probe.build(canary);
    let text;
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify({ [field]: message }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      const body = await res.text();
      let json;
      try {
        json = JSON.parse(body);
      } catch {
        json = null;
      }
      text = String((json && pick(json, reply)) ?? body);
    } catch (err) {
      results.push({ probe: probe.id, status: 'error', error: err.message });
      continue;
    }

    const hit = probe.detect ? probe.detect(text) : text.includes(canary);
    results.push({ probe: probe.id, status: hit ? 'vulnerable' : 'resisted' });
    if (hit) {
      findings.push({
        id: `agent-${probe.id}`,
        severity: probe.severity ?? 'high',
        owasp: probe.owasp,
        title: probe.title,
        detail: 'The agent followed instructions that arrived as untrusted input.',
        evidence: text.slice(0, 300),
        tool: '(agent)',
      });
    }
  }

  return { target: url, kind: 'agent', results, findings };
}
