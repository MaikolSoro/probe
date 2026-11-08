// SARIF 2.1.0 output so findings show up in GitHub code scanning (Security tab).
import { existsSync } from 'node:fs';
import { guidance } from './guidance.mjs';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
// GitHub ranks alerts by this numeric score (critical >= 9.0, high >= 7.0, medium >= 4.0).
const SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

// Code scanning needs a file to attach each result to. Skill findings already
// point at a file and line; for the other modes use the scanned file when the
// target names one, otherwise the given anchor.
function locationOf(finding, scan, anchor) {
  const line = Number(/^line (\d+):/.exec(finding.evidence ?? '')?.[1] ?? 1);
  if (scan.kind === 'skills' && finding.tool && !finding.tool.startsWith('(')) return { uri: finding.tool, line };
  const fromTarget = String(scan.target).split(/[\s,]+/).find((part) => /\.(m?js|ts|py|json)$/.test(part) && existsSync(part));
  return { uri: anchor ?? fromTarget ?? 'package.json', line: 1 };
}

export function toSarif(scan, { version, anchor } = {}) {
  const rules = new Map();
  const results = scan.findings.map((f) => {
    const g = guidance(f.id, 'en');
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        name: f.id.replace(/(^|-)(\w)/g, (_, __, c) => c.toUpperCase()),
        shortDescription: { text: g?.title ?? f.title },
        fullDescription: { text: g?.explain ?? f.detail },
        help: { text: g?.fix ?? f.detail },
        properties: { tags: ['security', f.owasp], 'security-severity': SCORE[f.severity] },
      });
    }
    const loc = locationOf(f, scan, anchor);
    return {
      ruleId: f.id,
      level: LEVEL[f.severity],
      message: { text: `${f.title} (${f.tool})${f.evidence ? ` — ${f.evidence}` : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: loc.uri }, region: { startLine: loc.line } } }],
      partialFingerprints: { probe: `${f.id}|${f.tool}|${f.evidence ?? ''}` },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AVENZOQ Probe',
            version,
            informationUri: 'https://github.com/MaikolSoro/probe',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
