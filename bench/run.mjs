// Measures Probe's precision and recall on the labeled corpus in cases.mjs.
//   node bench/run.mjs            pattern rules only
//   node bench/run.mjs --llm      pattern rules + LLM judge (needs ANTHROPIC_API_KEY)
//   add --write to save bench/RESULTS.md
import { writeFileSync } from 'node:fs';
import { mcpCases, skillCases } from './cases.mjs';
import { checkTool } from '../src/rules.mjs';
import { checkFile } from '../src/skills-scan.mjs';
import { judgeItems, mergeVerdicts, llmFinding, DEFAULT_MODEL } from '../src/llm.mjs';
import { ORDER } from '../src/report.mjs';

const useLlm = process.argv.includes('--llm');
const model = process.env.PROBE_BENCH_MODEL ?? DEFAULT_MODEL;

// What counts as "Probe flagged this as an attack": injection-type rules at or
// above a severity. Capability warnings (e.g. "can send email") are design
// advice, not attack detection, so they are excluded.
const MCP_IDS = new Set(['tool-poisoning', 'invisible-characters', 'llm-tool-poisoning']);
const SKILL_IDS = new Set(['skill-hide-from-user', 'skill-exfiltration', 'invisible-characters', 'skill-pipe-to-shell', 'skill-sensitive-write', 'skill-encoded-blob', 'llm-skill-injection']);
const atLeast = (sev, min) => ORDER.indexOf(sev) <= ORDER.indexOf(min);

async function evaluate(cases, findingsOf, ids, minSeverity, itemOf, newId) {
  let byCase = Object.fromEntries(cases.map((c) => [c.id, findingsOf(c)]));
  if (useLlm) {
    const verdicts = await judgeItems(cases.map(itemOf), { model });
    for (const c of cases) {
      byCase[c.id] = mergeVerdicts(
        byCase[c.id].map((f) => ({ ...f, caseId: c.id })),
        new Map([...verdicts].filter(([k]) => k === c.id)),
        { keyOf: () => c.id, newFinding: (k, v) => llmFinding(newId, c.id, v) },
      );
    }
  }
  const rows = cases.map((c) => {
    const flagged = byCase[c.id].some((f) => ids.has(f.id) && atLeast(f.severity, minSeverity));
    const outcome = c.label === 'malicious' ? (flagged ? 'TP' : 'FN') : flagged ? 'FP' : 'TN';
    return { id: c.id, label: c.label, outcome };
  });
  return rows;
}

function metrics(rows) {
  const n = (o) => rows.filter((r) => r.outcome === o).length;
  const [tp, fp, fn, tn] = ['TP', 'FP', 'FN', 'TN'].map(n);
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall = tp + fn ? tp / (tp + fn) : 1;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { tp, fp, fn, tn, precision, recall, f1 };
}

const pct = (x) => `${Math.round(x * 100)}%`;

const mcpRows = await evaluate(
  mcpCases,
  (c) => checkTool(c.tool),
  MCP_IDS,
  'high',
  (c) => ({ key: c.id, kind: 'MCP tool description', text: `${c.tool.name}: ${c.tool.description}` }),
  'llm-tool-poisoning',
);
const skillRows = await evaluate(
  skillCases,
  (c) => checkFile(c.file, c.text),
  SKILL_IDS,
  'medium',
  (c) => ({ key: c.id, kind: `agent instruction file ${c.file}`, text: c.text }),
  'llm-skill-injection',
);

const mode = useLlm ? `patterns + LLM judge (${model})` : 'patterns only';
const lines = [`## ${mode}`, '', '| Corpus | Cases | TP | FP | FN | TN | Precision | Recall | F1 |', '|---|---|---|---|---|---|---|---|---|'];
for (const [name, rows] of [['MCP tool descriptions', mcpRows], ['Skills and scripts', skillRows], ['Total', [...mcpRows, ...skillRows]]]) {
  const m = metrics(rows);
  lines.push(`| ${name} | ${rows.length} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} |`);
}
const wrong = [...mcpRows, ...skillRows].filter((r) => r.outcome === 'FP' || r.outcome === 'FN');
lines.push('', `Misclassified: ${wrong.length ? wrong.map((r) => `\`${r.id}\` (${r.outcome})`).join(', ') : 'none'}`);
const table = lines.join('\n');
console.log(table);

if (process.argv.includes('--write')) {
  const header = `# Probe benchmark\n\nCorpus: \`bench/cases.mjs\` (${mcpCases.length} MCP tool descriptions, ${skillCases.length} skill and script files; malicious and tricky-benign cases, all fictional). Re-run with \`node bench/run.mjs [--llm]\`.\n\nTP = attack caught · FP = harmless case flagged · FN = attack missed · TN = harmless case passed. Capability warnings (e.g. "tool can send email") are not counted; only attack detection is.\n\n_Run on ${new Date().toISOString().slice(0, 10)}._\n\n`;
  writeFileSync(new URL('./RESULTS.md', import.meta.url), header + table + '\n');
}
