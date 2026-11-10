// Maps each finding to the OWASP Top 10 for Agentic Applications (2026) and to
// MITRE ATLAS techniques, so a report can serve as evidence in an AI-security or
// compliance review. The mapping is indicative: check it against the current
// version of each framework before relying on it in an audit.

const ASI = {
  ASI01: 'ASI01:2026 Agent Goal Hijack',
  ASI02: 'ASI02:2026 Tool Misuse and Exploitation',
  ASI03: 'ASI03:2026 Identity and Privilege Abuse',
  ASI04: 'ASI04:2026 Agentic Supply Chain Vulnerabilities',
  ASI05: 'ASI05:2026 Unexpected Code Execution',
  ASI06: 'ASI06:2026 Memory and Context Poisoning',
};

const ATLAS = {
  inject: 'AML.T0051 (LLM prompt injection)',
  indirect: 'AML.T0051.001 (indirect prompt injection)',
  jailbreak: 'AML.T0054 (LLM jailbreak)',
  sysprompt: 'AML.T0056 (system prompt extraction)',
  leak: 'AML.T0057 (LLM data leakage)',
  tool: 'AML.T0053 (AI agent tool invocation)',
  exfil: 'AML.T0086 (exfiltration via AI agent tool invocation)',
  supply: 'AML.T0010 (AI supply chain compromise)',
};

const MAP = {
  'tool-poisoning': [['ASI01', 'ASI04'], ['indirect']],
  'llm-tool-poisoning': [['ASI01', 'ASI04'], ['indirect']],
  'invisible-characters': [['ASI01', 'ASI04'], ['indirect']],
  'long-description': [['ASI04'], ['indirect']],
  'tool-steering': [['ASI01'], ['indirect']],
  'tool-output-injection': [['ASI01', 'ASI06'], ['indirect']],
  'llm-output-injection': [['ASI01', 'ASI06'], ['indirect']],
  'capability-exec': [['ASI02', 'ASI05'], ['tool']],
  'capability-destructive': [['ASI02'], ['tool']],
  'capability-financial': [['ASI02'], ['tool']],
  'capability-outbound': [['ASI02'], ['tool']],
  'capability-write': [['ASI02'], ['tool']],
  'annotation-mismatch': [['ASI02'], ['tool']],
  'missing-annotations': [['ASI02'], ['tool']],
  'unconstrained-input': [['ASI02'], ['tool']],
  'exfiltration-path': [['ASI01', 'ASI02'], ['exfil', 'leak']],
  'cross-server-flow': [['ASI01', 'ASI02'], ['exfil', 'leak']],
  'config-plaintext-secret': [['ASI03'], []],
  'config-unpinned-package': [['ASI04'], ['supply']],
  'tool-definition-changed': [['ASI04'], ['supply']],
  'tool-added': [['ASI04'], ['supply']],
  'tool-removed': [['ASI04'], ['supply']],
  'skill-hide-from-user': [['ASI01', 'ASI04'], ['indirect']],
  'skill-exfiltration': [['ASI01', 'ASI04'], ['indirect', 'exfil']],
  'skill-encoded-blob': [['ASI04'], ['indirect']],
  'llm-skill-injection': [['ASI01', 'ASI04'], ['indirect']],
  'skill-sensitive-write': [['ASI04', 'ASI05'], ['supply']],
  'skill-pipe-to-shell': [['ASI04', 'ASI05'], ['supply']],
  'skill-hook-command': [['ASI04', 'ASI05'], ['supply']],
  'skill-broad-tools': [['ASI02', 'ASI04'], []],
  'skill-mcp-install': [['ASI04'], ['supply']],
  'doc-hidden-instructions': [['ASI01', 'ASI06'], ['indirect']],
  'doc-injection': [['ASI01', 'ASI06'], ['indirect']],
  'doc-hidden-text': [['ASI06'], ['indirect']],
  'doc-invisible-characters': [['ASI06'], ['indirect']],
};

// Agent probe ids are `agent-<probe>`; map them by what the probe does.
function agentMapping(id) {
  if (/^agent-tool-/.test(id)) return [['ASI01', 'ASI02'], ['inject', 'tool']];
  if (/exfiltration/.test(id)) return [['ASI01'], ['inject', 'leak']];
  if (/system-prompt/.test(id)) return [[], ['sysprompt']];
  if (/^agent-(indirect|delimiter|fake-transcript)/.test(id)) return [['ASI01'], ['indirect']];
  if (/^agent-(role-play|developer-mode|refusal-suppression)/.test(id)) return [['ASI01'], ['inject', 'jailbreak']];
  return [['ASI01'], ['inject']];
}

export function frameworksOf(id = '') {
  const [asi, atlas] = MAP[id] ?? (id.startsWith('agent-') ? agentMapping(id) : [[], []]);
  return { agentic: asi.map((k) => ASI[k]), atlas: atlas.map((k) => ATLAS[k]) };
}

// One line for reports, e.g. "OWASP Agentic: ASI01:2026 Agent Goal Hijack · MITRE ATLAS: AML.T0051.001 (…)".
export function frameworkLine(id) {
  const { agentic, atlas } = frameworksOf(id);
  const parts = [];
  if (agentic.length) parts.push(`OWASP Agentic: ${agentic.join(', ')}`);
  if (atlas.length) parts.push(`MITRE ATLAS: ${atlas.join(', ')}`);
  return parts.join(' · ');
}

// Short ids for SARIF tags, e.g. ["ASI01", "AML.T0051.001"].
export function frameworkTags(id) {
  const { agentic, atlas } = frameworksOf(id);
  return [...agentic.map((a) => a.split(':')[0]), ...atlas.map((a) => a.split(' ')[0])];
}

export const FRAMEWORK_NOTE =
  'Framework mapping (OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS) is indicative; check it against the current version of each framework before using it as audit evidence.';
