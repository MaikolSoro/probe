// Static checks for MCP tool definitions. Each rule looks only at what the
// server advertises (name, description, input schema, annotations); no tool is
// ever called, so scanning has no side effects on the target.

export const OWASP = {
  LLM01: 'LLM01:2025 Prompt Injection',
  LLM02: 'LLM02:2025 Sensitive Information Disclosure',
  LLM06: 'LLM06:2025 Excessive Agency',
  LLM07: 'LLM07:2025 System Prompt Leakage',
};

const SECRET = String.raw`(~\/\.ssh|\.ssh\b|id_rsa|(?<![\w.-])\.env(?![\w.])|\.aws\/credentials|api[_ -]?keys?|private key|credentials)`;

const INJECTION_PATTERNS = [
  [/ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|messages)/i, 'tells the model to ignore its instructions'],
  [/<\s*\/?\s*(important|system|secret|instructions?)\s*>/i, 'contains pseudo-system tags such as <IMPORTANT>'],
  [/(do not|don't|never) (tell|mention|inform|reveal to|show) (the )?user/i, 'asks the model to hide something from the user'],
  // Chaining hints ("before using this tool, call list_x") are normal; reading or sending data first is not.
  [/before (using|calling) (this|any other) tool[^.]{0,80}\b(read|send|include|pass|attach|upload)\b/i, 'tries to change how other tools are used'],
  [/(whenever|every time|each time|when) (the )?[\w.-]+ tool is (used|called)|(never|do not|don't) call [\w.-]+ directly|\b(supersedes|replaces|overrides) (the |all )?(other )?(tools?|servers?)\b/i, 'tries to change how other tools are used'],
  // Mentioning a secret is fine ("lists API key names"); acting on it is what matters.
  [new RegExp(String.raw`\b(read|send|pass|include|attach|upload|copy|forward|cat|leak|lee|leer|envía|envia|enviar|adjunta|incluye|copia|sube|leia|envie|anexe|inclua|copie)\b[^.]{0,80}` + SECRET, 'i'), 'tells the model to read or send secrets or credential files'],
  // Spanish and Portuguese: "no le digas (nada) al usuario", "não diga ao usuário".
  [/\b(no le digas|no le menciones|no informes|sin decirle|não (diga|conte|informe|mencione))\b[^.]{0,30}\b(usuario|usuária|usuário|cliente)\b/i, 'asks the model to hide something from the user'],
  [/(send|forward|copy|include) .{0,40}(to|in) (the )?(sidenote|note|parameter|http|url|webhook)/i, 'asks the model to move data into a parameter or URL'],
  [/!\[[^\]]*\]\(https?:\/\//i, 'embeds an external image, a classic data-exfiltration channel'],
  [/\b(ask|request|prompt) (the user|them|the customer) for (their |the |a )?[\w ]{0,25}(password|passcode|pin|otp|2fa|verification code|seed phrase|card number)/i, 'tells the model to ask the user for credentials'],
  [/\b(note|message|instructions?) (to|for) the (ai|assistant|model|llm)\b|\bfrom now on,? you (are|must|will)\b|\byou are now in\b/i, 'speaks directly to the model to change its behavior'],
  [/[A-Za-z0-9+/]{80,}={0,2}/, 'contains a long encoded blob that can hide instructions'],
];

const INVISIBLE_CHARS = /[​-‏‪-‮⁠-⁤﻿]/;

// Returns why a piece of text looks like it carries instructions for the model.
export function injectionSignals(text = '') {
  const signals = INJECTION_PATTERNS.filter(([pattern]) => pattern.test(text)).map(([pattern, why]) => ({
    why,
    evidence: text.match(pattern)[0],
  }));
  if (INVISIBLE_CHARS.test(text)) signals.push({ why: 'contains invisible Unicode characters', evidence: '(hidden characters)' });
  return signals;
}

const CAPABILITIES = [
  { id: 'exec', pattern: /\b(exec|shell|bash|command|run_?code|eval|terminal|subprocess)\b/i, label: 'code or command execution', severity: 'high' },
  { id: 'destructive', pattern: /\b(delete|drop|remove|truncate|destroy|wipe|purge)\b/i, label: 'destructive operations', severity: 'high' },
  { id: 'financial', pattern: /\b(payment|pay|transfer|refund|charge|invoice|payout|wire)\b/i, label: 'money movement', severity: 'high' },
  { id: 'outbound', pattern: /\b(send|email|mail|post|http|fetch|webhook|upload|publish|tweet|message)\b/i, label: 'outbound communication', severity: 'medium' },
  { id: 'write', pattern: /\b(write|update|create|insert|modify|edit|save)\b/i, label: 'write access', severity: 'low' },
  { id: 'private_read', pattern: /\b(customer|client|user|employee|patient|record|database|db|crm|file|document|inbox|secret)s?\b/i, label: 'access to private data', severity: 'info' },
];

// "foo_bar" and "fooBar" become "foo bar" so word-boundary patterns match tool names.
const words = (s = '') => s.replace(/[_\-.]/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2');

export function capabilitiesOf(tool) {
  const text = `${words(tool.name)} ${tool.description ?? ''}`;
  return CAPABILITIES.filter((c) => c.pattern.test(text)).map((c) => c.id);
}

export function checkTool(tool) {
  const findings = [];
  const desc = tool.description ?? '';
  const where = { tool: tool.name };

  for (const [pattern, why] of INJECTION_PATTERNS) {
    if (pattern.test(desc)) {
      findings.push({
        id: 'tool-poisoning',
        severity: 'critical',
        owasp: OWASP.LLM01,
        title: `Tool description ${why}`,
        detail: `The description of "${tool.name}" is read by the model as trusted context. Text like this can make an agent leak data or misuse other tools without the user noticing.`,
        evidence: desc.match(pattern)[0],
        ...where,
      });
    }
  }

  if (INVISIBLE_CHARS.test(desc) || INVISIBLE_CHARS.test(tool.name)) {
    findings.push({
      id: 'invisible-characters',
      severity: 'high',
      owasp: OWASP.LLM01,
      title: 'Invisible Unicode characters in tool metadata',
      detail: 'Zero-width or bidirectional control characters can hide instructions from human reviewers while the model still reads them.',
      ...where,
    });
  }

  if (desc.length > 1500) {
    findings.push({
      id: 'long-description',
      severity: 'low',
      owasp: OWASP.LLM01,
      title: `Unusually long tool description (${desc.length} characters)`,
      detail: 'Long descriptions are a common place to hide instructions. Review it manually.',
      ...where,
    });
  }

  const caps = capabilitiesOf(tool);
  for (const cap of CAPABILITIES.filter((c) => caps.includes(c.id) && c.severity !== 'info')) {
    findings.push({
      id: `capability-${cap.id}`,
      severity: cap.severity,
      owasp: OWASP.LLM06,
      title: `Tool grants ${cap.label}`,
      detail: `If an attacker controls any text the agent reads, they may be able to trigger "${tool.name}". Require human approval or narrow its scope.`,
      ...where,
    });
  }

  const a = tool.annotations ?? {};
  if (a.readOnlyHint === true && caps.some((c) => ['exec', 'destructive', 'financial', 'write'].includes(c))) {
    findings.push({
      id: 'annotation-mismatch',
      severity: 'medium',
      owasp: OWASP.LLM06,
      title: 'Tool claims to be read-only but looks like it changes state',
      detail: 'Clients may skip confirmation for read-only tools. Check that the annotation is correct.',
      ...where,
    });
  }
  if (caps.some((c) => ['exec', 'destructive', 'financial'].includes(c)) && a.destructiveHint === undefined) {
    findings.push({
      id: 'missing-annotations',
      severity: 'low',
      owasp: OWASP.LLM06,
      title: 'High-impact tool without destructiveHint annotation',
      detail: 'Annotations let clients ask for confirmation before risky calls.',
      ...where,
    });
  }

  const props = tool.inputSchema?.properties ?? {};
  for (const [name, schema] of Object.entries(props)) {
    const risky = /^(path|file|filename|url|uri|command|cmd|query|sql|script|code)$/i.test(name);
    const constrained = schema.enum || schema.pattern || schema.format || schema.maxLength;
    if (risky && (schema.type === 'string' || !schema.type) && !constrained) {
      findings.push({
        id: 'unconstrained-input',
        severity: 'low',
        owasp: OWASP.LLM06,
        title: `Free-form "${name}" parameter without constraints`,
        detail: 'Add an allowlist, pattern or length limit so an injected instruction cannot point the tool anywhere it wants.',
        ...where,
      });
    }
  }

  return findings;
}

// Private data + a way to send it out, on the same server, is the combination
// prompt-injection attacks need to exfiltrate data.
export function checkServer(tools) {
  const findings = tools.flatMap(checkTool);
  const readers = tools.filter((t) => capabilitiesOf(t).includes('private_read'));
  const senders = tools.filter((t) => capabilitiesOf(t).includes('outbound'));
  if (readers.length && senders.length) {
    findings.push({
      id: 'exfiltration-path',
      severity: 'high',
      owasp: OWASP.LLM02,
      title: 'Private data and an outbound channel are exposed together',
      detail: `An injected instruction could read data with ${readers.map((t) => `"${t.name}"`).join(', ')} and send it out with ${senders.map((t) => `"${t.name}"`).join(', ')}. Split these tools across agents or require approval for outbound calls.`,
      tool: '(server)',
    });
  }
  return findings;
}
