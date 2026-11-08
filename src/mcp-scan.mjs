// Connects to an MCP server, lists what it exposes and runs the static rules.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport, getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { checkServer, injectionSignals, OWASP } from './rules.mjs';
import { comparePins } from './pins.mjs';
import { judgeItems, mergeVerdicts, llmFinding } from './llm.mjs';

// Only tools that declare themselves read-only and need no arguments are called,
// so the opt-in output check cannot change anything on the target.
const safeToCall = (tool) =>
  tool.annotations?.readOnlyHint === true && !(tool.inputSchema?.required ?? []).length;

async function checkOutputs(client, tools) {
  const findings = [];
  const called = [];
  const outputs = {};
  for (const tool of tools.filter(safeToCall)) {
    let text;
    try {
      const result = await client.callTool({ name: tool.name, arguments: {} }, undefined, { timeout: 15000 });
      text = (result.content ?? []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
    } catch (err) {
      called.push({ tool: tool.name, status: 'error', error: err.message });
      continue;
    }
    called.push({ tool: tool.name, status: 'ok' });
    outputs[tool.name] = text;
    for (const s of injectionSignals(text)) {
      findings.push({
        id: 'tool-output-injection',
        severity: 'critical',
        owasp: OWASP.LLM01,
        title: `Tool output ${s.why}`,
        detail: `"${tool.name}" returns content that an agent will read as context. If that content comes from users, web pages or documents, an attacker can plant instructions there (indirect prompt injection).`,
        evidence: s.evidence,
        tool: tool.name,
      });
    }
  }
  return { findings, called, outputs };
}

export async function scanMcp({ command, args = [], url, env, callReadonly = false, timeoutMs = 30000, pins, llm }) {
  const transport = url
    ? new StreamableHTTPClientTransport(new URL(url))
    : new StdioClientTransport({ command, args, env: env ? { ...getDefaultEnvironment(), ...env } : undefined, stderr: 'ignore' });
  const client = new Client({ name: 'avenzoq-probe', version: '0.5.0' });

  // A server that never answers must not hang the scan; closing the client also stops its process.
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${timeoutMs / 1000}s`)), timeoutMs);
  });
  try {
    await Promise.race([client.connect(transport), timeout]);
    const server = client.getServerVersion();
    const { tools } = await Promise.race([client.listTools(), timeout]);
    let findings = checkServer(tools);
    let called;
    let outputs = {};
    if (callReadonly) {
      const checked = await checkOutputs(client, tools);
      findings.push(...checked.findings);
      called = checked.called;
      outputs = checked.outputs;
    }
    const target = url ?? [command, ...args].join(' ');

    let pinStatus;
    if (pins) {
      const result = comparePins(pins.data, pins.key ?? target, tools, { update: pins.update });
      findings.push(...result.findings);
      pinStatus = result.status;
    }

    if (llm) {
      const items = [
        ...tools.map((t) => ({ key: `desc:${t.name}`, kind: 'MCP tool description', text: `${t.name}: ${t.description ?? ''}` })),
        ...Object.entries(outputs).map(([name, text]) => ({ key: `out:${name}`, kind: 'MCP tool output', text })),
      ];
      const verdicts = await judgeItems(items, llm);
      findings = mergeVerdicts(findings, verdicts, {
        keyOf: (f) => `${f.id === 'tool-output-injection' ? 'out' : 'desc'}:${f.tool}`,
        newFinding: (key, v) => llmFinding(key.startsWith('out:') ? 'llm-output-injection' : 'llm-tool-poisoning', key.slice(key.indexOf(':') + 1), v),
      });
    }

    return {
      target,
      kind: 'mcp',
      server: server ? `${server.name} ${server.version}` : 'unknown',
      tools: tools.map((t) => t.name),
      called,
      pins: pinStatus,
      llm: llm ? llm.model ?? 'default' : undefined,
      findings,
    };
  } finally {
    clearTimeout(timer);
    await client.close().catch(() => {});
  }
}
