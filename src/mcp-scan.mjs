// Connects to an MCP server, lists what it exposes and runs the static rules.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { checkServer, injectionSignals, OWASP } from './rules.mjs';

// Only tools that declare themselves read-only and need no arguments are called,
// so the opt-in output check cannot change anything on the target.
const safeToCall = (tool) =>
  tool.annotations?.readOnlyHint === true && !(tool.inputSchema?.required ?? []).length;

async function checkOutputs(client, tools) {
  const findings = [];
  const called = [];
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
  return { findings, called };
}

export async function scanMcp({ command, args = [], url, callReadonly = false }) {
  const transport = url
    ? new StreamableHTTPClientTransport(new URL(url))
    : new StdioClientTransport({ command, args, stderr: 'ignore' });
  const client = new Client({ name: 'avenzoq-probe', version: '0.1.0' });

  await client.connect(transport);
  try {
    const server = client.getServerVersion();
    const { tools } = await client.listTools();
    const findings = checkServer(tools);
    let called;
    if (callReadonly) {
      const outputs = await checkOutputs(client, tools);
      findings.push(...outputs.findings);
      called = outputs.called;
    }
    return {
      target: url ?? [command, ...args].join(' '),
      kind: 'mcp',
      server: server ? `${server.name} ${server.version}` : 'unknown',
      tools: tools.map((t) => t.name),
      called,
      findings,
    };
  } finally {
    await client.close();
  }
}
