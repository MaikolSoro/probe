import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// Spin up `probe serve` over stdio and talk to it like a real MCP client would.
async function withServer(fn) {
  const transport = new StdioClientTransport({ command: process.execPath, args: ['src/cli.mjs', 'serve'] });
  const client = new Client({ name: 'test', version: '0' });
  await client.connect(transport);
  try {
    await fn(client);
  } finally {
    await client.close();
  }
}

test('probe serve exposes the four static scan tools, and no agent attack tool', async () => {
  await withServer(async (client) => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['scan_documents', 'scan_mcp_config', 'scan_mcp_server', 'scan_skills']);
    // The active attack scanner must never be reachable through the MCP server.
    assert.ok(!names.some((n) => n.includes('agent')));
    for (const t of tools) assert.ok(t.annotations?.readOnlyHint, `${t.name} should be read-only`);
  });
});

test('scan_skills runs a real scan and returns a summary plus JSON', async () => {
  await withServer(async (client) => {
    const res = await client.callTool({ name: 'scan_skills', arguments: { path: 'examples' } });
    assert.ok(!res.isError);
    const text = res.content[0].text;
    assert.match(text, /AVENZOQ Probe · SKILLS/);
    const json = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1));
    assert.equal(json.kind, 'skills');
    assert.ok(Array.isArray(json.findings));
  });
});

test('scan_mcp_server without a target is a clean tool error, not a crash', async () => {
  await withServer(async (client) => {
    const res = await client.callTool({ name: 'scan_mcp_server', arguments: {} });
    assert.ok(res.isError);
    assert.match(res.content[0].text, /url.*command|command.*url/i);
  });
});
