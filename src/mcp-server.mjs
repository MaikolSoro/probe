// Exposes Probe's static scans as an MCP server, so an AI client (Claude, Cursor,
// VS Code) can scan an MCP server, a local client config, a skills folder or
// documents on request: "check this MCP server before I install it" and the agent runs Probe.
//
// Only the read-only, static scans are exposed. `probe agent` actively attacks a
// live target, so it is deliberately NOT available here: an agent must never be
// able to launch prompt-injection attacks at a third party through this server.
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { scanMcp } from './mcp-scan.mjs';
import { scanConfigs } from './config-scan.mjs';
import { scanSkills } from './skills-scan.mjs';
import { scanDocs } from './docs-scan.mjs';
import { printSummary, counts } from './report.mjs';

// A scan result becomes an MCP tool result: the plain-text summary (no ANSI colour,
// since it is read by another program) followed by the findings as JSON so the
// calling agent can reason about them.
function toolResult(scan) {
  const findings = scan.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, where: f.tool, owasp: f.owasp }));
  const data = { kind: scan.kind, target: scan.target, counts: counts(scan.findings), inconclusive: scan.inconclusive ?? null, findings };
  const text = `${printSummary(scan, { color: false })}\n\n\`\`\`json\n${JSON.stringify(data, null, 2)}\n\`\`\``;
  return { content: [{ type: /** @type {const} */ ('text'), text }] };
}

const fail = (message) => ({ content: [{ type: /** @type {const} */ ('text'), text: `probe: ${message}` }], isError: true });

export function buildServer({ name = 'avenzoq-probe', version = '0.0.0' } = {}) {
  const server = new McpServer({ name, version });

  server.registerTool(
    'scan_mcp_server',
    {
      title: 'Scan an MCP server',
      description:
        'Statically analyse the tool definitions an MCP server exposes (names, descriptions, input schemas, annotations) for prompt injection, tool poisoning, excessive capabilities and other risks. Give either `url` for a remote Streamable HTTP server, or `command` (and `args`) to start a local stdio server. No tool is executed unless `callReadonly` is true, and then only tools that declare themselves read-only and take no arguments.',
      inputSchema: {
        url: z.string().url().optional().describe('Remote Streamable HTTP MCP server URL'),
        command: z.string().optional().describe('Command to start a local stdio MCP server, e.g. "npx"'),
        args: z.array(z.string()).optional().describe('Arguments for the command'),
        callReadonly: z.boolean().optional().describe('Also call read-only, no-argument tools and check their output for planted instructions (default false)'),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ url, command, args = [], callReadonly = false }) => {
      if (!url && !command) return fail('give either url (remote) or command (local stdio) to scan.');
      try {
        return toolResult(await scanMcp({ url, command, args, callReadonly }));
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    'scan_mcp_config',
    {
      title: 'Audit local MCP client configuration',
      description:
        'Audit the MCP servers configured in local AI clients (Claude Desktop/Code, Cursor, VS Code, Windsurf): secrets in plain text, unpinned packages and insecure transport. By default this is static (the configured servers are NOT started); set `connect` to true to also start each server and scan its tools.',
      inputSchema: {
        path: z.string().optional().describe('A specific config file to scan (default: auto-detect the known clients)'),
        connect: z.boolean().optional().describe('Start each configured server and scan its tools (default false: static review only)'),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path, connect = false }) => {
      try {
        return toolResult(await scanConfigs({ paths: path ? [path] : undefined, connect }));
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    'scan_skills',
    {
      title: 'Scan agent skills and instruction files',
      description:
        'Statically scan a folder of agent skills, slash commands, CLAUDE.md/AGENTS.md, hooks and install scripts before you install them: instructions aimed at the agent, invisible characters, scripts that download and run code, writes to sensitive files and MCP installs. Nothing is executed.',
      inputSchema: {
        path: z.string().describe('Path to the skills or instructions folder to scan'),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ path }) => {
      try {
        return toolResult(scanSkills(path));
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  server.registerTool(
    'scan_documents',
    {
      title: 'Scan documents for hidden AI instructions',
      description:
        'Statically scan a document or a folder of documents (PDF, Word, PowerPoint, Excel, HTML, Markdown, text) before an AI assistant or RAG pipeline reads them: instructions hidden in white or tiny text, invisible PDF text, hidden formatting or CSS, comments, metadata and invisible Unicode. Nothing is executed.',
      inputSchema: {
        path: z.string().describe('Path to a document or a folder of documents'),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ path }) => {
      try {
        return toolResult(scanDocs(path));
      } catch (err) {
        return fail(err.message);
      }
    },
  );

  return server;
}

// Start the server on stdio. Stdout is the MCP channel, so nothing else may write
// to it; the scan modules only return data, they do not print.
export async function serve(info) {
  const server = buildServer(info);
  await server.connect(new StdioServerTransport());
  return server;
}
