#!/usr/bin/env node
// avenzoq-probe: security scanner for MCP servers and AI agents.
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { scanMcp } from './mcp-scan.mjs';
import { scanAgent } from './agent-scan.mjs';
import { printSummary, toMarkdown } from './report.mjs';

const USAGE = `avenzoq-probe 0.1.0 — security scanner for MCP servers and AI agents

Usage:
  probe mcp [options] -- <command> [args...]   Scan a local (stdio) MCP server
  probe mcp --url <url> [options]              Scan a remote (Streamable HTTP) MCP server
  probe agent --url <url> [options]            Send prompt-injection probes to a chat endpoint

MCP options:
  --call-readonly     Also call tools marked read-only that take no arguments and
                      check their output for planted instructions

Agent options:
  --field <name>      JSON field for the message (default: message)
  --reply <path>      JSON path of the answer, e.g. choices.0.message.content (default: reply)
  --header "K: V"     Extra request header (repeatable)

Common options:
  --out <dir>         Write report.md and report.json to this folder
  --json              Print the raw JSON result instead of the summary

Exit code is 1 when there are critical or high findings, so it can run in CI.
Only scan systems you own or are authorized to test.`;

function parse(argv) {
  const opts = { headers: {} };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      rest.push(...argv.slice(i + 1));
      break;
    }
    if (a === '--json') opts.json = true;
    else if (a === '--call-readonly') opts.callReadonly = true;
    else if (a === '--header') {
      const [k, ...v] = argv[++i].split(':');
      opts.headers[k.trim()] = v.join(':').trim();
    } else if (a.startsWith('--')) opts[a.slice(2)] = argv[++i];
    else rest.push(a);
  }
  return { opts, rest };
}

async function main() {
  const [mode, ...argv] = process.argv.slice(2);
  const { opts, rest } = parse(argv);

  let scan;
  if (mode === 'mcp' && (opts.url || rest.length)) {
    scan = await scanMcp({ url: opts.url, command: rest[0], args: rest.slice(1), callReadonly: opts.callReadonly });
  } else if (mode === 'agent' && opts.url) {
    scan = await scanAgent({ url: opts.url, field: opts.field, reply: opts.reply, headers: opts.headers });
  } else {
    console.log(USAGE);
    process.exit(mode ? 2 : 0);
  }

  console.log(opts.json ? JSON.stringify(scan, null, 2) : printSummary(scan));

  if (opts.out) {
    mkdirSync(opts.out, { recursive: true });
    writeFileSync(join(opts.out, 'report.md'), toMarkdown(scan));
    writeFileSync(join(opts.out, 'report.json'), JSON.stringify(scan, null, 2));
    console.log(`\nReport written to ${opts.out}/report.md`);
  }

  process.exit(scan.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0);
}

main().catch((err) => {
  console.error(`probe: ${err.message}`);
  process.exit(2);
});
