#!/usr/bin/env node
// avenzoq-probe: security scanner for MCP servers and AI agents.
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { scanMcp } from './mcp-scan.mjs';
import { scanAgent } from './agent-scan.mjs';
import { scanSkills } from './skills-scan.mjs';
import { scanConfigs } from './config-scan.mjs';
import { printSummary, toMarkdown } from './report.mjs';
import { toHtml, htmlToPdf } from './report-html.mjs';

const USAGE = `avenzoq-probe 0.2.0 — security scanner for MCP servers, AI agents and agent skills

Usage:
  probe mcp [options] -- <command> [args...]   Scan a local (stdio) MCP server
  probe mcp --url <url> [options]              Scan a remote (Streamable HTTP) MCP server
  probe agent --url <url> [options]            Send prompt-injection probes to a chat endpoint
  probe config [--path <file>] [--no-connect]  Audit the MCP servers configured in Claude, Cursor,
                                               VS Code and Windsurf (starts each configured server)
  probe skills <path>                          Scan skills, slash commands, CLAUDE.md/AGENTS.md,
                                               hooks and install scripts before you install them

MCP options:
  --call-readonly     Also call tools marked read-only that take no arguments and
                      check their output for planted instructions

Agent options:
  --field <name>      JSON field for the message (default: message)
  --reply <path>      JSON path of the answer, e.g. choices.0.message.content (default: reply)
  --header "K: V"     Extra request header (repeatable)

Common options:
  --out <dir>         Write report.md and report.json to this folder
  --html              Also write a client-ready report.html (implies --out reports/latest)
  --pdf               Also write report.pdf from the HTML (needs Chrome or Chromium)
  --lang <en|es>      Language of the HTML/PDF report (default: en)
  --client <name>     Client name shown on the HTML/PDF report
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
    else if (a === '--html') opts.html = true;
    else if (a === '--pdf') opts.pdf = true;
    else if (a === '--no-connect') opts.noConnect = true;
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
  } else if (mode === 'config') {
    scan = await scanConfigs({ paths: opts.path ? [opts.path] : undefined, connect: !opts.noConnect });
  } else if (mode === 'skills' && rest[0]) {
    scan = scanSkills(rest[0]);
  } else if (mode === 'agent' && opts.url) {
    scan = await scanAgent({ url: opts.url, field: opts.field, reply: opts.reply, headers: opts.headers });
  } else {
    console.log(USAGE);
    process.exit(mode ? 2 : 0);
  }

  console.log(opts.json ? JSON.stringify(scan, null, 2) : printSummary(scan));

  if ((opts.html || opts.pdf) && !opts.out) opts.out = join('reports', 'latest');
  if (opts.out) {
    mkdirSync(opts.out, { recursive: true });
    writeFileSync(join(opts.out, 'report.md'), toMarkdown(scan));
    writeFileSync(join(opts.out, 'report.json'), JSON.stringify(scan, null, 2));
    const written = ['report.md', 'report.json'];
    if (opts.html || opts.pdf) {
      const htmlPath = join(opts.out, 'report.html');
      writeFileSync(htmlPath, toHtml(scan, { lang: opts.lang, client: opts.client }));
      written.push('report.html');
      if (opts.pdf) {
        htmlToPdf(htmlPath, join(opts.out, 'report.pdf'));
        written.push('report.pdf');
      }
    }
    console.log(`\nReports written to ${opts.out}/: ${written.join(', ')}`);
  }

  process.exit(scan.findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0);
}

main().catch((err) => {
  console.error(`probe: ${err.message}`);
  process.exit(2);
});
