#!/usr/bin/env node
// avenzoq-probe: security scanner for MCP servers, AI agents and agent skills.
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanMcp } from './mcp-scan.mjs';
import { scanAgent } from './agent-scan.mjs';
import { scanSkills } from './skills-scan.mjs';
import { scanConfigs } from './config-scan.mjs';
import { printSummary, toMarkdown, ORDER } from './report.mjs';
import { toHtml, htmlToPdf } from './report-html.mjs';
import { toSarif } from './sarif.mjs';
import { loadIgnore, applyIgnore } from './ignore.mjs';
import { readPins, writePins } from './pins.mjs';
import { DEFAULT_MODEL } from './llm.mjs';
import { judgeSkills } from './skills-scan.mjs';

const { version } = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'));

const USAGE = `avenzoq-probe ${version} — security scanner for MCP servers, AI agents and agent skills

Usage:
  probe mcp [options] -- <command> [args...]   Scan a local (stdio) MCP server
  probe mcp --url <url> [options]              Scan a remote (Streamable HTTP) MCP server
  probe agent --url <url> [options]            Send 32 prompt-injection probes to a chat endpoint
  probe agent --target openai|anthropic --model <id>   ...or straight to a model API
  probe config [--path <file>] [--no-connect]  Audit the MCP servers configured in Claude, Cursor,
                                               VS Code and Windsurf (starts each configured server)
  probe skills <path>                          Scan skills, slash commands, CLAUDE.md/AGENTS.md,
                                               hooks and install scripts before you install them

MCP and config options:
  --call-readonly     Also call tools marked read-only that take no arguments and
                      check their output for planted instructions
  --pin <file>        Rug-pull detection: pin tool definitions on first scan, report changes later
  --update-pins       Accept the current tool definitions into the pin file

LLM judge (mcp, config, skills):
  --llm               Ask Claude to confirm, dismiss or add injection findings (needs ANTHROPIC_API_KEY)
  --llm-model <id>    Model for the judge (default: ${DEFAULT_MODEL})

Agent options:
  --target <type>     json (default), openai (OpenAI-compatible APIs) or anthropic
  --model <id>        Model for --target openai/anthropic
  --system <text|@file>  System prompt to test with --target openai/anthropic
  --field <name>      JSON field for the message (default: message)
  --reply <path>      JSON path of the answer, e.g. choices.0.message.content (default: reply)
  --history-field <n> Send the whole conversation in this JSON field (enables multi-turn probes)
  --header "K: V"     Extra request header (repeatable)
  --categories <list> Only run these: direct,indirect,obfuscation,exfiltration,leak,multi-turn,tool-use

Reports:
  --out <dir>         Write report.md and report.json to this folder
  --html              Also write a client-ready report.html (implies --out reports/latest)
  --pdf               Also write report.pdf from the HTML (needs Chrome or Chromium)
  --lang <en|es>      Language of the HTML/PDF report (default: en)
  --client <name>     Client name shown on the HTML/PDF report
  --sarif <file>      Write SARIF 2.1.0 for GitHub code scanning
  --sarif-uri <path>  File to attach non-file findings to in SARIF (default: the scanned file)
  --json              Print the raw JSON result instead of the summary
  --timeout <seconds> How long to wait for each MCP server to start and answer (default: 30)

CI:
  --fail-on <level>   Exit 1 when a finding is at or above: critical, high (default), medium, low, none
  --ignore <file>     Suppressions file (default: ./.probeignore if present)

  --version           Print the version

Exit codes: 0 = below the --fail-on threshold, 1 = at or above it, 2 = usage or connection error.
Only scan systems you own or are authorized to test.`;

const FLAGS = { '--json': 'json', '--call-readonly': 'callReadonly', '--html': 'html', '--pdf': 'pdf', '--no-connect': 'noConnect', '--version': 'version', '--llm': 'llm', '--update-pins': 'updatePins' };

function parse(argv) {
  const opts = { headers: {} };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      rest.push(...argv.slice(i + 1));
      break;
    }
    if (FLAGS[a]) opts[FLAGS[a]] = true;
    else if (a === '--header') {
      const [k, ...v] = argv[++i].split(':');
      opts.headers[k.trim()] = v.join(':').trim();
    } else if (a.startsWith('--')) opts[a.slice(2)] = argv[++i];
    else rest.push(a);
  }
  return { opts, rest };
}

function failThreshold(level = 'high') {
  if (level === 'none') return -1; // no severity index is <= -1, so nothing fails the run
  const i = ORDER.indexOf(level);
  if (i === -1) throw new Error(`--fail-on must be one of: ${ORDER.join(', ')}, none`);
  return i;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === '--version' || argv[0] === '-v') {
    console.log(version);
    return 0;
  }
  const [mode, ...modeArgs] = argv;
  const { opts, rest } = parse(modeArgs);
  const threshold = failThreshold(opts['fail-on']);

  const timeoutMs = opts.timeout ? Number(opts.timeout) * 1000 : undefined;
  const llm = opts.llm ? { model: opts['llm-model'] ?? DEFAULT_MODEL } : undefined;
  const pins = opts.pin ? { file: opts.pin, data: readPins(opts.pin), update: opts.updatePins } : undefined;
  const system = opts.system?.startsWith('@') ? readFileSync(opts.system.slice(1), 'utf8') : opts.system;

  let scan;
  if (mode === 'mcp' && (opts.url || rest.length)) {
    scan = await scanMcp({ url: opts.url, command: rest[0], args: rest.slice(1), callReadonly: opts.callReadonly, pins, llm, timeoutMs });
  } else if (mode === 'config') {
    scan = await scanConfigs({ paths: opts.path ? [opts.path] : undefined, connect: !opts.noConnect, pins, llm, timeoutMs });
  } else if (mode === 'skills' && rest[0]) {
    scan = scanSkills(rest[0]);
    if (llm) scan = await judgeSkills(scan, llm);
  } else if (mode === 'agent' && (opts.url || opts.target === 'openai' || opts.target === 'anthropic')) {
    if (opts.target && opts.target !== 'json' && !opts.model) throw new Error('--target openai/anthropic needs --model');
    scan = await scanAgent({
      target: opts.target,
      url: opts.url,
      model: opts.model,
      system,
      field: opts.field,
      reply: opts.reply,
      historyField: opts['history-field'],
      headers: opts.headers,
      categories: opts.categories,
    });
  } else {
    console.log(USAGE);
    return mode ? 2 : 0;
  }

  if (pins) writePins(pins.file, pins.data);

  const { kept, suppressed } = applyIgnore(scan.findings, loadIgnore(opts.ignore));
  scan.findings = kept;
  if (suppressed) scan.suppressed = suppressed;

  console.log(opts.json ? JSON.stringify(scan, null, 2) : printSummary(scan));

  if (opts.sarif) {
    writeFileSync(opts.sarif, JSON.stringify(toSarif(scan, { version, anchor: opts['sarif-uri'] }), null, 2));
    console.log(`SARIF written to ${opts.sarif}`);
  }
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

  return scan.findings.some((f) => ORDER.indexOf(f.severity) <= threshold) ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`probe: ${err.message}`);
    process.exit(2);
  });
