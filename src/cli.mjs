#!/usr/bin/env node
// avenzoq-probe: security scanner for MCP servers, AI agents and agent skills.
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanMcp } from './mcp-scan.mjs';
import { scanAgent } from './agent-scan.mjs';
import { scanSkills } from './skills-scan.mjs';
import { scanConfigs } from './config-scan.mjs';
import { scanDocs } from './docs-scan.mjs';
import { printSummary, toMarkdown, ORDER } from './report.mjs';
import { toHtml, htmlToPdf } from './report-html.mjs';
import { toSarif } from './sarif.mjs';
import { loadIgnore, applyIgnore } from './ignore.mjs';
import { readPins, writePins } from './pins.mjs';
import { DEFAULT_MODEL } from './llm.mjs';
import { judgeSkills } from './skills-scan.mjs';
import { diffScans, printDiff, diffToMarkdown } from './diff.mjs';
import { authorizationMarkdown, authorizationHtml } from './authorization.mjs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';

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
  probe docs <path>                            Scan documents an AI will read (PDF, Word, PowerPoint,
                                               Excel, HTML, Markdown, text) for hidden instructions
  probe serve                                  Run Probe as an MCP server (stdio) so an AI client
                                               can scan servers, configs and skills on request
  probe diff <before.json> <after.json>        Compare two report.json files (resolved / new / still there)
  probe authorization [options]                Print the "authorization to test" document a client signs

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
  --yes               Confirm you are authorized to test the target (required when not interactive)

Authorization document options:
  --client <name>     Client organization        --authby <name>  Person who authorizes
  --role <title>      Their role                 --scope "a, b"   Systems in scope (comma/newline list)
  --exclude "x, y"    Systems out of scope       --start / --end  Testing window
  (prints Markdown; with --out <dir> writes authorization.md, plus --html / --pdf for the branded version)

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

// Boolean flags and the option key the code reads them as.
const FLAGS = { json: 'json', 'call-readonly': 'callReadonly', html: 'html', pdf: 'pdf', 'no-connect': 'noConnect', version: 'version', llm: 'llm', 'update-pins': 'updatePins', yes: 'yes' };
// Options that take a value; they keep their --name as the key (opts['fail-on']).
const VALUES = [
  'url', 'out', 'lang', 'client', 'sarif', 'sarif-uri', 'timeout', 'fail-on', 'ignore', 'pin', 'llm-model', 'path',
  'target', 'model', 'system', 'field', 'reply', 'history-field', 'categories',
  'tester', 'authby', 'role', 'scope', 'exclude', 'start', 'end',
];
/** @type {import('node:util').ParseArgsConfig['options']} */
const OPTIONS = {
  ...Object.fromEntries(Object.keys(FLAGS).map((f) => [f, { type: 'boolean' }])),
  ...Object.fromEntries(VALUES.map((v) => [v, { type: 'string' }])),
  version: { type: 'boolean', short: 'v' },
  header: { type: 'string', multiple: true },
};

// `probe agent` actively attacks a live target. Testing a system you do not own
// or control, without written authorization, is illegal in most countries. This
// gate makes the user confirm, and blocks non-interactive runs that did not pass --yes.
async function confirmAuthorization(opts) {
  if (opts.yes) return;
  const where = opts.url ?? `${opts.target} API`;
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error(
      `refusing to attack ${where} without confirmation. Only test systems you own or are authorized to test, ` +
        `then pass --yes. Sending these probes to someone else's service without written permission may be illegal.`,
    );
  }
  console.log(
    `\n⚠  'probe agent' will send prompt-injection attacks to:\n   ${where}\n\n` +
      `Only do this on a system you OWN or have WRITTEN AUTHORIZATION to test.\n` +
      `Testing someone else's service without permission may be illegal.\n`,
  );
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question('Do you confirm you are authorized to test this target? (yes/no) ', resolve));
  rl.close();
  if (!/^(y|yes|s|si|sí)$/i.test(answer.trim())) throw new Error('not confirmed — scan cancelled.');
}

// Everything after `--` is the MCP server command and is passed through untouched.
// Unknown options are an error rather than silently ignored, so a typo in CI fails loudly.
function parse(argv) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    throw new Error(`${err.message.replace(/\s*\n\s*/g, ' ').replace(/\.?$/, '.')} Run \`probe\` without arguments for usage.`);
  }
  const opts = { headers: {} };
  for (const [key, value] of Object.entries(parsed.values)) {
    if (key === 'header') {
      for (const h of /** @type {string[]} */ (value)) {
        const [k, ...v] = h.split(':');
        opts.headers[k.trim()] = v.join(':').trim();
      }
    } else opts[FLAGS[key] ?? key] = value;
  }
  return { opts, rest: parsed.positionals };
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

  // `probe serve` runs Probe itself as an MCP server. It speaks MCP on stdout and
  // keeps running, so it is handled before the one-shot scan modes below.
  if (mode === 'serve') {
    const { serve } = await import('./mcp-server.mjs');
    await serve({ name: 'avenzoq-probe', version });
    return new Promise(() => {}); // run until the transport closes
  }

  const { opts, rest } = parse(modeArgs);
  const threshold = failThreshold(opts['fail-on']);

  // `probe diff before.json after.json` compares two report.json files to show what
  // a fix changed. It reads results, it does not scan.
  if (mode === 'diff') {
    if (rest.length < 2) {
      console.log(USAGE);
      return 2;
    }
    const before = JSON.parse(readFileSync(rest[0], 'utf8'));
    const after = JSON.parse(readFileSync(rest[1], 'utf8'));
    const d = diffScans(before, after);
    console.log(opts.json ? JSON.stringify(d, null, 2) : printDiff(d));
    if (opts.out) {
      mkdirSync(opts.out, { recursive: true });
      writeFileSync(join(opts.out, 'diff.md'), diffToMarkdown(d));
      console.log(`\nWritten to ${opts.out}/diff.md`);
    }
    return d.added.some((f) => ORDER.indexOf(f.severity) <= threshold) ? 1 : 0;
  }

  // `probe authorization` prints the "authorization to test" document a client signs
  // before an assessment. Fields left out stay as blanks to fill in.
  if (mode === 'authorization' || mode === 'authz') {
    const lang = opts.lang === 'en' ? 'en' : 'es';
    const md = authorizationMarkdown(opts, lang);
    if (opts.out) {
      mkdirSync(opts.out, { recursive: true });
      writeFileSync(join(opts.out, 'authorization.md'), md);
      const written = ['authorization.md'];
      if (opts.html || opts.pdf) {
        const htmlPath = join(opts.out, 'authorization.html');
        writeFileSync(htmlPath, authorizationHtml(opts, lang));
        written.push('authorization.html');
        if (opts.pdf) {
          htmlToPdf(htmlPath, join(opts.out, 'authorization.pdf'));
          written.push('authorization.pdf');
        }
      }
      console.log(`Written to ${opts.out}/: ${written.join(', ')}`);
    } else {
      console.log(md);
    }
    return 0;
  }

  const timeoutMs = opts.timeout ? Number(opts.timeout) * 1000 : undefined;
  const llm = opts.llm ? { model: opts['llm-model'] ?? DEFAULT_MODEL } : undefined;
  const pins = opts.pin ? { file: opts.pin, data: readPins(opts.pin), update: opts.updatePins } : undefined;
  const system = opts.system?.startsWith('@') ? readFileSync(opts.system.slice(1), 'utf8') : opts.system;

  let scan;
  if (mode === 'mcp' && (opts.url || rest.length)) {
    scan = await scanMcp({ url: opts.url, command: rest[0], args: rest.slice(1), callReadonly: opts.callReadonly, pins, llm, timeoutMs });
  } else if (mode === 'config') {
    scan = await scanConfigs({ paths: opts.path ? [opts.path] : undefined, connect: !opts.noConnect, pins, llm, timeoutMs });
  } else if (mode === 'docs' && rest[0]) {
    scan = scanDocs(rest[0]);
  } else if (mode === 'skills' && rest[0]) {
    scan = scanSkills(rest[0]);
    if (llm) scan = await judgeSkills(scan, llm);
  } else if (mode === 'agent' && (opts.url || opts.target === 'openai' || opts.target === 'anthropic')) {
    if (opts.target && opts.target !== 'json' && !opts.model) throw new Error('--target openai/anthropic needs --model');
    await confirmAuthorization(opts);
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

  // An inconclusive scan did not actually test anything: exit 2 so CI never reads it as a pass.
  if (scan.inconclusive) return 2;
  return scan.findings.some((f) => ORDER.indexOf(f.severity) <= threshold) ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`probe: ${err.message}`);
    process.exit(2);
  });
