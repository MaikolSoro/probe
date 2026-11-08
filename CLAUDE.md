# CLAUDE.md: AVENZOQ Probe

Context for any Claude session that works on this project. Read this first, then `docs/STRATEGY.md` for the business side and `docs/ROADMAP.md` for what to build next.

## What this is

**Probe** is an open-source CLI that security-tests **MCP servers** and **AI chat agents**. It is the first piece of a planned AI-agent-security product line (Probe → Guard → Compliance), built by AVENZOQ, a small software, AI and cybersecurity company from Costa Rica. The founder is a former pentester.

This project is **separate** from the AVENZOQ website (`../avenqor-web`, its own git repo, deployed on Vercel). Do not mix the two.

## Status (2026-11-07)

- Version 0.1.0, working and tested locally (`npm test`: 6/6 pass; both demos run; HTML/PDF reports in es/en verified).
- **Not published:** no GitHub repo and no npm package yet.
- **No license chosen yet.** Apache-2.0 or MIT are the usual choices for adoption. This is the owner's decision, so ask before adding one.
- Package name `avenzoq-probe`, binary `probe`.

## Commands

```bash
npm install
npm test                                   # node --test test/*.test.mjs
npm run demo:mcp                           # scan examples/vulnerable-mcp-server.mjs (with --call-readonly)
node examples/mock-agent.mjs &             # simulated vulnerable agent on :8787
npm run demo:agent                         # probe it
node src/cli.mjs                           # usage
```

## Layout

| Path | Purpose |
|---|---|
| `src/cli.mjs` | Argument parsing, runs a scan, prints the summary, writes reports, sets the exit code (1 = critical/high, 2 = error) |
| `src/rules.mjs` | Static rules for MCP tool definitions (`checkTool`, `checkServer`), `injectionSignals(text)`, OWASP labels |
| `src/mcp-scan.mjs` | Connects over stdio or Streamable HTTP with `@modelcontextprotocol/sdk`, lists tools, optional read-only output check |
| `src/agent-scan.mjs` | POSTs each probe to a chat endpoint and detects canaries |
| `src/payloads.mjs` | The prompt-injection probes (id, title, OWASP, `build(canary)`, optional `detect`, `severity`) |
| `src/report.mjs` | Terminal summary and Markdown report |
| `src/report-html.mjs` | Client-facing HTML report (es/en, AVENZOQ branding, fonts embedded from `assets/`) and PDF via headless Chrome |
| `src/guidance.mjs` | Plain-language "what it means / how to fix it" per finding id, in English and Spanish. **Add an entry here for every new rule or probe** |
| `assets/` | Geist fonts and the AVENZOQ mark used by the HTML report |
| `examples/` | Deliberately vulnerable MCP server and a mock agent that obeys anything. Both are fake and do nothing real |
| `test/` | `node:test` unit tests for the rules |
| `docs/` | Strategy and roadmap |
| `reports/` | Scan output (git-ignored) |

## Conventions

- Plain Node ESM (`.mjs`). No build step and no TypeScript. Keep dependencies minimal: only the MCP SDK and zod.
- MCP SDK 1.32.x uses `registerTool(name, { description, inputSchema, annotations }, cb)`, where `inputSchema` is a zod raw shape. Zod is v4.
- Findings have the shape `{ id, severity: critical|high|medium|low, owasp, title, detail, evidence?, tool }`. Keep `tool` set: use `(server)` or `(agent)` when no single tool applies.
- Comments are short and only explain *why*. Code, docs and reports are in English. The founder speaks Spanish, so answer them in Spanish (tú).

## Safety and honesty rules (non-negotiable)

1. **Static scans never call tools.** Output checks only call tools that declare `readOnlyHint: true` **and** take no required arguments, and only behind the `--call-readonly` flag.
2. **No working exploits.** Probes show that an agent obeys untrusted input (canary echo). They never try to cause real damage, exfiltrate real data or run commands.
3. Examples stay fake: dummy data, `.invalid` domains, nothing executed or sent.
4. **Don't overclaim.** Rules are pattern-based. A clean report never means "secure", so keep that sentence in the README and reports.
5. Only scan systems you own or are authorized to test. Keep this notice in the README, the CLI usage and the reports.
