# CLAUDE.md: AVENZOQ Probe

Context for any Claude session that works on this project. Read this first, then `docs/ROADMAP.md` for what to build next.

## What this is

**Probe** is an open-source CLI that security-tests **MCP servers** and **AI chat agents**. It is the first piece of a planned AI-agent-security product line (Probe → Guard → Compliance), built by AVENZOQ, a small software, AI and cybersecurity company from Costa Rica. The founder is a former pentester.

This project is **separate** from the AVENZOQ website (`../avenqor-web`, its own git repo, deployed on Vercel). Do not mix the two.

## Status (2026-11-07)

- Version 0.7.0 (published on npm as @avenzoq/probe up to 0.6.2, GitHub up to date): modes `mcp`, `agent`, `config`, `skills`, `serve`; SARIF, `--fail-on`, `.probeignore`, GitHub Action; **LLM judge** (`--llm`), **rug-pull pins** (`--pin`), **32 agent probes** with OpenAI/Anthropic targets, multi-turn and tool-use. `npm test` passes 29/29. The LLM judge is only tested with a mocked model (no API key used during development). Plus the **benchmark** (`bench/`, pattern F1 90 %, guarded by a test) and the **research kit** (`research/`, Docker-isolated scans with a disclosure policy). **State of MCP Security study run on 2026-11-08** (owner approved): 19 targets, 12 started, 168 tools. After fixing false positives found in manual review (v0.5.1), there are 0 critical findings and every high is a real capability. Results are in `research/results/` and `research/REPORT-draft.md`, both git-ignored and unpublished; publishing is the owner's decision. The study was later expanded to 80 targets (39 started, 406 tools, 0 hidden attacks) and the branded report lives in `research/report/` (git-ignored). v0.6.3 adds an authorization gate for `probe agent` (confirm or `--yes`) and an INCONCLUSIVE result (exit 2) when every probe fails, so an unreachable target no longer looks clean. **v0.7.0** adds `probe serve` (runs Probe as a stdio MCP server exposing the three read-only scans — `scan_mcp_server`, `scan_mcp_config`, `scan_skills` — but never the active `agent` attack) and an **executive summary** block at the top of the HTML/PDF client report (top risk, estimated effort, next step; es/en).
- **GitHub:** https://github.com/MaikolSoro/probe (branch `main`). Not on npm yet.
- **License: Apache-2.0** (`LICENSE`, `NOTICE`). The Geist fonts are under the OFL (`assets/OFL.txt`). The AVENZOQ name and logo are not licensed.
- **npm:** `@avenzoq/probe`, with the `probe` and `avenzoq-probe` commands. Only the owner can publish (`npm login`, then `npm publish`); the npm org `avenzoq` must exist first.
- **Releases:** update `CHANGELOG.md`, bump the version in `package.json`, tag `vX.Y.Z` and push the tag. The Action is used as `MaikolSoro/probe@vX.Y.Z`.

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
| `src/config-scan.mjs` | Finds MCP configs (Claude Desktop/Code, Cursor, VS Code, Windsurf), checks secrets, unpinned packages and plain HTTP, then scans each server (`--no-connect` skips starting them) |
| `src/skills-scan.mjs` | Static scan of skills, slash commands, CLAUDE.md/AGENTS.md, hooks and install scripts; severity drops for commands that only appear in docs or comments |
| `src/llm.mjs` | LLM judge: `callClaude`, `judgeItems` (fenced untrusted content, batches of 15), `mergeVerdicts` (confirm, dismiss to low, add) |
| `src/pins.mjs` | Rug-pull detection: tool fingerprints, `comparePins` (changed/added/removed), pin file I/O |
| `src/sarif.mjs` | SARIF 2.1.0 output (rules, levels, `security-severity`, file locations) |
| `src/ignore.mjs` | `.probeignore` parsing and suppression |
| `action.yml` | Composite GitHub Action (inputs `args`, `fail-on`, `sarif`, `report-dir`) |
| `src/agent-scan.mjs` | Targets (`json`, `openai`, `anthropic`), multi-turn conversations, fake-tool detection |
| `src/mcp-server.mjs` | `probe serve`: runs Probe as a stdio MCP server exposing the read-only scans (`scan_mcp_server`, `scan_mcp_config`, `scan_skills`); the active `agent` attack is intentionally not exposed |
| `src/payloads.mjs` | 32 probes in 7 categories (`build(canary)` returns a string or an array of turns; `tools: true` for tool-use; `detect({ text, toolCalls })`) and `FAKE_TOOLS` |
| `src/report.mjs` | Terminal summary and Markdown report |
| `src/report-html.mjs` | Client-facing HTML report (es/en, AVENZOQ branding, fonts embedded from `assets/`) and PDF via headless Chrome |
| `src/guidance.mjs` | Plain-language "what it means / how to fix it" per finding id, in English and Spanish. **Add an entry here for every new rule or probe** |
| `assets/` | Geist fonts and the AVENZOQ mark used by the HTML report |
| `examples/` | Deliberately vulnerable MCP server and a mock agent that obeys anything. Both are fake and do nothing real |
| `test/` | `node:test` unit tests for the rules |
| `bench/` | `cases.mjs` (labeled corpus) and `run.mjs` (precision/recall/F1, `--llm`, `--write` → RESULTS.md). When you change rules, run `npm run bench` and keep F1 ≥ 85 % (enforced by `test/bench.test.mjs`). Add a benign near-miss for every new rule |
| `research/` | State of MCP Security kit: `Dockerfile` (locked-down runner), `run.mjs`, `aggregate.mjs` (public aggregate + private per-server table), methodology and disclosure template. `research/results/` is git-ignored: **never publish server names before disclosure** |
| `docs/` | Roadmap; `docs/assets/` holds the README banner, the animated terminal SVG and the report preview |
| `scripts/readme-assets.mjs` | Regenerates `banner.svg` and `terminal.svg`. Update the numbers in it when checks change |
| `.github/workflows/ci.yml` | Tests on Node 20/22/24, plus the demo scan |
| `SECURITY.md`, `CONTRIBUTING.md` | Policies for reporting issues and adding rules |
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
