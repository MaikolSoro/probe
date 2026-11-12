# Probe roadmap

## Done (v0.1.0, 2026-11-07)

- MCP scan over stdio and Streamable HTTP; static rules for:
  - tool poisoning;
  - invisible characters;
  - code execution, destructive and financial tools;
  - outbound channels;
  - false read-only claims and missing annotations;
  - unconstrained parameters;
  - the exfiltration path (private data + outbound channel on the same server).
- Opt-in output check (`--call-readonly`) for indirect injection planted in read-only tool output.
- Agent scan: 9 canary probes over a JSON HTTP endpoint, with a configurable message field, reply path and headers.
- Markdown and JSON reports; CI-friendly exit codes.
- Client-ready HTML/PDF report (`--html`, `--pdf`, `--lang es|en`, `--client`), with an executive summary, grouped issues and fixes in plain language. Used to deliver AVENZOQ AI-security audits.
- Vulnerable demo MCP server, mock agent and unit tests.

## Done (v0.2.0, 2026-11-07)

- `probe config`: audits the MCP configs of Claude Desktop, Claude Code, Cursor, VS Code and Windsurf. It checks for plain-text secrets, unpinned `npx`/`uvx` packages and plain-HTTP remotes, then scans every server.
- `probe skills`: reviews skills, slash commands, CLAUDE.md/AGENTS.md, hooks and install scripts before install.
  - Validated on Claude-BugHunter (266 files, 83 skills). The first pass flagged attack *descriptions* as critical. After tuning, only low findings remain, all of them install docs or payload examples.
- Per-call timeout, so a hung server cannot block a scan.
- README with banner, animated terminal SVG and report preview; SECURITY, CONTRIBUTING and CI workflow.

## Done (v0.3.0, 2026-11-08): Sprint 1, launch-ready

- Apache-2.0 license, NOTICE and font license; CHANGELOG; npm package `@avenzoq/probe`.
- SARIF output, `--fail-on`, `.probeignore`, `--version`.
- GitHub Action (`action.yml`), tested locally by running its script.

## Done (v0.4.0, 2026-11-08): Sprint 2, technical differentiation

- LLM judge (`--llm`) for MCP, config and skills.
- Rug-pull detection (`--pin`, `--update-pins`).
- 32 agent probes; multi-turn; tool-use with fake tools; OpenAI and Anthropic targets; `--history-field`, `--categories`.

## Done (v0.5.0, 2026-11-08): Sprint 3, credibility (part 1)

- Benchmark corpus and runner; stronger rules; pattern F1 went from 68 % to 90 % on the development set.
- Research kit for State of MCP Security (isolated runner, aggregation, disclosure policy).

## Done (v0.6.3, 2026-11-07): responsible use

- Authorization gate on `probe agent` (confirm, or `--yes` for CI); non-interactive runs refuse without it.
- INCONCLUSIVE result (exit 2) when every probe fails, so an unreachable target no longer reads as clean.

## Done (v0.7.0, 2026-11-07): reach and sales

- `probe serve`: Probe as a stdio MCP server, so an AI client can run the read-only scans itself (`scan_mcp_server`, `scan_mcp_config`, `scan_skills`). The active `agent` attack is intentionally not exposed.
- Executive-summary block at the top of the client report (top risk, estimated effort, next step; es/en).

## Done (v0.8.0, 2026-11-08): selling the audits

- `probe diff <before.json> <after.json>`: resolved / new / still-present, with before/after counts — proof of value for a client.
- `probe authorization`: the signable "authorization to test" document (es/en), Markdown + branded HTML/PDF. A template, not legal advice.

## Done (v0.9.0, 2026-11-10): documents, toxic flows, compliance

- `probe docs`: hidden instructions in PDF, Office, HTML, Markdown and text files (white/tiny/invisible text, hidden formatting and slides, CSS, comments, metadata, Unicode tag characters). Zero false positives on 117 real downloaded files and 145 `node_modules` docs.
- Toxic flows across MCP servers in `probe config` (`cross-server-flow`).
- OWASP Agentic Top 10 (2026) and MITRE ATLAS mapping in reports and SARIF.

## Next (to make it useful for real users)

> **Note (2026-11-10): features are paused; adoption comes first.** Probe already has more features than real users. The agreed order when work resumes:
> 1. Publish 0.9.1 to npm (the founder runs `npm login` + `npm publish`; npm still has 0.6.2).
> 2. Spanish/Portuguese injection patterns (item 4 below): small, closes a known gap in `probe docs`, and differentiates in Latin America.
> 3. Publish the State of MCP Security study. It already ran on 2026-11-08 (80 targets, 39 started, 406 tools, 0 criticals) and the branded report is in `research/report/` (git-ignored); only disclosure and the owner's go-ahead remain. Gives content, credibility for selling audits, and real cases to tune the rules.
>
> Everything else (tripartite authorization, hidden Excel sheets, text in images) waits until a client or user asks for it.
>
> **Language and architecture (reviewed 2026-11-12):** plain Node ESM stays. The work is I/O-bound (starting servers, waiting on models), the MCP ecosystem is TypeScript/Python-first, distribution via `npx` matches how MCP servers are installed, and a memory-safe language matters for parsing hostile documents. If a client needs "no Node", package Probe as a single executable or a Docker image instead of rewriting it in Go. Internal improvements, **done on 2026-11-12** (findings unchanged on the bench, the research corpus, ~/Downloads and the workspace):
> - **Type checking without a build step:** JSDoc types plus `checkJs` in `jsconfig.json`, `npm run typecheck` (dev-only TypeScript). Not yet in CI: `.github/` is not pushed (token lacks the workflow scope).
> - **Split `docs-scan.mjs`** (826 lines) into `src/docs/pdf.mjs`, `ooxml.mjs`, `html.mjs` and `shared.mjs`; `checkSegments` stays in `docs-scan.mjs`.
> - **Rules as data:** injection patterns live in `src/rules/en.mjs`, `es.mjs`, `pt.mjs`. The Spanish/Portuguese pack (step 2 above) now only adds data there. Still in code: the skills rules in `skills-scan.mjs` (English only), to move when that pack is written.
> - **CLI parsing:** `cli.mjs` uses the built-in `node:util` `parseArgs`; unknown options are now an error.

1. **Run the State of MCP Security study:** start Docker, run `research/run.mjs`, review the criticals by hand, disclose, then publish the aggregate report.
2. **Held-out benchmark:** new cases written without looking at the rules, plus an LLM-judge column.
3. **LLM judge for agent replies:** classify partial leaks and soft compliance that canaries miss.
4. **Probe pack in Spanish and Portuguese**, for the Latin American market and as a differentiator. The static rules recognize English instructions plus a few Spanish/Portuguese phrases; `probe docs` found a Spanish "ignora todas las instrucciones anteriores" only through another phrase in the same text. Adding Spanish/Portuguese injection patterns (with benign near-misses in `bench/`) also strengthens `probe docs`.
5. **`probe docs` follow-ups:** text placed off the page in PDFs, hidden Excel sheets and white-font cells, `.eml` email files, and an `--llm` pass over document text (`extractDocument` is exported for it).
6. **AI inventory (`probe inventory`)**, remote MCP checks (unauthenticated access, CORS, `0.0.0.0`), MCP package supply chain, tripartite `probe authorization` (vendor as a signer).

## Later (product)

- **Guard:** a runtime policy layer, either a proxy MCP server or an SDK middleware, that sits between the agent and its tools. It would:
  - enforce rules ("never send customer data outside", "payments over X need human approval");
  - block risky calls;
  - log every action.
- **Compliance:** turn scan results and Guard logs into evidence for OWASP LLM Top 10, ISO/IEC 42001 and the EU AI Act.
- **Hosted dashboard:** scan history, teams and alerts. This is the SaaS part.

## Research track (credibility)

- Scan popular open-source MCP servers and agents. Report real issues privately to the maintainers (responsible disclosure) before writing about them.
- Publish write-ups and short videos. The `instagram/virales/08-*` script, "three AIs working together", is the marketing angle.
