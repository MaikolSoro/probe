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

## Next (to make it useful for real users)

1. **Benchmark:** a corpus of known-good and known-bad MCP servers and skills, with Probe's measured precision and recall published.
2. **LLM judge for agent replies:** classify partial leaks and soft compliance that canaries miss.
3. **Probe pack in Spanish and Portuguese**, for the Latin American market and as a differentiator.

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
