# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org).

## [0.4.0] - 2026-11-08

### Added
- **LLM judge** (`--llm`, `--llm-model`) for `mcp`, `config` and `skills`. Claude confirms, dismisses (lowers, never hides) or adds injection findings. The untrusted content is fenced so it cannot instruct the judge.
- **Rug-pull detection** (`--pin <file>`, `--update-pins`). Tool fingerprints are pinned on first scan; later scans report changed, new and removed tools.
- **32 agent probes** (up from 9) in 7 categories, including multi-turn conversations and tool-use attacks with fake `send_email`, `read_file` and `transfer_money` tools.
- **Model API targets** for `probe agent`: `--target openai` (any OpenAI-compatible API) and `--target anthropic`, with `--model`, `--system` and `--categories`; `--history-field` for multi-turn on JSON endpoints.

## [0.3.0] - 2026-11-08

### Added
- SARIF 2.1.0 output (`--sarif <file>`, `--sarif-uri`). Findings appear in GitHub code scanning with severity scores and file locations.
- `--fail-on <critical|high|medium|low|none>` sets the severity that makes the run exit with `1`. The default is `high`.
- `.probeignore` suppressions (`<rule-id> [where]`, with `*` wildcards and `#` comments), or a custom file with `--ignore <file>`.
- A GitHub Action (`action.yml`): `uses: MaikolSoro/probe@v0.3.0`.
- `--version`.
- Apache-2.0 license, NOTICE, and the SIL OFL license for the bundled Geist fonts.
- Published to npm as `@avenzoq/probe`, with the `probe` and `avenzoq-probe` commands.

## [0.2.0] - 2026-11-07

### Added
- `probe config` audits the MCP servers configured in Claude Desktop, Claude Code, Cursor, VS Code and Windsurf. It flags plain-text secrets, unpinned packages and plain-HTTP remotes, then scans each server.
- `probe skills` reviews skills, slash commands, CLAUDE.md/AGENTS.md, hooks and install scripts before installation. It was tuned on Claude-BugHunter so that attack *descriptions* are not flagged.
- Per-call timeout, so a hung server cannot block a scan.
- A README with a banner, an animated terminal and a report preview; SECURITY.md and CONTRIBUTING.md.

## [0.1.0] - 2026-11-07

### Added
- MCP static rules: tool poisoning, invisible characters, excessive agency, false read-only claims, unconstrained parameters and exfiltration paths.
- An opt-in output check of read-only tools (`--call-readonly`).
- Nine canary prompt-injection probes for chat agents.
- Markdown, JSON and client-ready HTML/PDF reports in English and Spanish.
