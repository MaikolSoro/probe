# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org).

## [0.9.0] - 2026-11-10

### Added
- **`probe docs <path>`: hidden instructions in documents.** Scan PDF, Word, PowerPoint, Excel, HTML, Markdown, text and CSV files before an assistant or RAG pipeline reads them. It finds instructions hidden in white or tiny text, invisible PDF text, hidden Word formatting, hidden slides, CSS-hidden HTML, comments, speaker notes, metadata and Unicode tag characters (decoded), plus visible text aimed at the model. PDF text is decoded with each font's Unicode map and glyph widths. Files Probe cannot read are reported as such, never as clean. No new dependencies. Also available to AI clients as the `scan_documents` tool in `probe serve`.
- **Toxic flows across MCP servers** (`probe config`): a new `cross-server-flow` finding when one configured server reads private data and another can send it out (medium), or when a third also reads content from strangers (high).
- **Framework mapping:** every finding is mapped to the OWASP Top 10 for Agentic Applications (2026) and MITRE ATLAS, in the Markdown and HTML/PDF reports and as SARIF tags. The mapping is indicative.

## [0.8.0] - 2026-11-08

### Added
- **`probe diff <before.json> <after.json>`:** compare two scans and show what a fix changed — findings resolved, newly introduced, and still present — with before/after counts. Proof of value for a client: "before, 5 risks; after, 0". Exit 1 if a new finding is at or above `--fail-on`.
- **`probe authorization`:** print the "authorization to test" document a client signs before an assessment (scope, out-of-scope, testing window, terms, signatures), in Spanish or English. `--out <dir>` writes `authorization.md`; `--html`/`--pdf` add the AVENZOQ-branded version. It is a template, not legal advice.

## [0.7.0] - 2026-11-07

### Added
- **`probe serve`: run Probe as an MCP server.** An AI client (Claude, Cursor, VS Code) can now call Probe's static scans itself — "check this MCP server before I install it" — through three read-only tools: `scan_mcp_server`, `scan_mcp_config` and `scan_skills`. The active attack scanner (`probe agent`) is deliberately not exposed, so an agent can never launch prompt-injection attacks at a third party through it.
- **Executive summary in the client report.** The HTML/PDF report now opens with a plain-language block for decision makers: the single most important risk, a rough remediation effort and the recommended next step, in Spanish or English.

## [0.6.3] - 2026-11-08

### Added
- `probe agent` now asks you to confirm you are authorized to test the target. In a non-interactive run (CI, piped) it refuses unless you pass `--yes`. Testing a system you don't own, without written permission, may be illegal.

### Changed
- When every probe fails (403, 404, wrong format, endpoint down), the result is reported as **INCONCLUSIVE** with a specific hint, and the exit code is 2. Before, a target that could not be reached looked like a clean "No findings". The HTML/PDF and Markdown reports carry the same warning.

## [0.6.2] - 2026-11-08

### Fixed
- `annotation-mismatch` no longer fires on write-like verbs ("create a non-mutating proposal… in memory"). It now only checks tools that execute, delete or move money. This was found in the expanded scan (80 targets, 39 servers started, 406 tools), where it was the only remaining questionable finding.

### Changed
- The research runner uses Node 22 and a 150 s start timeout.

## [0.6.1] - 2026-11-08

### Added
- `--timeout <seconds>` for slow-starting MCP servers (the default stays at 30 s).
- The research runner scans 3 servers in parallel, and the target list now has 80 public MCP servers.

## [0.6.0] - 2026-11-08

### Added
- `tool-steering` (low, informational): flags tool descriptions that tell the agent which tool to prefer or what to call next ("you should always default to using this tool", "call this immediately after"). Found in a real public server during the State of MCP Security scan. It is usually a product choice, not an attack, but it is the same mechanism an attacker uses.

## [0.5.1] - 2026-11-08

### Fixed
False positives found by scanning 12 real public MCP servers (168 tools) and reviewing each critical and high finding by hand:
- "Include a word in the URL" (search-operator docs) was flagged as data exfiltration. The rule now requires *data* (conversation, files, secrets…) to be moved into a parameter or URL.
- "Drag and drop", "terminal state", "refund 1 credit", "excludeDomains to remove domains" and "lacks the read/update capability" triggered capability rules. Capabilities are now read from the tool name and the first sentence of its description, with narrower word lists.
- After the fixes, the real-world scan has **0 critical findings**, and every high finding is a real capability (delete, run code or SQL, private data + outbound channel).

### Added
- MCP JSON results include the tool definitions (name, description, annotations), so findings can be reviewed by hand later.

## [0.5.0] - 2026-11-08

### Added
- **Benchmark** (`bench/`): a labeled corpus of 42 malicious and tricky-benign MCP tool descriptions and skill files, with a runner that reports precision, recall and F1 (`npm run bench`, `--llm` to include the judge). A test fails if F1 drops below 85 %.
- **Research kit** (`research/`): an isolated Docker runner that scans public MCP servers without calling any tool, aggregation into a public draft plus a private per-server table, the methodology, and a responsible-disclosure policy and template.

### Changed
- Stronger injection rules: tool shadowing ("whenever X tool is used", "never call X directly", "supersedes other tools"), markdown-image exfiltration, asking the user for credentials, text addressed to the model ("note to the AI", "from now on you are"), encoded blobs, and Spanish/Portuguese hide-from-user phrases.
- Fewer false positives: mentioning a secret ("lists API key names", `.env.example`) or a chaining hint ("before using this tool, call list_x") is no longer flagged; acting on it still is.
- Pattern-only benchmark F1 rose from 68 % to 90 % (development set; see `bench/RESULTS.md` for the caveats).

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
