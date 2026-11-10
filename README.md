<p align="center">
  <img src="docs/assets/banner.svg" alt="AVENZOQ Probe: red-team your AI agents, MCP servers and skills before attackers do" width="100%">
</p>

<p align="center">
  <a href="#quick-start"><img alt="Node 20+" src="https://img.shields.io/badge/node-%E2%89%A520-5eead4?style=flat-square&labelColor=0b0d10"></a>
  <a href="#what-it-checks"><img alt="OWASP LLM Top 10 2025" src="https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-f47bff?style=flat-square&labelColor=0b0d10"></a>
  <a href="#mcp-servers"><img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20%7C%20HTTP-a98bff?style=flat-square&labelColor=0b0d10"></a>
  <a href="#use-it-in-ci"><img alt="CI ready" src="https://img.shields.io/badge/CI-exit%201%20on%20critical-ff4d6d?style=flat-square&labelColor=0b0d10"></a>
  <a href="LICENSE"><img alt="License Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-c9cdd3?style=flat-square&labelColor=0b0d10"></a>
  <a href="https://www.npmjs.com/package/@avenzoq/probe"><img alt="npm" src="https://img.shields.io/npm/v/@avenzoq/probe?style=flat-square&labelColor=0b0d10&color=8247ff"></a>
  <a href="#client-ready-reports"><img alt="Reports" src="https://img.shields.io/badge/reports-md%20%C2%B7%20json%20%C2%B7%20html%20%C2%B7%20pdf-ff8a3d?style=flat-square&labelColor=0b0d10"></a>
</p>

# AVENZOQ Probe

> **Your agent obeys whatever it reads.** A poisoned tool description, a review with hidden instructions, a skill that says *"don't tell the user"*: one piece of text is enough to make an agent leak data or misuse its tools.
>
> **Probe finds those problems before an attacker does.** It scans **MCP servers**, **AI chat agents**, the **MCP configs** of Claude, Cursor, VS Code and Windsurf, and **agent skills** before you install them. Every finding is mapped to the **OWASP LLM Top 10 (2025)**, and Probe can turn the results into a **client-ready PDF in English or Spanish**.

Built by [AVENZOQ](https://avenzoq.com): software, AI automation and offensive security.

<p align="center">
  <img src="docs/assets/terminal.svg" alt="Probe scanning a vulnerable MCP server" width="100%">
</p>

---

## Why this exists

Agents went from *answering* to *acting*: they read email, browse, query databases, move money and call tools through the [Model Context Protocol](https://modelcontextprotocol.io). Each of those inputs can carry instructions, and each tool is something an attacker can trigger.

Most tooling filters what the **user** types. Probe looks at what the **agent can do** and at **what it reads**:

| The risk | Where it hides | Probe mode |
|---|---|---|
| **Tool poisoning:** instructions inside tool descriptions | Third-party MCP servers | `probe mcp` |
| **Indirect prompt injection** through tool output | Reviews, emails, web pages a tool returns | `probe mcp --call-readonly` |
| **Excessive agency:** shell, delete, payments, outbound email | Tool design | `probe mcp` |
| **Exfiltration paths:** private data + an outbound channel | One server exposing both | `probe mcp` |
| **The agent obeys injected text, or uses its tools for the attacker** | Your chatbot, agent endpoint or a model API | `probe agent` |
| **Rug pulls:** a server changes its tools after you approved it | Any MCP server | `probe mcp --pin` |
| **Leaked secrets and unpinned servers** | `claude_desktop_config.json`, `.mcp.json`, `mcp.json` | `probe config` |
| **Malicious skills, hooks and installers** | `SKILL.md`, slash commands, `CLAUDE.md`, install scripts | `probe skills` |

## Quick start

No install needed:

```bash
npx @avenzoq/probe config                       # audit every MCP server you have configured
```

Or install it once and use the `probe` command:

```bash
npm install -g @avenzoq/probe

probe config                                    # audit every MCP server you have configured
probe mcp -- npx -y some-mcp-server@1.2.3       # scan one MCP server (stdio)
probe mcp --url https://example.com/mcp         # scan a remote MCP server (Streamable HTTP)
probe agent --url https://example.com/chat      # throw 32 attack probes at an agent
probe skills ./some-skill-pack                  # review skills before installing them
probe docs ./knowledge-base                     # find hidden instructions in PDFs, Office files, HTML
probe serve                                     # run Probe as an MCP server for your AI client
```

<details>
<summary>From source</summary>

```bash
git clone https://github.com/MaikolSoro/probe.git
cd probe && npm install
npm link            # or: ln -s "$PWD/src/cli.mjs" ~/.local/bin/probe   (if npm link needs root)
```
</details>

Try it on the bundled, deliberately vulnerable demos:

```bash
npm run demo:mcp                        # 8 critical · 2 high · 2 medium · 3 low
node examples/mock-agent.mjs &          # a fake agent that obeys anything
npm run demo:agent                      # 26 of 29 probes succeed

# Against a real model: a small support bot backed by the Claude API
ANTHROPIC_API_KEY=… node examples/claude-agent.mjs &
probe agent --url http://localhost:8788/chat
```

> [!IMPORTANT]
> Only scan systems you own or are authorized to test. `probe config` starts the servers listed in your configs, the same way your AI client does; use `--no-connect` to only read the config files.

## What it checks

### MCP servers

**Static checks.** No tool is called.

| Check | Severity | OWASP |
|---|---|---|
| Hidden instructions in tool descriptions (`<IMPORTANT>`, "ignore previous", "don't tell the user", secret paths) | critical | LLM01 Prompt Injection |
| Invisible Unicode characters in tool metadata | high | LLM01 |
| Tools that execute code, delete data or move money | high | LLM06 Excessive Agency |
| Private data and an outbound channel on the same server | high | LLM02 Sensitive Information Disclosure |
| Outbound communication tools | medium | LLM06 |
| Tools marked read-only that change state | medium | LLM06 |
| High-impact tools without `destructiveHint` | low | LLM06 |
| Free-form `path`, `url`, `command`, `query` parameters | low | LLM06 |
| Descriptions that steer the agent ("always use this tool", "call this immediately after") | low (informational) | LLM01 |

**Output check** (opt-in, `--call-readonly`). Probe calls only tools that declare `readOnlyHint: true` and take no arguments. It then scans what they return for planted instructions (indirect prompt injection, critical).

### AI agents

`probe agent` runs **32 attack probes** in 7 categories. Each one carries a random canary: if the canary comes back, or a fake tool gets called with the attacker's data, the agent obeyed untrusted input.

> [!WARNING]
> `probe agent` sends real attacks to a live target. Only run it against a chatbot or agent you **own** or have **written authorization** to test. It asks you to confirm, and refuses to run non-interactively unless you pass `--yes`. If the endpoint rejects every request (wrong URL, auth, or bot protection), the result is **INCONCLUSIVE** — that does not mean the target is secure.

| Category | Probes | Technique |
|---|---|---|
| `direct` | 8 | Overrides in English, Spanish and Portuguese; fake admin notice; developer mode; role-play; refusal suppression; forced prefix |
| `indirect` | 9 | Instructions hidden in an email, document, web page, JSON, CSV, code comment or review; fake delimiters; fake transcripts |
| `obfuscation` | 5 | Base64, ROT13, payload splitting, zero-width characters, translation smuggling |
| `exfiltration` | 2 | Data smuggled out through markdown images and links |
| `leak` | 3 | System prompt extraction: repeat, translate or summarize the hidden instructions |
| `multi-turn` | 2 | Gradual (crescendo) manipulation and instructions planted early in the chat |
| `tool-use` | 3 | Injected text makes the agent **send an email to the attacker, read SSH keys or transfer money** using fake tools that never run |

**Targets:**

```bash
# Your agent, behind any JSON endpoint
probe agent --url https://my-bot.com/chat                                   # {"message"} → {"reply"}
probe agent --url https://my-bot.com/chat --history-field messages          # enables multi-turn probes

# A model API directly, with your system prompt
probe agent --target openai --model gpt-4.1-mini --system @prompt.txt      # OPENAI_API_KEY
probe agent --target anthropic --model claude-haiku-5-5 --system @prompt.txt  # ANTHROPIC_API_KEY
probe agent --target openai --url http://localhost:11434/v1/chat/completions --model llama3   # Ollama or any OpenAI-compatible API
```

Tool-use probes need `--target openai` or `--target anthropic`. Multi-turn probes need one of those or `--history-field`. Select categories with `--categories direct,tool-use`.

### MCP client configs

`probe config` finds the MCP configs of **Claude Desktop, Claude Code, Cursor, VS Code and Windsurf**. It flags:
- secrets stored in plain text;
- `npx` or `uvx` servers without a pinned version (rug-pull risk);
- remote servers over plain HTTP.

It then runs the MCP checks on every server it can start. `--path <file>` scans a specific config file.

**Toxic flows across servers.** Each server can look harmless alone, but your agent combines all of them. If one server reads private data (files, CRM, inbox) and *another* can send data out (email, HTTP, chat), Probe reports a `cross-server-flow` (medium). When a third tool also reads content written by strangers (web pages, email, issues, reviews), that is the full "untrusted input + private data + way out" combination an injected instruction needs, and it is reported as high.

### Agent skills

`probe skills <path>` reviews skill packs, slash commands, `CLAUDE.md` / `AGENTS.md`, Cursor rules, hook configs and install scripts. It looks for:
- text aimed **at the agent** (hide from the user, send local secrets out);
- invisible characters and encoded blobs;
- `curl | bash` and writes to shell profiles or SSH keys;
- auto-running hooks, unrestricted `Bash` pre-approval and MCP installs.

It also lists every external domain the files reference.

Offensive-security skill packs legitimately *describe* attacks. Probe's rules target instructions to **your** agent, not attack vocabulary, and lower the severity of commands that only appear in docs or comments.

### Documents an AI will read (`probe docs`)

Before a PDF, a Word file or a web page goes into your knowledge base, RAG pipeline or assistant, check it for instructions hidden from people:

```bash
probe docs ./supplier-docs                     # a folder: PDF, DOCX, PPTX, XLSX, HTML, Markdown, TXT, CSV
probe docs quote.pdf --html --lang es          # one file, with the client-ready report
```

It reads the files as data (no external tools, nothing executed) and reports:
- **hidden instructions** (critical): text aimed at the model in white or tiny text, invisible PDF text, Word hidden formatting, hidden slides, CSS-hidden HTML, comments, speaker notes, metadata, or **Unicode tag characters** ("ASCII smuggling"), which are decoded;
- **visible instructions** (high): document text that talks to the model. A document *about* prompt injection will trigger this on purpose; suppress it with `.probeignore`;
- **hidden text** without instructions (low), invisible characters (medium), and anything Probe **could not read** (a scanned page, an unusual font encoding), so an unreadable file is never reported as clean.

PDF text is decoded with each font's Unicode map and glyph widths, so PDFs from Chrome, Word and most generators read correctly. White text and invisible OCR layers alone are normal in real documents and are only reported when they carry instructions. On a test set of 117 real downloaded files (designs, invoices, Office files) it reported nothing; on 145 Markdown/HTML files from `node_modules`, nothing either.

### Probe as an MCP server (`probe serve`)

Let your AI assistant scan things for you. `probe serve` runs Probe itself as a stdio MCP server, so from Claude, Cursor or VS Code you can say *"check this MCP server before I install it"* and the assistant runs the scan. It exposes four **read-only** tools:

- `scan_mcp_server` — analyse an MCP server's tool definitions (`url`, or `command` + `args`);
- `scan_mcp_config` — audit your local MCP client configs (static by default; `connect: true` starts the servers);
- `scan_skills` — review a skills/instructions folder;
- `scan_documents` — check documents for hidden instructions before the assistant reads them.

`probe agent` is **not** exposed: it actively attacks a live target, so an assistant must never be able to launch it at a third party. Add it to your client's MCP config:

```json
{ "mcpServers": { "probe": { "command": "npx", "args": ["-y", "@avenzoq/probe", "serve"] } } }
```

### LLM judge (`--llm`)

Patterns are fast but miss reworded attacks and sometimes flag harmless text. With `--llm`, Claude reviews every tool description, tool output and flagged skill excerpt:
- **confirms** real findings;
- **dismisses** false positives, lowering them to `low` with the reason (never hiding them);
- **adds** findings the patterns missed.

```bash
export ANTHROPIC_API_KEY=…
probe mcp --llm -- node server.js
probe skills ./skill-pack --llm --llm-model claude-haiku-5-5
```

The content under review is untrusted, so it is fenced with a random boundary and the judge is told to classify it, never to follow it.

### Rug-pull detection (`--pin`)

A server can be safe when you approve it and turn malicious in an update. `--pin` saves a fingerprint of every tool the first time (trust on first use). Later scans report:
- changed tools (**high**);
- new tools (**medium**);
- removed tools (**low**).

```bash
probe mcp --pin probe.pins.json -- npx -y some-mcp-server     # first run pins, later runs compare
probe config --pin probe.pins.json                             # pin every configured server
probe mcp --pin probe.pins.json --update-pins -- …             # accept a reviewed change
```

Commit the pin file so CI catches changes.

## Client-ready reports

Every finding is mapped to the **OWASP Top 10 for LLM Applications (2025)**, the **OWASP Top 10 for Agentic Applications (2026)** and **MITRE ATLAS** techniques, in the Markdown and HTML/PDF reports and as SARIF tags (`ASI01`, `AML.T0051.001`…). That turns a scan into evidence for an AI-security or compliance review. The mapping is indicative; check it against the current version of each framework before using it in an audit.

```bash
probe mcp --pdf --lang es --client "Cliente S.A." --out reports/cliente -- node server.js
```

<p align="center"><img src="docs/assets/report-preview.png" alt="Probe PDF report" width="720"></p>

| Option | Output |
|---|---|
| `--out <dir>` | `report.md` + `report.json` |
| `--html` | A self-contained `report.html` (fonts and logo embedded) |
| `--pdf` | `report.pdf` via headless Chrome or Chromium (`CHROME_PATH` if needed) |
| `--lang en\|es` | Report language |
| `--client <name>` | Name on the cover |

Each report opens with the overall risk and an **executive summary for decision makers** — the single most important risk, a rough remediation effort and the recommended next step — then the scope and method, and every issue with **what it means** and **how to fix it** in plain language.

### Before/after (`probe diff`)

Run two scans with `--out` and compare their `report.json` to show what a fix changed:

```bash
probe mcp --out before -- node server.js      # scan, then fix the issues
probe mcp --out after  -- node server.js       # scan again
probe diff before/report.json after/report.json   # resolved / new / still present
```

Exit code 1 if a **new** finding appears at or above `--fail-on`. Add `--out <dir>` to also write `diff.md`.

### Authorization document (`probe authorization`)

Start every engagement with written permission. `probe authorization` prints the document a client signs — scope, out-of-scope, testing window, terms and signatures — in Spanish or English:

```bash
probe authorization --client "Cliente S.A." --authby "Jane Doe" --role CTO \
  --scope "https://api.client.com/chat, inventory MCP server" --exclude "production" \
  --start 2026-11-10 --end 2026-11-14 --pdf --out ./engagement
```

Fields you leave out stay as blanks to fill in. It is a template, not legal advice — have a lawyer review it.

## Use it in CI

### GitHub Action

```yaml
# .github/workflows/probe.yml
name: Probe
on: [pull_request, push]
permissions:
  contents: read
  security-events: write        # to upload SARIF to the Security tab
jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - uses: MaikolSoro/probe@v0.3.0
        with:
          args: mcp -- node ./server.js     # or: skills ./skills · config --path .mcp.json --no-connect
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: probe.sarif }
```

Findings show up in **Security → Code scanning**, with severity, the OWASP category and how to fix each one.

### Any CI

```bash
npx @avenzoq/probe mcp --fail-on high --sarif probe.sarif --out probe-report -- node ./server.js
```

| Option | What it does |
|---|---|
| `--fail-on <level>` | Exit `1` at or above `critical`, `high` (default), `medium` or `low`; `none` never fails |
| `--sarif <file>` | SARIF 2.1.0 for GitHub code scanning or any SARIF viewer |
| `--ignore <file>` | Suppressions file; `./.probeignore` is used automatically if present |

Exit codes: `0` below the threshold, `1` at or above it, `2` on usage or connection errors.

### Suppressing findings

Some findings are expected, for example a tool that really must send email. List them in `.probeignore`:

```gitignore
# <rule-id> [where]   (both accept * wildcards)
capability-outbound send_email        # sends only to allowlisted domains, with approval
skill-pipe-to-shell docs/*            # install instructions for humans
config-unpinned-package *
```

Suppressed findings are counted in the summary, so nothing disappears silently.

## Accuracy

Probe ships with a labeled benchmark (`bench/`): 42 malicious and tricky-benign tool descriptions and skill files. Some benign cases are deliberately hard, for example security documentation that quotes attack text.

| Mode | Precision | Recall | F1 |
|---|---|---|---|
| Pattern rules only | 90% | 90% | 90% |
| + LLM judge (`--llm`) | run `npm run bench -- --llm` | | |

The remaining pattern misses are **paraphrased** attacks, and the false positives are **docs that quote attacks**. Telling those apart is the LLM judge's job. The corpus was used while developing the rules, so treat these as optimistic numbers; see [bench/RESULTS.md](bench/RESULTS.md).

## Research

`research/` contains the kit for the **State of MCP Security** study:
- public MCP servers are scanned inside a locked-down container;
- no tool is ever called;
- results are published as aggregates only after responsible disclosure to maintainers.

See [research/README.md](research/README.md).

## How it works

```
             ┌──────────────┐   list tools    ┌────────────────────┐
 probe mcp ─▶│  MCP client  │────────────────▶│  your MCP server   │
             └──────┬───────┘  (read-only     └────────────────────┘
                    │           calls opt-in)
                    ▼
             ┌──────────────┐    ┌────────────┐    ┌──────────────────────┐
             │ rules.mjs    │───▶│ findings   │───▶│ terminal · md · json │
             │ OWASP-mapped │    │ + guidance │    │ html · pdf (es/en)   │
             └──────────────┘    └────────────┘    └──────────────────────┘
```

Everything is plain Node.js ESM, with no build step. The only dependencies are the official MCP SDK and zod.

## Limits

- The checks are **pattern-based**. They catch known poisoning techniques and risky designs, not every possible attack. Expect some false positives on legitimate tools that really send email or run commands.
- Agent probes test one conversation at a time. Tool-use probes use fake tools and report the *attempt*; they never execute anything.
- `probe docs` reads text, not pixels: text drawn as an image, or hidden by covering it with a shape, is not detected. Text placed off the page in a PDF and hidden worksheets in Excel are not checked yet.
- The LLM judge is itself an LLM. It reduces noise but can be wrong, so review its reasoning in the report.
- **A clean report is not a guarantee.** It means none of these checks found a problem.

## Roadmap

- [x] Multi-turn and tool-use probes, OpenAI and Anthropic targets
- [x] Rug-pull detection (`--pin`)
- [x] SARIF output and GitHub Action
- [x] `.probeignore` and `--fail-on`
- [x] LLM judge (`--llm`)
- [x] Public benchmark (`bench/`)
- [x] Hidden instructions in documents (`probe docs`)
- [x] Toxic flows across MCP servers
- [x] OWASP Agentic Top 10 and MITRE ATLAS mapping
- [ ] "State of MCP Security" report (kit ready in `research/`)
- [ ] **Guard:** a runtime policy firewall between agents and their tools

See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

[Apache-2.0](LICENSE). The bundled Geist fonts are under the [SIL Open Font License 1.1](assets/OFL.txt). The AVENZOQ name and logo are trademarks and are not covered by the license (see [NOTICE](NOTICE)).

## Contributing and security

Ideas, rules and probes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). If you find a vulnerability **in Probe itself**, please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

---

<p align="center">
  <b>AVENZOQ</b> · Software, AI and offensive security · <a href="https://avenzoq.com">avenzoq.com</a> · <a href="mailto:info@avenzoq.com">info@avenzoq.com</a><br>
  <sub>Need an AI-security audit of your agents? We use Probe and manual testing to find what automated tools miss.</sub>
</p>
