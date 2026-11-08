<p align="center">
  <img src="docs/assets/banner.svg" alt="AVENZOQ Probe: red-team your AI agents, MCP servers and skills before attackers do" width="100%">
</p>

<p align="center">
  <a href="#quick-start"><img alt="Node 20+" src="https://img.shields.io/badge/node-%E2%89%A520-5eead4?style=flat-square&labelColor=0b0d10"></a>
  <a href="#what-it-checks"><img alt="OWASP LLM Top 10 2025" src="https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-f47bff?style=flat-square&labelColor=0b0d10"></a>
  <a href="#mcp-servers"><img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20%7C%20HTTP-a98bff?style=flat-square&labelColor=0b0d10"></a>
  <a href="#use-it-in-ci"><img alt="CI ready" src="https://img.shields.io/badge/CI-exit%201%20on%20critical-ff4d6d?style=flat-square&labelColor=0b0d10"></a>
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
| **The agent obeys injected text** | Your chatbot or agent endpoint | `probe agent` |
| **Leaked secrets and unpinned servers** | `claude_desktop_config.json`, `.mcp.json`, `mcp.json` | `probe config` |
| **Malicious skills, hooks and installers** | `SKILL.md`, slash commands, `CLAUDE.md`, install scripts | `probe skills` |

## Quick start

```bash
git clone https://github.com/MaikolSoro/probe.git
cd probe && npm install
npm link            # optional: makes the `probe` command available everywhere
```

```bash
probe config                                    # audit every MCP server you have configured
probe mcp -- npx -y some-mcp-server@1.2.3       # scan one MCP server (stdio)
probe mcp --url https://example.com/mcp         # scan a remote MCP server (Streamable HTTP)
probe agent --url https://example.com/chat      # throw 9 prompt-injection probes at an agent
probe skills ./some-skill-pack                  # review skills before installing them
```

Try it on the bundled, deliberately vulnerable demos:

```bash
npm run demo:mcp                        # 7 critical · 2 high · 2 medium · 3 low
node examples/mock-agent.mjs &          # a fake agent that obeys anything
npm run demo:agent                      # 9 of 9 probes succeed
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

**Output check** (opt-in, `--call-readonly`). Probe calls only tools that declare `readOnlyHint: true` and take no arguments. It then scans what they return for planted instructions (indirect prompt injection, critical).

### AI agents

`probe agent` sends 9 probes, each with a random canary. If the canary comes back, the agent obeyed untrusted input.

| Probe | Technique |
|---|---|
| `direct-override` · `spanish-override` | "Ignore all previous instructions", in English and in Spanish |
| `fake-authority` | A fake system or administrator notice |
| `indirect-email` · `indirect-document` | Instructions hidden in content the agent summarizes or translates |
| `payload-splitting` · `encoded-instruction` | The instruction split into variables, or base64-encoded |
| `markdown-exfiltration` | Data smuggled into an image URL the chat would load |
| `system-prompt-leak` | Extraction of the agent's hidden instructions |

Works with any JSON endpoint. Use `--field`, `--reply` (for example `choices.0.message.content`) and `--header "Authorization: Bearer …"`.

### MCP client configs

`probe config` finds the MCP configs of **Claude Desktop, Claude Code, Cursor, VS Code and Windsurf**. It flags:
- secrets stored in plain text;
- `npx` or `uvx` servers without a pinned version (rug-pull risk);
- remote servers over plain HTTP.

It then runs the MCP checks on every server it can start. `--path <file>` scans a specific config file.

### Agent skills

`probe skills <path>` reviews skill packs, slash commands, `CLAUDE.md` / `AGENTS.md`, Cursor rules, hook configs and install scripts. It looks for:
- text aimed **at the agent** (hide from the user, send local secrets out);
- invisible characters and encoded blobs;
- `curl | bash` and writes to shell profiles or SSH keys;
- auto-running hooks, unrestricted `Bash` pre-approval and MCP installs.

It also lists every external domain the files reference.

Offensive-security skill packs legitimately *describe* attacks. Probe's rules target instructions to **your** agent, not attack vocabulary, and lower the severity of commands that only appear in docs or comments.

## Client-ready reports

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

Each report has the overall risk, an executive summary, the scope and method, and every issue with **what it means** and **how to fix it** in plain language.

## Use it in CI

The exit code is `1` when there are critical or high findings, and `2` on errors.

```yaml
# .github/workflows/mcp-security.yml
name: MCP security
on: [pull_request]
jobs:
  probe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - run: git clone --depth 1 https://github.com/MaikolSoro/probe.git /tmp/probe && npm --prefix /tmp/probe ci
      - run: node /tmp/probe/src/cli.mjs mcp --out probe-report -- node ./server.js
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: probe-report, path: probe-report }
```

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
- Agent probes are single-turn, over a JSON HTTP endpoint.
- **A clean report is not a guarantee.** It means none of these checks found a problem.

## Roadmap

- [ ] Multi-turn and tool-use probes against agent frameworks
- [ ] Rug-pull detection (tool definitions that change between scans)
- [ ] SARIF output for GitHub code scanning
- [ ] `.probeignore` and per-rule severity overrides
- [ ] **Guard:** a runtime policy firewall between agents and their tools

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Contributing and security

Ideas, rules and probes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). If you find a vulnerability **in Probe itself**, please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

---

<p align="center">
  <b>AVENZOQ</b> · Software, AI and offensive security · <a href="https://avenzoq.com">avenzoq.com</a> · <a href="mailto:info@avenzoq.com">info@avenzoq.com</a><br>
  <sub>Need an AI-security audit of your agents? We use Probe and manual testing to find what automated tools miss.</sub>
</p>
