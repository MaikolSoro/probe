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
- Vulnerable demo MCP server, mock agent and unit tests.

## Next (to make it useful for real users)

1. **Publish:** choose a license, create the GitHub repo, write a CONTRIBUTING file and set up a CI workflow that runs `npm test`.
2. **Config scan:** read the MCP config files of Claude Desktop, Cursor and VS Code (`mcpServers`) and scan every server listed, so one command audits a developer's whole setup.
3. **SARIF output** for GitHub code scanning. Results need a file location, so anchor them to the MCP config file or to the server's entry point.
4. **Multi-turn and tool-use probes:** support chat endpoints that take a message history, and agents that call tools. Detect whether an injected instruction leads to a tool call, not just to a canary echo.
5. **Rug-pull detection:** save a hash of each server's tool definitions and warn when they change between scans.
6. **Probe pack in Spanish and Portuguese**, for the Latin American market and as a differentiator.
7. **Reduce false positives:** an allowlist or suppression file (`.probeignore`) and per-rule severity overrides.

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
