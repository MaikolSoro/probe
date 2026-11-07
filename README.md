# AVENZOQ Probe

Security scanner for **MCP servers** and **AI agents**. It finds the problems that let a single piece of text take over an agent: poisoned tool descriptions, instructions planted in tool output, tools with too much power, data-exfiltration paths and prompt injection.

> Only scan systems you own or are authorized to test.

## What it checks

**MCP servers: static checks (no tool is called)**

| Check | Severity | OWASP LLM Top 10 (2025) |
|---|---|---|
| Hidden instructions in tool descriptions (tool poisoning) | critical | LLM01 Prompt Injection |
| Invisible Unicode characters in tool metadata | high | LLM01 |
| Tools that execute code, delete data or move money | high | LLM06 Excessive Agency |
| Private data and an outbound channel on the same server | high | LLM02 Sensitive Information Disclosure |
| Tools marked read-only that change state | medium | LLM06 |
| High-impact tools without a `destructiveHint` annotation | low | LLM06 |
| Free-form `path`, `url`, `command` or `query` parameters | low | LLM06 |

**MCP servers: output check (opt-in, `--call-readonly`)**

Probe calls only the tools that declare `readOnlyHint: true` and take no arguments. It then scans their output for planted instructions (indirect prompt injection, LLM01, critical).

**Chat agents (dynamic)**

There are nine probes, and each one carries a random canary:
- direct override, and the same override in Spanish;
- fake administrator authority;
- instructions hidden in an email or in a document;
- payload splitting;
- base64-encoded instructions;
- markdown-image exfiltration;
- system-prompt extraction.

If the canary comes back, the agent obeyed untrusted input.

## Quick start

Requires Node.js 20 or later.

```bash
npm install

# Scan a local MCP server
node src/cli.mjs mcp -- node path/to/server.js

# Also check the output of read-only tools
node src/cli.mjs mcp --call-readonly -- node path/to/server.js

# Scan a remote MCP server (Streamable HTTP)
node src/cli.mjs mcp --url https://example.com/mcp

# Probe a chat endpoint that takes {"message": "..."} and returns {"reply": "..."}
node src/cli.mjs agent --url https://example.com/chat

# OpenAI-style response shape and an auth header
node src/cli.mjs agent --url https://example.com/chat --reply choices.0.message.content --header "Authorization: Bearer $TOKEN"

# Write report.md and report.json
node src/cli.mjs mcp --out reports/my-server -- node server.js
```

The exit code is `1` when there are critical or high findings, and `2` on usage or connection errors. This lets Probe gate a CI pipeline.

## Demo

`examples/` contains a deliberately vulnerable MCP server and a simulated agent that obeys any instruction. Neither one executes, sends or deletes anything.

```bash
npm run demo:mcp                      # 7 critical, 2 high, 2 medium, 3 low
node examples/mock-agent.mjs &        # then:
npm run demo:agent                    # 9 of 9 probes succeed
```

## Tests

```bash
npm test
```

## Limits

- MCP checks are pattern-based. They catch common poisoning and risky designs, not every possible attack. They can also flag legitimate tools that send email or run commands.
- Agent probes send one message at a time, and only over a JSON HTTP endpoint.
- A clean report means these checks found nothing. It does not prove that a system is secure.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md).

Built by [AVENZOQ](https://avenzoq.com).
