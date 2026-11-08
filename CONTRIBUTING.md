# Contributing to Probe

Thanks for helping make AI agents safer.

## Setup

```bash
npm install
npm test
npm run demo:mcp
```

Requires Node.js 20 or later. The code is plain ESM (`.mjs`) with no build step.

## Adding a rule or a probe

1. **Rule:** add it in `src/rules.mjs` (MCP tools), `src/skills-scan.mjs` (skills and instruction files) or `src/config-scan.mjs` (client configs). **Probe:** add it in `src/payloads.mjs` (agent probes).
2. Give it a stable `id`, a `severity` (`critical`, `high`, `medium`, `low`) and its OWASP LLM Top 10 (2025) category.
3. Add a plain-language entry, in **English and Spanish**, to `src/guidance.mjs`. It feeds the client report.
4. Add a test in `test/` that covers a true positive and a near-miss that must **not** match.
5. Run `npm test` and the demos.

## Ground rules

- **No working exploits.** Probes prove that an agent obeys untrusted input (canary echo). They never cause real damage or exfiltrate real data.
- **Static scans never call tools.** Anything that calls a tool must be opt-in and limited to read-only tools without arguments.
- **Keep false positives low.** Skill packs for security research legitimately describe attacks. Target instructions aimed at the agent, not attack vocabulary.
- Examples stay fake: dummy data and `.invalid` domains.

## Regenerating the README images

```bash
node scripts/readme-assets.mjs        # docs/assets/banner.svg and terminal.svg
```
