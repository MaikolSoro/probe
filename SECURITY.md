# Security policy

## Reporting a vulnerability in Probe

If you find a security problem **in Probe itself**, please do not open a public issue. Examples:
- a scan that can be made to execute code;
- a report that leaks secrets;
- a bypass of the read-only safeguard.

Email **info@avenzoq.com** with:
- a description of the issue and its impact;
- the steps to reproduce it, or a proof of concept;
- the Probe version (`node src/cli.mjs` prints it).

We aim to reply within 5 business days and to agree on a disclosure date with you.

## Findings Probe reports about other software

Probe reports issues in the MCP servers, agents and skills **you** scan. If you find a real vulnerability in someone else's project with Probe, report it privately to that project's maintainers first (responsible disclosure).

## Safe use

- Only scan systems you own or are authorized to test.
- Static MCP scans never call tools. `--call-readonly` only calls tools that declare `readOnlyHint: true` and take no arguments.
- `probe config` starts the MCP servers listed in your client configs, as the client itself would. Use `--no-connect` to only read the files.
- `probe skills` reads files and never executes them.
