# State of MCP Security: research kit

Tools and rules for scanning public MCP servers at scale and publishing the results responsibly.

## Method

1. **Targets:** widely used public MCP servers published on npm (`targets.txt`). Only public packages are scanned. No private deployments, and no servers we are not allowed to run.
2. **Isolation:** each server runs inside a locked-down container (`Dockerfile`, flags in `run.mjs`):
   - read-only filesystem;
   - no Linux capabilities and `no-new-privileges`;
   - 1 CPU, 1 GB of memory and 256 processes;
   - no host folders mounted.

   Third-party code never runs on the researcher's machine.
3. **What Probe does:** it starts the server, **lists its tools** and applies the static rules. It never calls a tool, so nothing is read, written or sent on anyone's behalf.
4. **Manual review:** every critical finding is checked by a person, plus the `--llm` judge when available, before it is counted. Pattern matches alone are not reported as vulnerabilities.
5. **Benchmark:** the rules' measured precision and recall (`../bench/RESULTS.md`) are published next to the results, so readers know the error rate.

## Running it

```bash
# Docker Desktop must be running
node research/run.mjs                 # scans research/targets.txt → research/results/*.json
node research/aggregate.mjs           # → research/REPORT-draft.md (aggregate only)
                                      #   + research/results/PRIVATE-by-server.md (never published)
```

`research/results/` is git-ignored on purpose.

## Responsible disclosure

- **Before publishing anything:** each confirmed critical issue is reported privately to the maintainer, through their `SECURITY.md`, a GitHub security advisory, or email. Use `disclosure-template.md`.
- **Embargo:** 90 days from the report, or until a fix ships, whichever comes first. Extend it if the maintainer is actively working on a fix.
- **Public report:** aggregate numbers only (for example, "X % of servers expose a command-execution tool"). Servers are named only after their issue is fixed or the embargo ends, and fixes are credited.
- **Capabilities are not vulnerabilities.** A filesystem server that can write files is doing its job. The report presents capability numbers as "what an agent could be tricked into doing", never as flaws of those projects.
- **Nothing is exploited.** No tool is called and no payload is sent to anyone's infrastructure.

## Checklist before publishing

- [ ] Every critical finding was reviewed manually and is not a false positive
- [ ] Maintainers with confirmed issues were contacted, and the date was logged
- [ ] The embargo has ended or fixes have shipped
- [ ] The benchmark (`bench/RESULTS.md`) was re-run with the same Probe version
- [ ] The report states the Probe version, the scan date, the sample size and its limits
