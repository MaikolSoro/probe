import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

// Guards against rule changes that quietly make detection worse.
test('pattern-only benchmark stays at or above 85% F1', () => {
  const { NODE_TEST_CONTEXT, ...env } = process.env;
  const out = spawnSync(process.execPath, ['bench/run.mjs'], { encoding: 'utf8', env }).stdout;
  const total = out.split('\n').find((l) => l.startsWith('| Total'));
  const f1 = Number(total.split('|').at(-2).trim().replace('%', ''));
  assert.ok(f1 >= 85, `F1 dropped to ${f1}%`);
});
