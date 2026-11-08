import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffScans, diffToMarkdown } from '../src/diff.mjs';
import { authorizationMarkdown } from '../src/authorization.mjs';

const f = (id, severity, tool, title = id) => ({ id, severity, tool, title });

test('diff classifies findings as resolved, new or still present by rule id and location', () => {
  const before = { findings: [f('tool-poisoning', 'critical', 'a'), f('excessive-capability', 'high', 'b'), f('tool-steering', 'medium', 'a')] };
  const after = { findings: [f('tool-steering', 'medium', 'a'), f('plain-http', 'low', '(server)')] };
  const d = diffScans(before, after);
  assert.deepEqual(d.resolved.map((x) => x.id).sort(), ['excessive-capability', 'tool-poisoning']);
  assert.deepEqual(d.added.map((x) => x.id), ['plain-http']);
  assert.deepEqual(d.unchanged.map((x) => x.id), ['tool-steering']);
  // Same rule, different tool, is not the same finding.
  const moved = diffScans({ findings: [f('x', 'high', 'a')] }, { findings: [f('x', 'high', 'b')] });
  assert.equal(moved.resolved.length, 1);
  assert.equal(moved.added.length, 1);
  assert.match(diffToMarkdown(d), /before\/after/i);
});

test('authorization template fills provided fields and leaves blanks otherwise', () => {
  const md = authorizationMarkdown({ client: 'Cliente S.A.', scope: 'https://api.x/chat, MCP Y', exclude: 'prod' }, 'es');
  assert.match(md, /Cliente S\.A\./);
  assert.match(md, /- https:\/\/api\.x\/chat/);
  assert.match(md, /- MCP Y/);
  assert.match(md, /- prod/);
  assert.match(md, /AVENZOQ/); // default tester
  assert.match(md, /abogado/); // keeps the "not legal advice" note
  assert.match(md, /_{6,}/); // unfilled fields are blanks to sign
  // English variant switches the heading and the disclaimer.
  assert.match(authorizationMarkdown({}, 'en'), /Authorization to perform a security assessment/);
  assert.match(authorizationMarkdown({}, 'en'), /not legal advice/);
});
