// .probeignore: one suppression per line, "<rule-id> [where]", where both parts
// accept * wildcards and "#" starts a comment. Examples:
//   capability-outbound send_email     # we really do send email, with approval
//   skill-pipe-to-shell docs/*
//   config-unpinned-package *
import { existsSync, readFileSync } from 'node:fs';

const toRegex = (glob) => new RegExp(`^${glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);

export function parseIgnore(text) {
  return text
    .split('\n')
    .map((line) => line.replace(/#.*/, '').trim())
    .filter(Boolean)
    .map((line) => {
      const [rule, where = '*'] = line.split(/\s+/, 2);
      return { rule: toRegex(rule), where: toRegex(where) };
    });
}

export function loadIgnore(path) {
  const file = path ?? '.probeignore';
  if (!existsSync(file)) {
    if (path) throw new Error(`ignore file not found: ${path}`);
    return [];
  }
  return parseIgnore(readFileSync(file, 'utf8'));
}

export function applyIgnore(findings, rules) {
  const kept = findings.filter((f) => !rules.some((r) => r.rule.test(f.id) && r.where.test(f.tool)));
  return { kept, suppressed: findings.length - kept.length };
}
