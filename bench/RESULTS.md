# Probe benchmark

Corpus: `bench/cases.mjs` (30 MCP tool descriptions, 12 skill and script files; malicious and tricky-benign cases, all fictional). Re-run with `node bench/run.mjs [--llm]`.

TP = attack caught · FP = harmless case flagged · FN = attack missed · TN = harmless case passed. Capability warnings (e.g. "tool can send email") are not counted; only attack detection is.

_Run on 2026-11-08._

## patterns only

| Corpus | Cases | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| MCP tool descriptions | 30 | 14 | 1 | 1 | 14 | 93% | 93% | 93% |
| Skills and scripts | 12 | 5 | 1 | 1 | 5 | 83% | 83% | 83% |
| Total | 42 | 19 | 2 | 2 | 19 | 90% | 90% | 90% |

Misclassified: `m03-paraphrased-keys` (FN), `b02-security-scanner` (FP), `s-m05-paraphrased` (FN), `s-b05-prompt-injection-docs` (FP)

### Read this before quoting the numbers

- This corpus was used **while developing** the rules (a development set), so these scores are optimistic. Expect lower precision and recall on attacks nobody has seen yet. A held-out set and real-world servers (see `research/`) are the honest test.
- The remaining misses are **paraphrased** attacks (`m03`, `s-m05`), and the false positives are **security documentation that quotes attack text** (`b02`, `s-b05`). Pattern rules cannot tell those apart; that is exactly what `--llm` is for. Run `node bench/run.mjs --llm --write` with `ANTHROPIC_API_KEY` set to add the judge's column.
