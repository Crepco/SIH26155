# ADR 0004 — The model proposes parsers; the deterministic engine issues verdicts

**Status:** Accepted · 25 Aug 2026 · Track B and Track C

## Context

The predictable submission for this problem statement pastes a configuration into a prompt and
renders the reply as a compliance table. It fails in five ways that are each fatal for an audit
tool: it is non-deterministic, it hallucinates control identifiers, it exceeds context on real
files, it silently passes what it did not read, and it is undeployable for the customer.

The temptation is to mitigate those with better prompting. Mitigation is not enough. An audit that
is not reproducible is not an audit.

## Decision

The model never emits a verdict. Its output is a **candidate extraction rule** — a regex, a path
expression, a field mapping — carrying a confidence score. That candidate is applied
deterministically to the raw configuration text, and the resulting fact enters the IR with
provenance recording the tier and the confidence.

The pass or fail decision is made by the YAML policy engine operating on parsed facts. Low
confidence never becomes a finding; it becomes a question for an administrator in the training
GUI.

**AI proposes; the deterministic engine disposes.**

## Consequences

**Good.**

- Reproducibility is structural. Run the audit twice, get identical findings, because the verdict
  path contains no model.
- Hallucination cannot reach a report. A hallucinated mapping produces either no match against the
  raw text or a wrong match that a human sees in the training GUI — it cannot invent a control
  identifier, because identifiers come from rule metadata.
- Context limits become irrelevant. The model sees individual unresolved nodes, never a
  40,000-line file.
- A small local model becomes viable, which is what makes ADR 0003 affordable.
- We have a one-sentence answer to the sharpest question a judge can ask: *how do I know your AI
  did not invent this?*

**Bad, and accepted.**

- More machinery than a prompt. The cascade, confidence scoring and training loop are real work,
  and they are the work NTRO actually asked for.
- Genuinely novel structures still need a human once. That is the training module in the
  requirements list, not a gap.
- We cannot claim the model understands security. We claim something narrower and true: it
  understands syntax well enough to propose a parser, and nothing it proposes is trusted without
  being applied deterministically.
