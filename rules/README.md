# Compliance rules

Rules are data, never code. A compliance control is a YAML file; adding a framework means adding
files. This directory is the whole of the compliance engine's knowledge.

Format specification: [docs/04-rule-format.md](../docs/04-rule-format.md).
Machine-readable contract: [schemas/rule/v1.0.0/](../schemas/rule/v1.0.0/).

## Layout

| Directory | Source | Scope for submission |
|-----------|--------|----------------------|
| [`cis/`](cis/) | Hand-authored by Track B | ~40 controls, grouped by IR section |
| [`stig/`](stig/) | Bulk-imported from official DISA XCCDF XML | 300+ controls, generated not hand-typed |
| [`nist/`](nist/) | Mapping demonstration | We demonstrate the mapping, not the totality |
| [`iso/`](iso/) | Mapping demonstration | We demonstrate the mapping, not the totality |
| [`_template/`](_template/) | Annotated starting point for a new rule | — |

## Authoring a new rule

1. Copy [`_template/rule-template.yaml`](_template/rule-template.yaml).
2. Give it an `id` that has never been used. Identifiers are permanent: they appear in issued
   reports and in the hash-chained ledger.
3. Write the assertion against IR paths only. If the fact you need is not in the IR, that is a
   Track A conversation, not a reason to reach into raw text.
4. Check the assertion when the field is `null`. `null <= 10` is `unknown`, not `false`. If
   absence should fail, say `defined(...)` explicitly.
5. Write remediation for every render target the rule can apply to, ordered so that pasting it
   top to bottom cannot lock the administrator out mid-sequence.
6. Add `verify:` if a probe in the Crucible library can demonstrate it live. Without it the
   finding stays ASSERTED, which is honest and fine.

## What a review rejects

- CIS Benchmark text pasted into `rationale` or `references`. Cite the identifier; write our own
  prose. See the licensing note in [docs/04](../docs/04-rule-format.md).
- A rule whose remediation has never been run against a twin, once Crucible exists.
- A reused or renumbered `id`.
- An assertion that reaches outside the IR.
- Remediation that disables the transport the administrator is currently connected over, before
  the replacement transport is enabled.

## Loading

Every file here is validated against the rule schema at load time. A rule that does not validate
does not load, and the failure is loud. There is no partial rule set.
