# ADR 0002 — Compliance rules are data, never code

**Status:** Accepted · 25 Aug 2026 · Track B

## Context

NTRO requirement 5 asks for a modular architecture supporting new vendors, standards and OS
versions **with no manual code changes**. A rule engine where each control is a Python function
fails that requirement on the first new benchmark, and cannot be extended by the auditor who
actually owns the standard.

DISA also publishes STIGs as machine-readable XCCDF XML. If rules are code, that XML has to be
translated by a programmer. If rules are data, one importer converts an entire benchmark release.

## Decision

A compliance rule is a YAML file: identifier, framework mappings, severity, an assertion over the
IR, rationale, and per-target remediation. The evaluator is a small, auditable expression
language over IR paths. There is no plugin API, no registration step and no Python per control.

## Consequences

**Good.**

- Adding a framework means adding files. This is the literal wording of the requirement.
- One XCCDF importer yields 300+ real controls — the highest-leverage half-day in the plan.
- Rules are reviewable by someone who knows compliance but not Python, which is who actually owns
  the content.
- Rules are diffable and versionable, so a report can name the exact rule set that produced it.

**Bad, and accepted.**

- The assertion language limits what a rule can express. Deliberate: a rule a reviewer cannot read
  in five seconds is a liability in a compliance tool. Controls that need more than the language
  offers become a request for a new IR field, not a request for arbitrary code.
- Some XCCDF check content cannot be mechanically mapped to an IR assertion. Those controls import
  with identity and text intact, marked as requiring manual authoring, and report UNKNOWN — never
  a silent PASS.
- We forgo OPA/Rego, which would be the more impressive answer. YAML ships faster, is easier to
  defend in Q&A, and does not add a runtime to the offline bundle. Revisit only if Phase 5 has
  slack.
