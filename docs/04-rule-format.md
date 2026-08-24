# 04 — Rule format: compliance as data

**Status: draft, freezes 27 August 2026. Owner: Track B.**

A compliance rule is a YAML file. Adding a framework means adding files; it never means writing
Python. This is precisely what satisfies the "no manual code modification" scalability
requirement in the problem statement, and it lets the same parsed configuration be scored against
four frameworks simultaneously without re-parsing.

## A complete rule

    - id: CIS-NET-1.2.4
      title: "Idle session timeout must be 10 minutes or less"
      frameworks: [CIS-v8, NIST-SP800-53:AC-11, STIG-NET0993]
      severity: medium
      assert: mgmt.idle_timeout_min <= 10
      rationale: "Unattended sessions permit hijacking of privileged access."
      remediation:
        cisco_ios: ["line vty 0 4", " exec-timeout 10 0"]
        juniper:   ["set system login idle-timeout 10"]
        fortios:   ["config system global", " set admintimeout 10", "end"]

That is the whole thing. No code, no plugin, no registration step.

## Fields

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable identifier. Never reused, never renumbered. Appears verbatim in the report and in the ledger. |
| `title` | yes | One line, imperative, states the desired state rather than the violation. |
| `frameworks` | yes | Cross-framework control identifiers this rule satisfies. Identifiers only — see the licensing note below. |
| `severity` | yes | `critical`, `high`, `medium`, `low`, `info`. Drives Crucible selection: only `high` and `critical` are verified against a twin. |
| `assert` | yes | An expression over the IR that must evaluate true for a PASS. |
| `applies_to` | no | Guard limiting the rule to particular vendors, roles or OS versions. Omitted means all devices. |
| `rationale` | yes | Why this matters, in the language of consequence, not of the standard. Printed in the report. |
| `remediation` | yes | Per-render-target command sequences. Ordered, and safe to paste top to bottom. |
| `references` | no | Public URLs or document identifiers. STIG and NIST text may be quoted; CIS text may not. |
| `verify` | no | Named probe from the Crucible probe library. Presence makes the finding eligible for DEMONSTRATED. |

## The assertion language

Deliberately small and auditable. This is a compliance tool: an expression a reviewer cannot read
in five seconds is a liability.

| Construct | Example |
|-----------|---------|
| Path reference | `mgmt.idle_timeout_min` |
| Comparison | `== != < <= > >=` |
| Boolean | `and` `or` `not` |
| Membership | `snmp.version in [3]` |
| Existence | `defined(ntp.servers)` |
| Emptiness | `empty(snmp.communities)` |
| Quantifiers | `all(interfaces, iface.shutdown or defined(iface.acl_in))` |
| Set difference | `subset(mgmt.ssh.ciphers, APPROVED_CIPHERS)` |

Explicitly not supported: arbitrary function calls, regular expressions over raw config text,
loops with side effects, and anything that reads a file. Rules read the IR and nothing else.

## Three-valued logic, because absence is not falsehood

Every assertion evaluates to one of three results, never two.

| Result | When | Reported as |
|--------|------|-------------|
| `true` | The assertion held over facts that were actually observed | PASS |
| `false` | The assertion was violated by observed facts | FAIL, with line-cited evidence |
| `unknown` | A path in the expression is `null` because it was never parsed | UNKNOWN, counted against coverage |

`null <= 10` is **not** false and is **not** true. It is `unknown`. This is invariant 3 — fail
closed — expressed in the evaluator. A rule author who wants to treat absence as a violation must
say so explicitly with `defined(...)`.

## Guards

    applies_to:
      vendor: [cisco, arista]
      role:   [core, distribution]
      os_version: ">=15.0"

A rule that does not apply is `not_applicable` and appears in the report as such. It is neither a
pass nor a hidden omission.

## Severity and framework mapping

Each rule carries its native severity plus cross-framework control identifiers. The report groups
by severity; the framework selector filters by identifier. One IR, four frameworks, no re-parse.

## Licensing constraint

**CIS Benchmarks are copyrighted and licence-restricted.** Reproducing their text inside
generated reports has real licensing implications. DISA STIGs and NIST SP 800-53 are US
government publications and are far safer to quote.

Therefore: `frameworks` holds CIS control *identifiers* cited deterministically from our own rule
metadata, `rationale` is our own prose, and full control text is quoted only from STIG and NIST
sources. Rule files must never paste CIS Benchmark text into `rationale` or `references`.

## Directory layout

    rules/
      cis/        hand-authored, ~40 controls for submission
      stig/       bulk-imported from official XCCDF XML
      nist/       mapping demonstration, not full coverage
      iso/        mapping demonstration, not full coverage
      _template/  the annotated starting point for a new rule

Bulk-importing DISA STIGs is the highest-leverage half-day in the entire plan: STIGs ship as
machine-readable XCCDF XML, so one importer yields 300+ real controls instead of forty hand-typed
ones. That is the difference between claiming multi-framework support and demonstrating it.

## Rule review checklist

- Does the assertion read correctly when the field is `null`?
- Is the remediation ordered so that it cannot lock the administrator out mid-sequence?
- Is remediation present for every render target the rule can apply to?
- Does the rationale state a consequence rather than restate the title?
- Is any CIS Benchmark text reproduced? If yes, reject.
