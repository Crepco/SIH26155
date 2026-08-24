# NIST SP 800-53 mapping

**Scope: we demonstrate the mapping, not the totality.** Full NIST SP 800-53 coverage is
explicitly out of scope for the submission, and pretending otherwise would be a breadth claim we
cannot defend.

## How the mapping works

NIST SP 800-53 controls are organisational and technical requirements, not device commands.
`AC-11` says a system must initiate a session lock after a defined period of inactivity; it does
not say `exec-timeout 10 0`. The bridge between the two is our own rule metadata.

Every rule in [`../cis/`](../cis/) and [`../stig/`](../stig/) already carries its NIST control
identifiers in `frameworks`:

    frameworks: [CIS-v8, NIST-SP800-53:AC-11, STIG-NET0993]

Selecting NIST in the dashboard therefore does not re-parse anything and does not evaluate a
different rule set. It filters and regroups the same findings by NIST control family. That is the
IR paying for itself: one parse, four frameworks.

## What lives in this directory

Files here add NIST-specific control text and family grouping metadata — the material a report
needs in order to present findings the way an assessor expects to read them. NIST SP 800-53 is a
US Government publication, so control text may be quoted in full.

## Families exercised by the current rule set

| Family | Controls touched by existing rules |
|--------|-----------------------------------|
| AC — Access Control | AC-3, AC-11, AC-17 |
| AU — Audit and Accountability | AU-4, AU-8 |
| IA — Identification and Authentication | IA-2, IA-3, IA-5 |
| SC — System and Communications Protection | SC-7, SC-8, SC-13 |
