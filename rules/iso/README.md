# ISO/IEC 27001 mapping

**Scope: we demonstrate the mapping, not the totality.**

ISO/IEC 27001 Annex A controls sit a level above device configuration. `A.8.20 Network security`
and `A.8.5 Secure authentication` describe management intent; they do not describe a CLI. The
mapping is therefore many device findings to one Annex A control, and the value of selecting ISO
in the dashboard is that a compliance officer sees their own control identifiers rather than
network engineering vocabulary.

## Mechanism

Identical to the NIST mapping: rules already carry ISO control identifiers in `frameworks`, so
selecting ISO regroups existing findings rather than re-evaluating anything.

    frameworks: [CIS-v8, NIST-SP800-53:AC-17, ISO27001:A.8.20]

## Licensing

ISO/IEC standards are copyrighted and sold. Their control text is **not** reproduced here or in
generated reports. We cite Annex A control identifiers and reference numbers only, from our own
metadata — the same discipline applied to CIS Benchmarks. See
[docs/04-rule-format.md](../../docs/04-rule-format.md).

## Annex A controls exercised by the current rule set

| Control | Title (identifier cited, text not reproduced) |
|---------|----------------------------------------------|
| A.5.15 | Access control |
| A.8.5 | Secure authentication |
| A.8.15 | Logging |
| A.8.16 | Monitoring activities |
| A.8.17 | Clock synchronisation |
| A.8.20 | Networks security |
| A.8.21 | Security of network services |
| A.8.24 | Use of cryptography |
