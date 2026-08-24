# Changelog

Notable changes to Crucible. Format loosely follows Keep a Changelog; versions track the phase
plan in [docs/12-execution-plan.md](docs/12-execution-plan.md).

## [Unreleased] — Phase 0, Foundations (25–31 Aug 2026)

### Added

- Project scaffold: repository layout, licence, contributing guide, code of conduct, security
  policy.
- Full specification set in [`docs/`](docs/): problem statement breakdown, architecture, IR
  schema, rule format, parsing cascade, adapter packs, Crucible sandbox, fleet graph, ledger and
  signing, reporting, air-gap constraints, execution plan, technology stack, risk register, demo
  script, validation plan, competitive landscape, glossary.
- Six architecture decision records covering the IR pivot, rules as data, local-only inference,
  the AI-proposes invariant, the single emulation target, and the decision against a permissioned
  blockchain.
- IR v1.0.0 JSON Schema draft with coverage accounting and per-fact provenance, plus a worked
  Cisco IOS example.
- Compliance rule v1.0.0 JSON Schema draft, an annotated rule template, and thirteen hand-authored
  CIS controls across the management plane, SNMP, logging, NTP, AAA, cryptography and interface
  ACLs.
- Vendor Adapter Pack specification and a worked MikroTik RouterOS example.
- Backend package layout with import contracts enforcing the IR dependency rule, and a pyproject
  with dependencies chosen against the offline-bundle constraint.
- Frontend scaffold, screen inventory and the bundled-asset rule.
- Corpus layout, manifest, ground-truth label format and the held-out-vendor policy.
- containerlab topologies for corpus generation and for Crucible twins.
- Deployment compose stack, documented environment template, and the offline bundle
  specification.
- CI: schema and rule validation, lint, types, import contracts, tests, frontend build, and an
  air-gap workflow that fails on any cloud inference SDK or external asset host.
- Issue templates, pull request template with an invariant checklist, CODEOWNERS, Makefile and
  pre-commit configuration.

### Frozen on 27 Aug 2026

- IR schema v1.0.0.
- Compliance rule format v1.0.0.

Both are contracts from that date. Changes are breaking API changes with a migration, not edits.

## Planned

| Version | Phase | Headline |
|---------|-------|----------|
| 0.1.0 | 1 · 1–7 Sep | Core pipeline end to end: upload a real Cisco config, get a correct line-cited PDF |
| 0.2.0 | 2 · 8–14 Sep | The AI layer: structural inference, mapping proposals, training GUI, signed adapter packs, XCCDF import |
| 0.3.0 | 3 · 15–19 Sep | Fleet graph, attack-path ranking, hash-chained ledger, measured precision and recall |
| 0.4.0 | 4 · 21 Sep on | Crucible: twins, probes, the four-phase verification run, three-state findings |
| 0.5.0 | 5 · pre-finale | Bulk performance, drift tracking, UX pass, offline installation bundle |
