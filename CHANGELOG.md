# Changelog

Notable changes to Crucible. Format loosely follows Keep a Changelog; versions track the phase
plan in [docs/12-execution-plan.md](docs/12-execution-plan.md).

## [Unreleased] — Phases 2 to 5 (21 Sep 2026)

Everything the plan called specified is now built. 224 tests.

### Added

- **The learning layer (Tiers 1–3).** Structural inference for an unknown grammar; a lexical
  proposer (TF-IDF over words and character trigrams) that needs no model and is deterministic;
  an optional local model on loopback that is only ever asked to *choose* among candidates and
  point at the value token, never to write a pattern; the training console; and **signed Vendor
  Adapter Packs** — data only, a fixed transform library, Ed25519 signatures and a trust store
  that refuses an unknown signer. Measured on RouterOS with its parser held out: 7 of 9 fields.
- **XCCDF 1.1/1.2 importer.** A DISA benchmark becomes rules the engine loads, through explicit
  bindings, verified against real BIND and Firefox STIG content. No standard text is reproduced,
  only identifiers.
- **Palo Alto PAN-OS parser**, expat-based with line numbers and DTDs refused.
- **Fleet attack-path graph.** Devices, interfaces, segments, credentials and services; four
  correlations; reachability; remediation ranked by the paths each fix severs. Credentials are
  matched by salted HMAC fingerprint, never by value.
- **Crucible sandbox.** A container twin built here (ADR 0008, superseding VyOS), two internal
  bridges, stdlib probes (telnet, SSH KEXINIT, hand-rolled SNMPv2c BER, HTTP, ACL bypass), and a
  four-phase run: demonstrate, remediate, re-test, check for lock-out. The proof digest goes into
  the ledger leaf. A finding is `DEMONSTRATED` only if a probe actually demonstrated it.
- **Measured accuracy.** `crucible validate` against hand-labelled configurations: precision 1.00,
  recall 0.90, fact accuracy 1.00 — printed with the caveat that the labels await human review.
  A miss that lands on UNKNOWN is counted as a cautious miss, separately from a false negative.
- **Drift.** `crucible drift` names what regressed, what was fixed, and which facts moved
  underneath a control that was already failing. Exit 1 on regression.
- **The offline bundle.** `build-offline-bundle.sh` vendors every wheel and the twin image;
  `verify-offline-bundle.sh` installs it with `--no-index` and no usable proxy, then runs the
  suite, a full audit and a ledger check out of the installed copy.
- **Audit console** served by the API at `/`: AUDIT, TRAIN and FLEET views, plain HTML/CSS/JS,
  with a test that fails if any asset reaches off the host.
- Submission artefacts in `docs/submission/`: a two-page architecture document (PDF and Markdown)
  and the two-minute demo video script.

### Fixed

- **A proxy would have seen every prompt.** The Ollama proposer checked that its URL was loopback
  but called `urlopen`, whose default opener reads `http_proxy`. On a host with a corporate proxy
  — the kind that also has an air gap — every prompt, customer configuration lines included,
  would have gone to that proxy. Loopback is now enforced in the transport.
- **Fleet correlation was quadratic.** A 200-device audit spent 110.9s of 2m6s in path search.
  One breadth-first sweep per (segment, port) gives identical findings in 4.0s.
- One unreadable device no longer aborts the fleet; failures are reported per device, and an
  audit where nothing could be read exits 2 rather than looking clean.
- Redaction leaks found by reading the output rather than the code: SNMP community strings in the
  evidence gutter, and credential hashes in the training view.
- Accuracy bugs found by measuring against ground truth, not by inspection: an assertion stricter
  than its own title, Arista eAPI assumed plaintext, and NTP and Junos services needing a
  closed-world reading.
- The fingerprinter called Huawei VRP "cisco" at 0.72 confidence from a single keyword. Confidence
  is now evidence × margin, and an unrecognised device is `unknown`.

### Changed

- README, `backend/README.md` and `deploy/` rewritten against what now runs, with measured numbers
  and their caveats rather than claims.
- The console is plain HTML served by the API; the Next.js scaffold is retired (ADR 0007).

## [0.1.0] — Phase 1, the baseline pipeline (28 Aug 2026)

Upload a real configuration, get a correct, line-cited, signed PDF. The whole loop is closed.

### Added

- **Ingestion.** Files, directories, device bundles and zip archives. Archive handling refuses
  path traversal, absolute members, symlinks and decompression bombs rather than sanitising them.
  A directory holding one config plus its `show version` output is correctly read as one device.
- **Fingerprinting.** Weighted signature scoring across six vendors with a published confidence.
  Below the threshold no parser runs at all, so an unrecognised device reports UNKNOWN rather than
  being misread by the wrong grammar. Serial, model and OS version are extracted from command
  output and cited to a file and line.
- **Tier-0 parsers.** Cisco IOS, Arista EOS (shared IOS-style walker), Fortinet FortiOS, Juniper
  Junos, MikroTik RouterOS, plus a show-output reader. Every parser writes provenance with every
  fact and accounts for every line it consumed.
- **The IR.** `IRBuilder` refuses to record a fact without a source line, and computes coverage
  from what was and was not claimed. `parsed + unparsed == total` is asserted, not assumed.
- **Three-valued policy engine.** A Kleene-logic assertion language over the IR with `defined`,
  `empty`, `count`, `all`, `any` and `subset`. A missing fact yields UNKNOWN and can never become
  a PASS. Assertions compile at rule-load time, so a broken rule stops the run immediately.
- **Reporting.** One assembled report rendered three ways — JSON, Markdown and a ReportLab PDF
  with the verification hash on every page. Coverage is published, uninterpreted lines are listed
  verbatim in Appendix C, and the what-if projection never assumes an UNKNOWN will pass.
- **Remediation ordering.** Fixes are grouped into four phases so that pasting them top to bottom
  cannot lock an administrator out: the safe path is established first, weak services are removed
  second, and management access is narrowed last.
- **Tamper-evident ledger.** Merkle-rooted reports with domain-separated leaves and odd-node
  promotion, hash-chained into an append-only log and signed with Ed25519. Altering one historical
  entry breaks its signature and every subsequent link.
- **CLI.** `crucible audit | verify | rules | show`, with exit codes that distinguish "found
  something serious" from "could not run".
- **HTTP API.** FastAPI service for upload, audit, rules and ledger state, driving the same
  runner as the CLI. Uploads are deleted before the response returns.
- **92 tests**, runnable with no third-party test framework installed, covering all five
  invariants, multi-vendor consistency, ledger tampering, archive attacks and the full pipeline.

### Fixed during the build, each caught by a test

- Only the last interface of a Cisco configuration reached the IR.
- SNMP community strings survived redaction into evidence on four vendors.
- `defined()` reported a confident FAIL on a device whose section was never parsed.
- Loading a single device directory split it into two phantom devices.
- Telnet remediation disabled the daemon before confirming SSH was up.
- Fingerprint confidence was a float, which broke canonical IR export.

### Known gaps

- Tiers 1–3 (structural inference, model-proposed mappings, the training GUI) are specified but
  not implemented. Unrecognised vendors currently fall through to UNKNOWN, which is correct
  behaviour but not yet the learning loop.
- PAN-OS has no Tier-0 parser yet; the fingerprinter recognises it.
- Fleet graph, XCCDF import and Crucible remain Phase 3 and Phase 4.

## [0.0.1] — Phase 0, Foundations (25–31 Aug 2026)

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
