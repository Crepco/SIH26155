<div align="center">

# Crucible

**Compliance you can prove.**

An AI-driven, vendor-agnostic network security compliance auditor that runs fully air-gapped —
and proves every high-severity finding against a disposable digital twin before an administrator
touches production.

Smart India Hackathon 2026 · Problem Statement **SIH26155** · National Technical Research Organisation

</div>

---

> **Status: Phase 1 — the baseline pipeline works end to end.** Upload a real configuration,
> get a correct, line-cited, signed PDF. Six vendors parse, 13 CIS controls evaluate, findings
> are hash-chained into a tamper-evident ledger. 92 tests pass with no third-party test runner.
> The AI layer (Tiers 1–3) and Crucible are next — see [docs/12-execution-plan.md](docs/12-execution-plan.md).

## The problem

A single government or enterprise network runs firewalls from Palo Alto, Fortinet, Cisco and
Check Point; switches and routers from Cisco, Arista, Juniper, HPE Aruba and MikroTik; cloud
security groups in AWS and Azure; and white-box hardware running SONiC or Cumulus. Every one of
those devices must comply with CIS Benchmarks, NIST SP 800-53, DISA STIGs and ISO/IEC 27001 —
and every one of them speaks a different language.

Today an auditor either works a three-hundred-item checklist by hand, or buys a vendor-locked
enterprise suite that only understands its own ecosystem. NTRO asked for the third option.

## The approach

Everything pivots on a **vendor-neutral intermediate representation** — an LLVM IR for network
security posture. Parsers write into it; rules, reports, remediation, graph analysis and the
verification sandbox read only from it.

```
config files (any vendor, single or bulk)
        |
        v
[1] INGESTION + FINGERPRINTING            vendor · model · OS version · serial
        |
        v
[2] PARSING CASCADE                       <-- this is where the "AI" actually lives
     Tier 0  known vendor      -> deterministic parser
     Tier 1  structural infer  -> generic config tree
     Tier 2  local LLM + embeddings PROPOSE A MAPPING (never a verdict)
     Tier 3  training GUI      -> admin confirms -> signed Vendor Adapter Pack
        |
        v
[3] NORMALISED SECURITY BASELINE MODEL (vendor-neutral JSON)
        |                                   |
        v                                   v
[4] POLICY ENGINE                       [5] FLEET GRAPH
    CIS / NIST / STIG / ISO                 cross-device correlation
    rules as versioned YAML                 + attack-path queries
        |                                   |
        +-----------------+-----------------+
                          v
[6] REPORTING   per-device PDF + fleet report, signed and hash-chained
                          |
                          v
[7] CRUCIBLE    boot a disposable twin -> demonstrate -> remediate
                -> re-test -> regression
```

Full description: [docs/02-architecture.md](docs/02-architecture.md).

## The five invariants

These are architectural guarantees, not aspirations. They are what separates an audit tool from
a chatbot with a file upload.

| # | Invariant | Consequence |
|---|-----------|-------------|
| 1 | **The AI never decides pass or fail.** It only writes parsers. | Model output is a candidate extraction rule, applied deterministically. AI proposes; the engine disposes. |
| 2 | **Every finding carries line-level evidence.** | File, line number and raw text. Audits reproduce byte-for-byte. |
| 3 | **Fail closed.** Unparsed input can never produce a pass. | Anything uninterpreted is reported `UNKNOWN` and counted against coverage. |
| 4 | **Coverage is published, not hidden.** | Every report states `parsed 12,847 of 13,102 lines (98.1%)`. |
| 5 | **Findings have three honest states, never two.** | `DEMONSTRATED` · `ASSERTED` · `UNKNOWN`. We never fabricate certainty. |

## What makes this different

- **Air-gapped by construction.** Local quantised model via Ollama, local embeddings, zero
  outbound calls in any code path. The customer is NCIIPC — a cloud LLM API is a hard
  disqualifier, not a preference.
- **Learns vendors instead of hard-coding them.** Unrecognised lines are surfaced to an admin in
  a low-code GUI and persisted as a **signed, portable Vendor Adapter Pack**. One organisation
  teaches it; every deployment benefits the next morning.
- **Rules are data, never code.** A compliance control is a YAML file. Adding a framework means
  adding files, never writing Python.
- **Reasons across the fleet, not device by device.** Two devices can each pass and the network
  still be trivially breachable. Remediation is ranked by attack paths severed, not by CIS severity.
- **Tamper-evident reports.** Findings are hash-chained into an append-only ledger, Merkle-rooted,
  signed, with a verification hash printed in the PDF footer.
- **Crucible: it proves the finding, and proves the fix is safe.** See
  [docs/07-crucible-sandbox.md](docs/07-crucible-sandbox.md).

> Every compliance tool tells you what is wrong. Ours proves it, fixes it, and proves the fix did
> not break anything — against a disposable digital twin, fully air-gapped.

## Repository layout

| Path | Contents |
|------|----------|
| [docs/](docs/) | Specifications, execution plan, ADRs. Start at [docs/00-index.md](docs/00-index.md). |
| [schemas/](schemas/) | Versioned JSON Schema for the intermediate representation and adapter packs. |
| [rules/](rules/) | Compliance rules as YAML, one directory per framework. |
| [backend/](backend/) | FastAPI service: ingestion, parsing cascade, policy engine, ledger, reporting. |
| [frontend/](frontend/) | Next.js dashboard, training GUI and fleet graph view. |
| [corpus/](corpus/) | Real multi-vendor configuration corpus and hand-labelled ground truth. |
| [adapters/](adapters/) | Vendor Adapter Packs — exported, signed, importable. |
| [labs/](labs/) | containerlab topologies for corpus generation and Crucible twins. |
| [deploy/](deploy/) | Compose files and the offline installation bundle. |
| [scripts/](scripts/) | Operator and developer task scripts. |

## Deliverable mapping

The problem statement names five required components. Each maps to a directory and a spec.

| NTRO requirement | Where it lives |
|------------------|----------------|
| 1. Unified Ingestion Engine | `backend/crucible/ingest` · [docs/05](docs/05-parsing-cascade.md) |
| 2. AI-Powered Training Module | `backend/crucible/training` + `frontend/` · [docs/06](docs/06-adapter-packs.md) |
| 3. Multi-Framework Compliance Engine | `backend/crucible/policy` + `rules/` · [docs/04](docs/04-rule-format.md) |
| 4. Actionable Intelligence & PDF Reporting | `backend/crucible/report` · [docs/10](docs/10-reporting.md) |
| 5. Vendor-Agnostic Scalability | `schemas/ir` + `adapters/` · [docs/03](docs/03-ir-schema.md) |

## Roadmap

| Phase | Dates | Headline | Definition of done |
|-------|-------|----------|--------------------|
| 0 | 25–31 Aug | Foundations | IR schema frozen, 60+ real configs collected, 20 hand-labelled |
| 1 | 1–7 Sep | Core pipeline end to end | Upload a real Cisco config, get a correct line-cited PDF |
| 2 | 8–14 Sep | The AI layer | Hold out a vendor, train it cold in under three minutes, export the pack |
| 3 | 15–19 Sep | Differentiators | A demo that survives an audience, and a real accuracy figure |
| — | **20 Sep** | **Idea submission closes** | Four artefacts, each mapped to the five-component list |
| 4 | 21 Sep on | Crucible | `crucible verify` confirms a finding live, under 15 s, offline |
| 5 | Pre-finale | Hardening | Something that looks like a product, not a prototype |

Full plan with owners and risks: [docs/12-execution-plan.md](docs/12-execution-plan.md) ·
[docs/14-risk-register.md](docs/14-risk-register.md) · [CHANGELOG.md](CHANGELOG.md).

## Getting started

Python 3.11+. The core pipeline runs on the standard library plus three packages — and, like
everything else here, it makes no network calls.

```bash
pip install pyyaml reportlab cryptography      # core
pip install fastapi uvicorn                    # optional: the HTTP API

cd backend
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports
```

That audits five real configurations from five vendors and writes a JSON, Markdown and PDF report
per device, plus a signed `ledger.jsonl`. Then:

```bash
python -m crucible.api.cli verify ../reports/ledger.jsonl   # tamper check
python -m crucible.api.cli show tests/fixtures/devices/cisco-ios-core-01   # the parsed IR
python -m crucible.api.cli rules --rules ../rules/cis       # the loaded rule set
python tests/run_tests.py                                   # 92 tests, no pytest required
```

Or through `make`: `make demo`, `make verify`, `make test`, `make serve`.

### What a run looks like

```
  core-sw-01
    cisco IOS 15.2(4)E10  serial FDO1234ABCD
    score  [#######.................] 31%  -> 85% after remediation
    checks fail 7  unknown 2  pass 4
    parsed 163/164 lines (99.4%)  1 uninterpreted
      FAIL critical CIS-NET-1.1.1  Telnet must be disabled on all management tr   running-config.txt:102
      FAIL critical CIS-NET-2.1.2  No default or well-known SNMP community stri   running-config.txt:87
      UNKN high     CIS-NET-5.3.1  Weak SSH key exchange algorithms must not be   no line to cite
```

Every failure cites a line. Every `UNKN` is a control we refused to guess at. Exit code `1` means
findings, `2` means the audit could not run — a CI job must never confuse the two.

### Where to read next

- [docs/00-index.md](docs/00-index.md) — every specification, in reading order
- [CONTRIBUTING.md](CONTRIBUTING.md) — track ownership, branch and commit conventions, and the
  seven rules a review will reject a PR for
- [docs/adr/](docs/adr/) — decisions already made, and not re-litigated

## Licence

[MIT](LICENSE). CIS Benchmark text is not reproduced in this repository or in generated reports —
see the third-party content notice in the licence file.
