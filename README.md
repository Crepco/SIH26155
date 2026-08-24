<div align="center">

# Crucible

**Compliance you can prove.**

An AI-driven, vendor-agnostic network security compliance auditor that runs fully air-gapped —
and proves every high-severity finding against a disposable digital twin before an administrator
touches production.

Smart India Hackathon 2026 · Problem Statement **SIH26155** · National Technical Research Organisation

</div>

---

> **Status: Phase 0 — Foundations.** This repository currently contains the specification,
> schemas and project scaffold. Implementation begins with Phase 1 (1 Sep 2026).
> See [docs/12-execution-plan.md](docs/12-execution-plan.md).

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

## Getting started

Setup instructions land with Phase 1. Until then, read
[docs/00-index.md](docs/00-index.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

[MIT](LICENSE). CIS Benchmark text is not reproduced in this repository or in generated reports —
see the third-party content notice in the licence file.
