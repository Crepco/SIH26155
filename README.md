<div align="center">

# Crucible

**Compliance you can prove.**

A vendor-agnostic network security compliance auditor that runs fully air-gapped, cites the exact
configuration line behind every finding, and signs every report into a tamper-evident ledger.

Smart India Hackathon 2026 · Problem Statement **SIH26155** · National Technical Research Organisation ·
Blockchain & Cybersecurity

**[Architecture (PDF, 2 pages)](docs/submission/Crucible-Architecture.pdf)** ·
[Architecture (Markdown)](docs/submission/ARCHITECTURE.md) ·
**Demo video: VIDEO_LINK** ·
[Setup](#setup-five-minutes-no-internet-needed-after-install)

</div>

---

## What it does today

Point it at network device configurations from different vendors. In about one second, offline,
you get this for each device:

- **identity**: vendor, OS version, model and serial number, each cited to the file it came from
- **findings**: pass, fail or unknown, by severity, each pointing at the **file and line number**
  that caused it
- **coverage**: how much of the file was actually understood (`parsed 163 of 164 lines`), with
  the lines it could not interpret listed word for word
- **remediation**: vendor-specific CLI, ordered so that applying it top to bottom cannot lock the
  administrator out
- **a signed PDF**: with a verification hash on every page, recorded in an Ed25519-signed,
  hash-chained ledger that shows any later edit

This happens through a browser console or a CLI. There is no cloud model, no outbound call, and
no database.

## Status: what is built and what is not

We would rather show a working foundation and an honest gap than claim features that don't run.

| | Component | Status |
|---|-----------|--------|
| ✅ | Ingestion: single files, bulk upload, directories, device bundles, zip archives (safe against path traversal and zip bombs) | **Built** |
| ✅ | Fingerprinting: vendor, OS, version, model and serial, with a confidence score (6 vendors recognised) | **Built** |
| ✅ | Tier-0 parsers: **Cisco IOS, Arista EOS, Fortinet FortiOS, Juniper Junos, MikroTik RouterOS**, plus `show version` output | **Built** |
| ✅ | Vendor-neutral IR (JSON Schema v1.0.0, frozen), with per-fact provenance and line coverage accounting | **Built** |
| ✅ | Three-valued policy engine: 13 controls written as YAML, each mapped to **CIS v8, NIST SP 800-53 and DISA STIG** | **Built** |
| ✅ | Reports: JSON, Markdown and PDF, with line-cited evidence, safety-ordered remediation and a what-if score | **Built** |
| ✅ | Tamper-evident ledger: Merkle-rooted reports, hash chain, Ed25519 signatures, `verify` command | **Built** |
| ✅ | Audit console (browser) served by the API. No external assets, enforced by a test | **Built** |
| ✅ | 101 tests, runnable without pytest | **Built** |
| ⏳ | AI training module (Tiers 1–3): structural inference, a local-LLM mapping proposal, the training GUI, signed Vendor Adapter Packs | Specified · Phase 2 |
| ⏳ | ISO/IEC 27001 rules; XCCDF importer for full STIG coverage; PAN-OS parser | Specified · Phase 2 |
| ⏳ | Fleet attack-path graph: cross-device correlation, remediation ranked by paths severed | Specified · Phase 3 |
| ⏳ | Crucible sandbox: boot a disposable digital twin, demonstrate the finding, verify the fix | Specified · Phase 4 |

An unrecognised vendor currently produces an honest `UNKNOWN` for every control. It is never
reported as a pass. The learning loop that closes that gap is Phase 2.

---

## Setup (five minutes, no internet needed after install)

### Prerequisites

- **Python 3.11 or newer.** Check with `python --version`.
- Git. Nothing else: no Docker, no database, no Node, no GPU, no API key.

### 1. Clone and install

```bash
git clone https://github.com/Crepco/SIH26155.git
cd SIH26155
python -m pip install -r backend/requirements.txt
```

This installs a handful of small packages: PyYAML, ReportLab, cryptography, FastAPI, Uvicorn,
python-multipart, and httpx (used only by the tests). A virtual environment is optional but recommended:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.txt
```

### 2. Check the install

```bash
cd backend
python tests/run_tests.py
```

Expected last line: **`101 passed`**.

### 3. Run the audit console

```bash
python -m uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000
```

Open **<http://127.0.0.1:8000>** and click **Audit the sample fleet**. That audits five real
configurations from five vendors. Then:

1. Click **core-sw-01** in the fleet list.
2. Expand **CIS-NET-1.1.1 (Telnet)**. The device's own config appears at its real line numbers,
   with line 102 marked.
3. Look at **COVERAGE** (163 of 164 lines) and **NOT INTERPRETED** (the one line it could not
   read, shown verbatim).
4. Click the **UNKNOWN** filter. These are controls the engine refused to guess at.
5. Scroll to **REMEDIATION**, then open the signed PDF for that device at
   <http://127.0.0.1:8000/reports/cisco-ios-core-01.pdf>.

You can also upload your own configurations with **Choose files**. You can switch Wi-Fi off before
any of this; nothing changes.

### 4. Or use the CLI

Run these from the `backend/` directory:

```bash
# Audit the five sample devices, write JSON + Markdown + PDF per device and a signed ledger
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports

# Check the ledger has not been altered
python -m crucible.api.cli verify ../reports/ledger.jsonl

# Only STIG-mapped controls (same parse, different framework)
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports --framework STIG

# The vendor-neutral IR the rules actually read
python -m crucible.api.cli show tests/fixtures/devices/cisco-ios-core-01

# The loaded rule set
python -m crucible.api.cli rules --rules ../rules/cis
```

`audit` exits with code `1` when it finds serious findings and `2` when the audit could not run, so a
CI job can never confuse the two. Reports land in `reports/` at the repository root.

**Try the tamper check.** Open `reports/ledger.jsonl`, change one character in the second entry's
`merkle_root`, save, and run `verify` again. It reports `TAMPERED`: that entry's signature fails, and the next
entry's link to it breaks. Hiding the edit would mean re-signing every later entry, which needs the
issuing private key.

### What a run looks like

```
  CRUCIBLE 0.1.0   rules: 13 (digest 49c9878c30156358)
  5 device(s)   fleet score 28%   mean coverage 99.6%

  core-sw-01
    cisco IOS 15.2(4)E10  serial FDO1234ABCD
    score  [#######.................] 31%  -> 85% after remediation
    checks fail 7  unknown 2  pass 4
    parsed 163/164 lines (99.4%)  1 uninterpreted
      FAIL critical CIS-NET-1.1.1  Telnet must be disabled on all management tr   running-config.txt:102
      FAIL critical CIS-NET-2.1.2  No default or well-known SNMP community stri   running-config.txt:87
      UNKN high     CIS-NET-5.3.1  Weak SSH key exchange algorithms must not be   no line to cite
```

Every failure cites a line. Every `UNKN` is a control we refused to guess at.

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `python` is 3.10 or older | On Windows use `py -3.11`, elsewhere `python3.11` |
| Port 8000 already in use | Add `--port 8010` and open that port instead |
| Console page is blank | Hard refresh (Ctrl+Shift+R). The CLI prints the same findings |
| `Form data requires "python-multipart"` | Install from `backend/requirements.txt`, not package by package |
| `make` targets | Optional shortcuts (`make test`, `make demo`, `make serve`, `make verify`), for Linux/macOS |

---

## The approach

Everything pivots on a **vendor-neutral intermediate representation**, an LLVM-style IR for
network security posture. Parsers write into it. Rules, reports, remediation and (later) graph
analysis and the sandbox read only from it. Adding a vendor never touches a rule; adding a
framework never touches a parser.

```
config files (any vendor, single or bulk)
        |
        v
[1] INGESTION + FINGERPRINTING            vendor · model · OS version · serial        built
        |
        v
[2] PARSING CASCADE
     Tier 0  known vendor      -> deterministic parser                             built (5 vendors)
     Tier 1  structural infer  -> generic config tree                              Phase 2
     Tier 2  local LLM PROPOSES a mapping (never a verdict)                        Phase 2
     Tier 3  training GUI      -> admin confirms -> signed Vendor Adapter Pack     Phase 2
        |
        v
[3] NORMALISED SECURITY BASELINE MODEL (vendor-neutral JSON IR)                    built
        |                                   |
        v                                   v
[4] POLICY ENGINE  (rules as YAML)      [5] FLEET GRAPH                            built | Phase 3
        |                                   |
        +-----------------+-----------------+
                          v
[6] REPORTING   per-device PDF, signed and hash-chained                           built
                          |
                          v
[7] CRUCIBLE    disposable twin -> demonstrate -> remediate -> re-test             Phase 4
```

The two-page summary is [docs/submission/ARCHITECTURE.md](docs/submission/ARCHITECTURE.md), and the full
design is in [docs/02-architecture.md](docs/02-architecture.md).

## The five invariants

These are guarantees built into the architecture, and the tests enforce them.

| # | Invariant | Consequence |
|---|-----------|-------------|
| 1 | **The AI never decides pass or fail.** It only writes parsers. | Model output is a candidate extraction rule, applied deterministically. The AI proposes and the engine decides. This build has no model in the verdict path at all. |
| 2 | **Every finding carries line-level evidence.** | File, line number and raw text. Audits reproduce byte for byte. |
| 3 | **Fail closed.** Unparsed input can never produce a pass. | Anything uninterpreted is reported `UNKNOWN` and counted against coverage. |
| 4 | **Coverage is published, not hidden.** | Every report states `parsed N of M lines` and lists the rest verbatim. |
| 5 | **Findings have three honest states, never two.** | `DEMONSTRATED` · `ASSERTED` · `UNKNOWN`. Until the sandbox lands, nothing is marked `DEMONSTRATED`. |

## Mapping to the NTRO requirements

| NTRO component | Where it lives | Status |
|----------------|----------------|--------|
| 1. Unified Ingestion Engine | `backend/crucible/ingest`, `fingerprint` · console **Choose files** · `POST /audit` | **Built.** Single and bulk upload, bundles, archives |
| 2. AI-Powered Training Module | `backend/crucible/training` · [adapters/](adapters/) · [docs/06](docs/06-adapter-packs.md) | **Specified, Phase 2.** Today every uninterpreted line is already surfaced verbatim; that list is the training GUI's input |
| 3. Multi-Framework Compliance Engine | `backend/crucible/policy` · [rules/](rules/) · [docs/04](docs/04-rule-format.md) | **Built for CIS / NIST / STIG** (13 controls, one parse, `--framework` selects). ISO and XCCDF import: Phase 2 |
| 4. Actionable Intelligence & PDF Reporting | `backend/crucible/report`, `ledger` · [docs/10](docs/10-reporting.md) | **Built.** Identity incl. serial, severity, line evidence, vendor CLI, signed PDF |
| 5. Vendor-Agnostic Scalability | [schemas/ir](schemas/ir/) · rules as data · parser registry · [docs/03](docs/03-ir-schema.md) | **Built foundation.** New rules need no code; new vendors will need no code once adapter packs land (Phase 2) |

## Why these design choices

- **Air-gapped by construction.** The customer is NCIIPC. A device config is a blueprint of a
  network's defences, and sending it to a cloud API is disqualifying, whatever the preference.
  This build makes no outbound call, and a test fails the build if any console asset tries to
  reach off the machine. The planned AI tiers use a local quantised model
  ([ADR 0003](docs/adr/0003-local-models-only.md)).
- **Rules are data, never code.** A control is a YAML file with its assertion, rationale, framework
  mappings and per-vendor remediation ([ADR 0002](docs/adr/0002-rules-as-data.md)).
- **A signed hash chain, not a blockchain.** There is one writer and no peers, so consensus would add
  weight and no integrity. Merkle roots, chaining and Ed25519 give tamper evidence that anyone can
  verify offline ([ADR 0006](docs/adr/0006-no-permissioned-blockchain.md)).
- **Remediation that won't lock you out.** Fixes are grouped into four phases: establish the safe
  path, harden, disable weak services, and only then restrict management access.

## Repository layout

| Path | Contents |
|------|----------|
| [backend/](backend/) | Python package `crucible`: ingestion, parsers, IR, policy engine, reports, ledger, CLI and FastAPI service |
| [frontend/public/](frontend/public/) | The audit console: plain HTML/CSS/JS served by the API, no build step ([ADR 0007](docs/adr/0007-plain-html-console.md)) |
| [rules/](rules/) | Compliance controls as YAML |
| [schemas/](schemas/) | Versioned JSON Schemas for the IR, rules and adapter packs |
| [docs/](docs/) | Specifications, execution plan, ADRs. Start at [docs/00-index.md](docs/00-index.md) |
| [adapters/](adapters/) | Vendor Adapter Pack format and a worked example |
| [labs/](labs/), [deploy/](deploy/) | containerlab topologies and the planned deployment stack (later phases) |

## Roadmap

| Phase | Headline | State |
|-------|----------|-------|
| 0 | Foundations: IR schema frozen, rule format, specs, ADRs | Done |
| 1 | Core pipeline end to end: real config in, line-cited signed PDF out | **Done** |
| 2 | The AI layer: structural inference, local-LLM mapping proposals, training GUI, adapter packs, XCCDF | Next |
| 3 | Fleet graph and attack-path-ranked remediation; measured precision/recall on a labelled corpus | Planned |
| 4 | Crucible: `crucible verify` confirms a finding live against a twin, offline | Planned |

Details: [docs/12-execution-plan.md](docs/12-execution-plan.md) · [CHANGELOG.md](CHANGELOG.md) ·
[docs/14-risk-register.md](docs/14-risk-register.md)

## Licence

[MIT](LICENSE). CIS Benchmark text is not reproduced in this repository or in generated reports.
See the third-party content notice in the licence file.
