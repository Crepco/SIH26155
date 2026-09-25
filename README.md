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

Across a fleet it also correlates devices into an attack-path graph, ranks remediation by the
paths each fix severs, and — where Docker is present — boots a disposable twin of a device to
**demonstrate** a finding rather than assert it. `crucible drift` says what moved between two
audits of the same device.

This happens through a browser console or a CLI. There is no cloud model, no outbound call, and
no database.

## Status: what is built and what is not

We would rather show a working foundation and an honest gap than claim features that don't run.

| | Component | Status |
|---|-----------|--------|
| ✅ | Ingestion: single files, bulk upload, directories, device bundles, zip archives (safe against path traversal and zip bombs) | **Built** |
| ✅ | Fingerprinting: vendor, OS, version, model and serial, with a confidence score | **Built** |
| ✅ | Tier-0 parsers: **Cisco IOS, Arista EOS, Fortinet FortiOS, Juniper Junos, MikroTik RouterOS, Palo Alto PAN-OS**, plus `show version` output | **Built** |
| ✅ | Vendor-neutral IR (JSON Schema v1.0.0, frozen), with per-fact provenance and line coverage accounting | **Built** |
| ✅ | Three-valued policy engine: 13 controls written as YAML, each mapped to **CIS v8, NIST SP 800-53, DISA STIG and ISO/IEC 27001** | **Built** |
| ✅ | XCCDF 1.1/1.2 importer: a DISA benchmark becomes rules the engine loads, through explicit bindings | **Built** |
| ✅ | Tier 1–3 learning: structural inference, a deterministic proposer plus **Qwen2.5-Coder-7B on loopback**, the training console, signed Vendor Adapter Packs with a trust store | **Built** |
| ✅ | Fleet attack-path graph: cross-device correlation, reachability, remediation ranked by paths severed | **Built** |
| ✅ | Crucible sandbox: boots a container twin, demonstrates the finding, applies the fix, re-tests, checks for lock-out | **Built** (needs Docker) |
| ✅ | Reports: JSON, Markdown and PDF, with line-cited evidence, safety-ordered remediation and a what-if score | **Built** |
| ✅ | Drift: what regressed, what was fixed, and which facts changed between two audits | **Built** |
| ✅ | Tamper-evident ledger: Merkle-rooted reports, hash chain, Ed25519 signatures, `verify` command | **Built** |
| ✅ | Audit console (browser) served by the API. No external assets, enforced by a test | **Built** |
| ✅ | Offline installation bundle, built and then verified by installing it with no package index | **Built** |
| ✅ | 227 tests, runnable without pytest | **Built** |
| ⏳ | A corpus of real configurations at scale (60+), and human review of the labels behind the accuracy numbers | In progress |
| ⏳ | Signing the bundle manifest; the multi-user compose deployment | Specified |

An unrecognised vendor produces an honest `UNKNOWN` for every control until someone teaches it
one. It is never reported as a pass.

### Measured, not claimed

Against six hand-labelled configurations (`crucible validate`):

| | |
|---|---|
| Precision | **1.00** — 37 true, 0 false positives |
| Recall | **0.90** — nothing missed as a PASS; 4 missed as UNKNOWN |
| Fact accuracy | **1.00** — 53 of 53 facts read with the labelled value |
| Mean coverage | 98.1% |

A miss that lands on `UNKNOWN` is a cautious miss: the auditor is told to look, not told it is
fine. Those are counted separately from false negatives, which is the number that would matter.
The labels are our own and not yet externally reviewed — `crucible validate` says so on every
run, and [docs/16](docs/16-validation-plan.md) gives the method.

### Teaching it a vendor it has never seen

The claim NTRO actually asked about. MikroTik's parser is held out of the build, and the
vocabulary the proposer learns from contains **no RouterOS syntax** — a test enforces that, so
this is transfer into an unfamiliar grammar rather than recall. `crucible tier2-eval`:

| Proposer | Fields read correctly |
|---|---|
| Lexical — the offline default, no model at all | 7 of 9 |
| `qwen2.5-coder:7b` running locally on loopback | **9 of 9** |

Both are deterministic and reproduce exactly. The model is optional and **off unless you ask for
it** (`CRUCIBLE_OLLAMA=1`), because an audit that changes its answer depending on what happens to
be installed is not an audit.

Measuring the model is also what caught the sharpest bug in the project: on an unseen Huawei
config it read `stelnet server enable` — VRP's *SSH* server — as Telnet, at 0.95 confidence,
which would have auto-installed a security-relevant inversion. A model's opinion of itself is
not a measurement, so confidence now comes from our own evidence and the model may only lower
it. Details in [docs/16](docs/16-validation-plan.md).

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

Expected last line: **`227 passed`**.

### 3. Run the audit console

```bash
python -m uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000
```

Open **<http://127.0.0.1:8000>** and click **Audit the sample fleet**. That audits six real
configurations from six vendors. Then:

1. Click **core-sw-01** in the fleet list.
2. Expand **CIS-NET-1.1.1 (Telnet)**. The device's own config appears at its real line numbers,
   with line 102 marked.
3. Look at **COVERAGE** (163 of 164 lines) and **NOT INTERPRETED** (the one line it could not
   read, shown verbatim).
4. Click the **UNKNOWN** filter. These are controls the engine refused to guess at.
5. Scroll to **REMEDIATION**, then open the signed PDF for that device at
   <http://127.0.0.1:8000/reports/cisco-ios-core-01.pdf>.
6. Switch to the **FLEET** view for the attack-path graph: which devices reach which, and which
   single fix severs the most paths.
7. Switch to the **TRAIN** view to see the lines no parser understood, grouped into families with
   a proposed mapping for each, a preview of exactly what accepting one would extract, and the
   pack it would be signed into.

You can also upload your own configurations with **Choose files**. You can switch Wi-Fi off before
any of this; nothing changes.

### 4. Or use the CLI

Run these from the `backend/` directory:

```bash
# Audit the six sample devices, write JSON + Markdown + PDF per device and a signed ledger
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports

# Check the ledger has not been altered
python -m crucible.api.cli verify ../reports/ledger.jsonl

# Only STIG-mapped controls (same parse, different framework)
python -m crucible.api.cli audit tests/fixtures/devices --rules ../rules/cis --out ../reports --framework STIG

# The vendor-neutral IR the rules actually read
python -m crucible.api.cli show tests/fixtures/devices/cisco-ios-core-01

# The loaded rule set
python -m crucible.api.cli rules --rules ../rules/cis

# Measure precision and recall against the hand-labelled configurations
python -m crucible.api.cli validate --labels ../corpus/labels/fixtures --devices tests/fixtures/devices

# What changed between two audits of the same device (exit 1 if posture regressed)
python -m crucible.api.cli drift before/core-sw-01.audit.json after/core-sw-01.audit.json
```

Three more, each needing something extra — a held-out vendor, a DISA benchmark, or Docker:

```bash
# Teach it a vendor: propose mappings for the lines nobody understood, then sign a pack
python -m crucible.api.cli propose tests/fixtures/devices/routeros-branch-01 --hold-out mikrotik

# Import a DISA STIG benchmark (XCCDF XML or the published zip)
python -m crucible.api.cli stig-import <benchmark.zip> --bindings ../rules/stig/bindings

# Prove a finding against a disposable twin instead of asserting it
python -m crucible.api.cli verify --device tests/fixtures/devices/cisco-ios-core-01 --finding CIS-NET-1.1.1
```

`audit` exits with code `1` when it finds serious findings and `2` when the audit could not run, so a
CI job can never confuse the two. Reports land in `reports/` at the repository root.

**Try the tamper check.** Open `reports/ledger.jsonl`, change one character in the second entry's
`merkle_root`, save, and run `verify` again. It reports `TAMPERED`: that entry's signature fails, and the next
entry's link to it breaks. Hiding the edit would mean re-signing every later entry, which needs the
issuing private key.

### What a run looks like

```
  CRUCIBLE 0.1.0   rules: 13 (digest 21785aa38a98facc)
  6 device(s)   fleet score 29%   mean coverage 97.3%

  core-sw-01
    cisco IOS 15.2(4)E10  serial FDO1234ABCD
    score  [#######.................] 31%  -> 92% after remediation
    checks fail 8  unknown 1  pass 4
    parsed 163/164 lines (99.4%)  1 uninterpreted
      FAIL critical CIS-NET-1.1.1  Telnet must be disabled on all management tr   running-config.txt:102
      FAIL critical CIS-NET-2.1.2  No default or well-known SNMP community stri   running-config.txt:87
      FAIL high     CIS-NET-1.3.1  Plaintext HTTP management interface must be    running-config.txt:39
```

Every failure cites a line. Every `UNKN` is a control we refused to guess at.

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `python` is 3.10 or older | On Windows use `py -3.11`, elsewhere `python3.11` |
| Port 8000 already in use | Add `--port 8010` and open that port instead |
| Console page is blank | Hard refresh (Ctrl+Shift+R). The CLI prints the same findings |
| `Form data requires "python-multipart"` | Install from `backend/requirements.txt`, not package by package |
| `make` targets | Optional shortcuts (`make test`, `make demo`, `make serve`, `make verify`, `make airgap-check`, `make bundle`), for Linux/macOS and Git Bash |
| Sandbox says "no Docker daemon" | Expected without Docker. Findings stay `ASSERTED`; the audit is otherwise unaffected |

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
     Tier 0  known vendor      -> deterministic parser                             built (6 vendors)
     Tier 1  structural infer  -> generic config tree                              built
     Tier 2  proposer PROPOSES a mapping (never a verdict)                         built
     Tier 3  training console  -> admin confirms -> signed Vendor Adapter Pack     built
        |
        v
[3] NORMALISED SECURITY BASELINE MODEL (vendor-neutral JSON IR)                    built
        |                                   |
        v                                   v
[4] POLICY ENGINE  (rules as YAML)      [5] FLEET GRAPH                            built | built
        |                                   |
        +-----------------+-----------------+
                          v
[6] REPORTING   per-device PDF, signed and hash-chained                           built
                          |
                          v
[7] CRUCIBLE    disposable twin -> demonstrate -> remediate -> re-test             built
```

The two-page summary is [docs/submission/ARCHITECTURE.md](docs/submission/ARCHITECTURE.md), and the full
design is in [docs/02-architecture.md](docs/02-architecture.md).

## The five invariants

These are guarantees built into the architecture, and the tests enforce them.

| # | Invariant | Consequence |
|---|-----------|-------------|
| 1 | **The AI never decides pass or fail.** It only writes parsers. | A proposal is a candidate extraction rule, applied deterministically. The AI proposes and the engine disposes. A model is never asked for a pattern, only to choose among candidates and point at the value token — so it cannot smuggle a regex into a pack. |
| 2 | **Every finding carries line-level evidence.** | File, line number and raw text. Audits reproduce byte for byte. |
| 3 | **Fail closed.** Unparsed input can never produce a pass. | Anything uninterpreted is reported `UNKNOWN` and counted against coverage. |
| 4 | **Coverage is published, not hidden.** | Every report states `parsed N of M lines` and lists the rest verbatim. |
| 5 | **Findings have three honest states, never two.** | `DEMONSTRATED` · `ASSERTED` · `UNKNOWN`. Only a finding proven against a live twin is `DEMONSTRATED`; with no Docker daemon, findings stay `ASSERTED` and never become a pass. |

## Mapping to the NTRO requirements

| NTRO component | Where it lives | Status |
|----------------|----------------|--------|
| 1. Unified Ingestion Engine | `backend/crucible/ingest`, `fingerprint` · console **Choose files** · `POST /audit` | **Built.** Single and bulk upload, bundles, archives. One unreadable device never aborts the fleet |
| 2. AI-Powered Training Module | `backend/crucible/training` · [adapters/](adapters/) · [docs/06](docs/06-adapter-packs.md) | **Built.** Tiers 1–3: structural inference, a deterministic proposer and an opt-in local Qwen2.5-Coder-7B, the training console, and signed adapter packs gated by a trust store. **9 of 9 fields on a held-out vendor** |
| 3. Multi-Framework Compliance Engine | `backend/crucible/policy` · [rules/](rules/) · [docs/04](docs/04-rule-format.md) | **Built.** 13 controls, one parse, `--framework` selects CIS v8 / NIST SP 800-53 / DISA STIG / ISO 27001. A DISA XCCDF benchmark imports into the same engine |
| 4. Actionable Intelligence & PDF Reporting | `backend/crucible/report`, `graph`, `ledger` · [docs/10](docs/10-reporting.md) | **Built.** Identity incl. serial, severity, line evidence, vendor CLI, signed PDF, and remediation ranked by the attack paths each fix severs |
| 5. Vendor-Agnostic Scalability | [schemas/ir](schemas/ir/) · rules as data · parser registry · [docs/03](docs/03-ir-schema.md) | **Built.** New rules need no code, and a new vendor needs no code either: it is taught through the training console and shipped as a signed pack |

## Why these design choices

- **Air-gapped by construction.** The customer is NCIIPC. A device config is a blueprint of a
  network's defences, and sending it to a cloud API is disqualifying, whatever the preference.
  This build makes no outbound call, and a test fails the build if any console asset tries to
  reach off the machine. The default proposer needs no model at all; where one is wanted, it is a
  local quantised model that the transport itself refuses to reach anywhere but loopback
  ([ADR 0003](docs/adr/0003-local-models-only.md)). `scripts/check-airgap.sh` enforces this over
  the dependency tree, and `scripts/verify-offline-bundle.sh` over a real installation.
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
| [labs/](labs/) | The Crucible twin image, and containerlab topologies for generating corpus configurations |
| [corpus/](corpus/) | Hand-labelled ground truth behind the accuracy numbers |
| [deploy/](deploy/) | [Offline bundle](deploy/OFFLINE-BUNDLE.md) and deployment notes |
| [scripts/](scripts/) | `check-airgap.sh`, `corpus-status.sh`, `build-offline-bundle.sh`, `verify-offline-bundle.sh` |

## Roadmap

| Phase | Headline | State |
|-------|----------|-------|
| 0 | Foundations: IR schema frozen, rule format, specs, ADRs | Done |
| 1 | Core pipeline end to end: real config in, line-cited signed PDF out | **Done** |
| 2 | The AI layer: structural inference, mapping proposals, training console, adapter packs, XCCDF | **Done** |
| 3 | Fleet graph and attack-path-ranked remediation; measured precision/recall | **Done** |
| 4 | Crucible: `crucible verify` confirms a finding live against a twin, offline | **Done** |
| 5 | Hardening: bulk performance, isolated failures, drift, the offline bundle | **Done** |
| — | A corpus of 60+ real configurations, and human review of the labels | In progress |

Details: [docs/12-execution-plan.md](docs/12-execution-plan.md) · [CHANGELOG.md](CHANGELOG.md) ·
[docs/14-risk-register.md](docs/14-risk-register.md)

## Licence

[MIT](LICENSE). CIS Benchmark text is not reproduced in this repository or in generated reports.
See the third-party content notice in the licence file.
