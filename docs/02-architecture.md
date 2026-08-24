# 02 — Architecture

The whole design pivots on one idea: a **vendor-neutral intermediate representation** that sits
between parsing and everything else. Think of it as an LLVM IR for network security posture.
Parsers write into it; rules, reports, remediation and analysis read only from it.

Adding a vendor never touches the rules engine. Adding a benchmark never touches a parser.
That single property is what satisfies NTRO's "no manual code modification" scalability
requirement, and it is what makes the verification sandbox affordable.

## The pipeline

    config files (any vendor, single or bulk)
            |
            v
    [1] INGESTION + FINGERPRINTING        vendor - model - OS version - serial
            |
            v
    [2] PARSING CASCADE                   <-- this is where the "AI" actually lives
         Tier 0  known vendor -> deterministic parser
                 (ciscoconfparse, TextFSM/ntc-templates, Junos & PAN-OS XML)
            | unparsed lines fall through
         Tier 1  structural inference -> generic config tree
                 (detect brace / indent / flat-command grammar)
            | semantically unknown nodes fall through
         Tier 2  local LLM + embeddings PROPOSE A MAPPING
                 "set admintimeout 10"  ->  mgmt.idle_timeout_min
            | low confidence
         Tier 3  Interactive Training GUI -> admin confirms
                 -> persisted as a signed Vendor Adapter Pack (YAML)
                 -> on the next run this line is handled at Tier 0
            |
            v
    [3] NORMALISED SECURITY BASELINE MODEL (vendor-neutral JSON)
            |                              |
            v                              v
    [4] POLICY ENGINE                  [5] FLEET GRAPH
        CIS / NIST / STIG / ISO            cross-device correlation
        rules as versioned YAML            + attack-path queries
            |                              |
            +--------------+---------------+
                           v
    [6] REPORTING   per-device PDF + fleet report
                    pass/fail - severity - line-cited evidence
                    vendor-specific remediation CLI - signed & hash-chained
                           |
                           v
    [7] CRUCIBLE    render IR -> VyOS twin, demonstrate -> remediate
                    -> re-test -> regression

Everything downstream of stage 3 reads only the neutral model.

## Stage responsibilities

| Stage | Responsibility | Spec | Track |
|-------|----------------|------|-------|
| 1 | Accept single files, bulk uploads, archives and tech-support bundles. Determine vendor, model, OS version, serial. | [05](05-parsing-cascade.md) | A |
| 2 | Convert raw text into IR facts, with per-line accounting of what was and was not understood. | [05](05-parsing-cascade.md) | A, C |
| 3 | Hold the normalised model. Versioned, validated against JSON Schema, immutable once written. | [03](03-ir-schema.md) | A |
| 4 | Evaluate versioned YAML rules against IR facts and emit findings with evidence. | [04](04-rule-format.md) | B |
| 5 | Build the fleet graph, run cross-device correlations, rank remediation by paths severed. | [08](08-fleet-graph.md) | B |
| 6 | Render per-device and fleet reports; hash-chain, Merkle-root and sign them. | [10](10-reporting.md), [09](09-ledger-and-signing.md) | E |
| 7 | Boot a twin, demonstrate the finding, apply the fix, re-test, check blast radius. | [07](07-crucible-sandbox.md) | F |

## The five invariants

Architectural guarantees, stated in the architecture document and defended in Q&A. They are what
separate an audit tool from a chatbot with a file upload.

### 1. The AI never decides pass or fail. It only writes parsers.

The model's output is never a verdict — it is a *candidate extraction rule*: a regex, a path
expression, a field mapping. That rule is then applied deterministically to the raw text. The
verdict comes from the YAML policy engine operating on parsed facts.
**AI proposes; the deterministic engine disposes.**

### 2. Every finding carries line-level evidence.

Each finding records the file, the line number and the raw text that triggered it. Audits are
reproducible byte-for-byte. This is the answer to *"how do I know your AI didn't invent this?"* —
structurally, it cannot.

### 3. Fail closed. Unparsed input can never produce a pass.

Anything the engine could not interpret is reported as UNKNOWN, surfaced in the report, and
counted against coverage. A silent parser miss must never become a silent PASS on an unhardened
device.

### 4. Coverage is published, not hidden.

Every report states it plainly: *parsed 12,847 of 13,102 lines (98.1%); 255 lines uninterpreted,
listed in Appendix C.* Commercial tools hide this and create false confidence. We are the only
tool that tells you what it does not know.

### 5. Findings have three honest states, never two.

DEMONSTRATED (proven live against a twin), ASSERTED (rule matched, not runtime-testable), UNKNOWN
(could not parse). We never fabricate certainty we do not have.

## Differentiators beyond the baseline

**Air-gapped, and proven on stage.** Ollama serving a quantised model, local sentence-transformer
embeddings, no outbound calls. During the demo the machine is visibly disconnected and the audit
continues. See [11](11-air-gap.md).

**Learn a new vendor live, then export it.** The training loop emits a signed, portable Vendor
Adapter Pack. NCIIPC audits two hundred organisations; one of them buys a new vendor, trains the
parser once, publishes the pack, and all two hundred can audit the new hardware the next morning
— with no code written and no software update shipped. See [06](06-adapter-packs.md).

**Fleet attack-path graph.** Every tool in this category audits device by device, in isolation.
Breaches are emergent. A device can be one hundred per cent CIS-compliant while the network
remains trivially breachable. See [08](08-fleet-graph.md).

**Tamper-evident reports.** The theme is *Blockchain & Cybersecurity* and most teams will ignore
the blockchain half. We do not bolt on a gratuitous chain: findings are hash-chained into an
append-only ledger, each report is Merkle-rooted and signed, and a verification hash is printed
in the PDF footer. See [09](09-ledger-and-signing.md).

**Crucible — the verification sandbox.** The single element that makes this submission
structurally different. See [07](07-crucible-sandbox.md).

## Why Crucible is almost free, architecturally

We are already building two things that reduce it to a rendering problem:

1. A vendor-neutral IR — the normalised security baseline model.
2. A renderer that goes IR to vendor-specific CLI, because the remediation deliverable demands it.

We already render IR to Cisco IOS, IR to FortiOS, IR to Junos. We add **one more render target:
IR to VyOS**, a platform that boots as a container. That is the entire new capability. Because
the IR is the pivot, any audited device from any vendor becomes something we can boot, probe and
test. No other team has an IR, so no other team can do this. It is a capability that falls out of
good architecture — exactly the story the architecture document should tell.
