# 13 — Technology stack

Every choice below is justified against one of three constraints: it must **run fully offline**,
it must **keep the AI layer separable from the deterministic layer**, or it must be **buildable
by six students in three weeks**. A dependency that fails all three does not enter the tree.

## Ingestion and fingerprinting

| Component | Choice | Why |
|-----------|--------|-----|
| Config parsing entry | Plain file I/O + zipfile | Upload is the primary path; the demo must never depend on hardware being in the room |
| Live device pull (stretch) | Netmiko, NAPALM | As suggested in the problem statement. Useful for the deployment story, not for the demo |
| Fingerprinting | Custom heuristics over header lines | Vendor, model, OS version from config headers; serial from `show version` in the uploaded bundle |

## Parsing cascade — Tier 0 (deterministic)

| Component | Choice | Why |
|-----------|--------|-----|
| Cisco IOS / Arista EOS | `ciscoconfparse2` | Purpose-built for IOS-style hierarchical configs; Arista EOS is close enough to reuse |
| Structured CLI output | TextFSM + `ntc-templates` | Hundreds of maintained templates for show-command output — and its test fixtures double as our config corpus |
| Junos / PAN-OS | `lxml` | Both expose XML representations; parse the tree rather than the CLI text |
| FortiOS / MikroTik | Custom block and flat-command parsers | Small, well-defined grammars. Roughly 200 lines each |

## Parsing cascade — Tiers 1 to 3 (the AI layer)

| Component | Choice | Why |
|-----------|--------|-----|
| Local model runtime | **Ollama** + Qwen2.5-Coder-7B (or Llama 3.1 8B), quantised | The air-gap requirement is non-negotiable. A coder-tuned model reasons about CLI syntax better than a general chat model |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2) | Small, fast, fully local. Powers similarity transfer: a command learned on Vendor A suggests a mapping for a structurally similar command on Vendor B |
| Vector store | ChromaDB or FAISS | Local, embedded, no server. Chroma is faster to build against; FAISS is faster at scale |
| Structural inference | Custom tokeniser | Detects brace / indent / flat-command grammar. Deterministic, no model needed — this tier exists specifically to reduce how often we invoke the model |
| Adapter packs | YAML + Ed25519 signatures (`cryptography`) | Portable, human-readable, verifiable provenance. Signing matters because a pack is executable knowledge |

Note the discipline: the model is invoked only on lines that survived Tiers 0 and 1 — typically a
very small fraction of a file. That is what makes a 7B model on a laptop viable, and it is also
why context limits never become a problem.

## Compliance engine

| Component | Choice | Why |
|-----------|--------|-----|
| Rule format | YAML, versioned per framework | Rules as data, never code. Adding a framework is adding files. Directly satisfies the "no manual code modification" requirement |
| Evaluator | Custom expression evaluator over the IR | A small, auditable assertion language. OPA/Rego is the more impressive answer if time allows, but YAML ships faster and is easier to defend |
| STIG ingestion | XCCDF XML importer (`lxml`, external entities disabled) | STIGs are machine-readable. One importer yields 300+ real controls |
| Severity model | CVSS-informed, framework-mapped | Each rule carries its native severity plus cross-framework control identifiers |

## Fleet graph and correlation

| Component | Choice | Why |
|-----------|--------|-----|
| Graph store | **Neo4j** (NetworkX fallback) | Cypher path queries are exactly the primitive we need, and the team already has working experience with Neo4j-backed attack-path analysis |
| Reachability (optional) | **Batfish** | Open source, purpose-built for multi-vendor reachability and ACL analysis. Calling it for hard reachability mathematics is strictly better than reimplementing it — and knowing it exists is itself a credibility marker |

## Crucible verification sandbox

| Component | Choice | Why |
|-----------|--------|-----|
| Emulation target | **VyOS** (FRR as fallback) | Boots as a container in seconds, fully scriptable, free. The single render target the whole sandbox pivots on |
| Orchestration | **containerlab** + Docker | Declarative topologies, ephemeral labs, isolated bridge networks, trivial teardown |
| Probe library | nmap, ssh, snmpwalk, curl, scapy | Standard, well-understood tools. Their output *is* the proof artefact |
| Capture | tcpdump to pcap, attached to each finding | Turns a demonstration into a durable, auditable artefact inside the report |

## Reporting, ledger and application

| Component | Choice | Why |
|-----------|--------|-----|
| PDF generation | **ReportLab** | Suggested in the problem statement itself, pure Python, no system dependencies — which matters for an offline installation bundle |
| Audit ledger | Merkle hash-chained append-only log + Ed25519 | Tamper-evident by construction. Satisfies the Blockchain & Cybersecurity theme honestly, without a gratuitous chain |
| Backend | **FastAPI** + SQLAlchemy + PostgreSQL | Async, typed, auto-generated API docs. Postgres because IR documents are JSONB and query well |
| Job queue | Celery + Redis (or RQ) | Bulk audits of 200 configs are embarrassingly parallel; parsing must not block the request thread |
| Frontend | **Next.js** + React + Tailwind + shadcn/ui | The training GUI is the artefact judges will physically touch — it has to feel finished. Streamlit is the fallback only if frontend bandwidth collapses |
| Graph visualisation | Cytoscape.js or react-force-graph | The fleet attack-path view is a pitch centrepiece; it must render cleanly on a projector |
| Packaging | Docker Compose, offline bundle with pre-pulled models | "Air-gapped" has to mean an installer that works with the cable unplugged, not an aspiration |

## Data sources

| What we need | Where it comes from |
|--------------|---------------------|
| Real multi-vendor configurations | containerlab (Arista cEOS, Nokia SR Linux, FRR, SONiC, VyOS — all on one laptop); MikroTik CHR and pfSense in VMs; Cisco DevNet always-on sandboxes; ntc-templates test fixtures; public config dumps on GitHub. **Do not demo on synthetic toy configs** — evaluators can tell |
| Compliance rule content | DISA STIGs as XCCDF XML (machine-readable, US government publication, safe to quote). NIST SP 800-53 control text. CIS Benchmark control **identifiers** cited deterministically from our own metadata; full CIS text not reproduced, for licensing reasons |
| Ground truth for accuracy | 20 configurations hand-labelled by the team in Phase 0. There is no substitute and no shortcut |

## What we deliberately are not using

- **No cloud LLM API.** Not OpenAI, not Anthropic, not Gemini. It would disqualify the solution
  for the customer who wrote the problem statement, and *we can swap it later* is not an
  architecture.
- **No RAG over standards text for generating remediation commands.** Retrieval reintroduces
  hallucination exactly where we can least afford it — in the CLI an administrator will paste
  into a production firewall. Control identifiers are cited deterministically from rule metadata;
  remediation commands live in the versioned rule files. Retrieval is used only for background
  rationale prose, clearly labelled as such.
- **No blockchain beyond the hash-chained ledger.** A permissioned chain adds operational weight
  for no additional integrity guarantee at this scale. Merkle chaining plus signing is the honest
  engineering answer, and we should say so rather than over-claim.
- **No attempt at full-fidelity vendor emulation.** Security properties reproduce; feature parity
  does not, and we do not pretend otherwise.

> **The sentence the whole stack exists to make true.**
> Every compliance tool tells you what is wrong. Ours proves it, fixes it, and proves the fix did
> not break anything — against a disposable digital twin, fully air-gapped.
