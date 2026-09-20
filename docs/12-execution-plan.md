# 12 — Execution plan

> ## Status, 21 September 2026
>
> This document is the plan as written on 25 August, kept as a record. What actually happened:
>
> | Phase | Planned | Outcome |
> |-------|---------|---------|
> | 0 · Foundations | 25–31 Aug | **Done** |
> | 1 · Core pipeline | 1–7 Sep | **Done** |
> | 2 · The AI layer | 8–14 Sep | **Done** |
> | 3 · Differentiators | 15–19 Sep | **Done** |
> | — · Idea submission | 20 Sep | **Submitted** |
> | 4 · Crucible sandbox | 21 Sep onward | **Done** |
> | 5 · Hardening | Pre-finale | **Done** |
>
> Three places where the build deviated from the plan below, each deliberate:
>
> * **13 CIS controls, not ~40.** Each one is mapped to four frameworks, carries per-vendor
>   remediation, and is checked against hand-labelled ground truth. Forty thinner controls would
>   have read better and meant less. The XCCDF importer is the answer to breadth.
> * **The twin is an Alpine container built here, not VyOS via containerlab**
>   ([ADR 0008](adr/0008-alpine-twin.md)). We control what is installed, it boots in a second,
>   and it ships in the offline bundle.
> * **The console is plain HTML served by the API, not Next.js**
>   ([ADR 0007](adr/0007-plain-html-console.md)). No build step, and nothing to fetch.
> * **Bulk audits are not parallelised**, though Phase 5 called for it. Profiling a 200-device job
>   found 110.9s of its 2m6s in fleet correlation, which was running one path search per
>   (entry point, target, service). One breadth-first sweep per (segment, port) gives identical
>   findings, and **200 devices now audit in 2.6s — 13 ms each**. Adding a worker pool to that
>   would buy nothing and cost a broker, a process model and a class of bug we currently cannot
>   have. Fixing the algorithm was the cheaper answer.
>
> Still open, and named as such in the README: a corpus of 60+ real configurations, and human
> review of the labels behind the accuracy numbers.

Today is 25 August 2026. Idea submission closes 20 September 2026 — roughly three and a half
weeks. The internal college round comes before that. This plan is cut against those real dates,
not a generic ten-week roadmap.

> **The one rule that governs the whole build.** The baseline ships first, end to end, before any
> differentiator is started. A working pipeline across three vendors with one framework beats a
> half-finished feature list every time. Every differentiator here is additive and independently
> droppable — if a phase slips, we drop the last item, never the foundation. Depth plus a
> credible extensibility story reads as engineering maturity; breadth claims read as slideware.

## 12.1 Scope decision, made now and not revisited

| Dimension | In scope for submission | Explicitly out of scope |
|-----------|------------------------|-------------------------|
| Vendors (Tier-0 parsers) | Cisco IOS, Juniper Junos, Fortinet FortiOS, Arista EOS, Palo Alto PAN-OS, MikroTik RouterOS — six, done properly | The other 34 named vendors. They are handled by the training loop, which is the point |
| Frameworks | CIS (hand-authored, ~40 controls) + DISA STIG (bulk-imported from official XCCDF XML) | Full NIST 800-53 and ISO 27001 coverage — we demonstrate the mapping, not the totality |
| Live device access | File upload as the primary path. Netmiko/NAPALM pull is a stretch goal | Any demo that depends on real hardware being present in the room |
| Emulation | VyOS containers via containerlab, 6 to 8 probe types, HIGH/CRITICAL findings only | Full-fidelity vendor emulation. We are not rebuilding GNS3 |

Bulk-importing DISA STIGs is the highest-leverage half-day in the entire plan: STIGs ship as
machine-readable XCCDF XML, so one importer yields 300+ real controls instead of forty hand-typed
ones. That is the difference between claiming multi-framework support and demonstrating it.

## 12.2 Team allocation

Six members. Ownership is exclusive — one person accountable per track — but the two integration
points (IR schema and rule format) are frozen jointly on day three and treated as contracts after
that. Full table in [CONTRIBUTING.md](../CONTRIBUTING.md).

## 12.3 Phase plan

### PHASE 0 · 25 to 31 Aug · Foundations

- Freeze the IR schema. The single most consequential artefact in the project — every other track
  reads from it. Version it from commit one.
- Freeze the YAML rule format. Write three rules by hand to prove the format survives contact
  with reality.
- Build the config corpus: containerlab (Arista cEOS, FRR, SONiC, VyOS), MikroTik CHR and pfSense
  in VMs, Cisco DevNet always-on sandboxes, ntc-templates test fixtures, public config dumps on
  GitHub. Target 60+ real configuration files across 8+ vendors.
- Hand-label ground truth on 20 of those configs. Without this we can never state an accuracy
  number.
- Repository, CI, issue board, branch conventions.

**Definition of done** — IR schema v1.0 frozen and documented; 60+ real configs collected; 20
labelled.

### PHASE 1 · 1 to 7 Sep · Core pipeline, end to end

- Ingestion: single and bulk upload, zip/folder, config + show-output bundles. Device
  fingerprinting including serial extraction from `show version`.
- Tier-0 parsers for the first three vendors (Cisco IOS, Junos, FortiOS) writing into the IR.
- Coverage accounting from the very first parser — parsed versus total lines per device.
  Retrofitting this later is painful.
- Rule evaluator + 40 hand-authored CIS controls.
- First PDF report: device identity, pass/fail, severity, line-cited evidence, vendor-specific
  remediation.
- Air-gapped packaging from day one: Ollama pinned, models pre-pulled, no outbound calls in any
  code path.

**Definition of done** — Upload a real Cisco config, get a correct, line-cited PDF. The whole loop
closed.

### PHASE 2 · 8 to 14 Sep · The AI layer, the part NTRO actually asked for

- Tier 1 structural inference: detect brace / indent / flat-command grammar on unknown formats.
- Tier 2: sentence-transformer embeddings + local LLM proposing candidate field mappings with
  confidence scores. **The model outputs mappings, never verdicts.**
- Tier 3 training GUI: surface raw unrecognised lines, admin maps them, mapping persists.
- Adapter pack export/import, signed. Prove it: train on a vendor in instance A, import into
  instance B.
- Three more Tier-0 parsers (Arista, PAN-OS, MikroTik).
- XCCDF importer for DISA STIGs.

**Definition of done** — Hold out MikroTik entirely, feed it in cold, train it live in under three
minutes, export the pack.

### PHASE 3 · 15 to 19 Sep · Differentiators and internal round readiness

- Fleet graph: build the device/interface/VLAN/ACL graph, implement four cross-device
  correlations (management plane exposure, NTP authentication drift, credential reuse, ACL
  shadowing).
- Attack-path ranking of remediation — fixes ordered by paths severed.
- Hash-chained ledger + report signing + verification hash in the PDF footer.
- Remediation safety: ordering to prevent self-lockout, rollback per step, what-if simulator
  projecting the post-remediation compliance score.
- Precision/recall measured against the 20 labelled configs. One hard number.
- Demo rehearsal, twice, with a recorded fallback video.

**Definition of done** — A demo that survives a live audience, and a real accuracy figure to quote.

### MILESTONE · 20 Sep · Idea submission closes

- Two-page architecture document — lead with the IR pivot and the five invariants.
- Five-slide deck: (1) problem and why current approaches fail, (2) architecture and the parsing
  cascade, (3) the differentiators, (4) measured results, (5) deployment path for NCIIPC.
- Two-minute demo video — scripted, not improvised.
- README with genuine setup instructions someone else can follow cold.

**Definition of done** — All four artefacts submitted, each visibly mapped to the five-component
list in the problem statement.

### PHASE 4 · 21 Sep onward · Crucible, the verification sandbox

- IR to VyOS renderer. The one new render target that makes everything else possible.
- containerlab harness: boot, configure, probe, tear down. Isolated bridge, no egress, ephemeral.
- Probe library: telnet reachability, weak SSH KEX/cipher, default SNMP community, exposed HTTP
  management, ACL bypass from untrusted segment, session timeout, NTP authentication.
- Four-phase verification run: demonstrate, remediate, re-test, regression.
- Three-state finding model wired through the report: DEMONSTRATED / ASSERTED / UNKNOWN.
- Run the sandbox across the entire corpus as a parser self-test; publish the resulting precision
  figure.

**Definition of done** — `crucible verify --finding CIS-NET-1.2.1` confirms a finding live, in
under fifteen seconds, offline.

### PHASE 5 · Pre-finale · Hardening and polish

- Bulk performance: 200 configs in a single job, parallelised.
- Drift tracking across successive snapshots per device.
- UX pass on the dashboard and the training GUI — the training GUI is the thing judges will touch.
- Full documentation, deployment guide, and an offline installation bundle.
- Q&A drilling against the objection list in [01](01-problem-statement.md) and
  [17](17-competitive-landscape.md).

**Definition of done** — Something that looks like a product, not a prototype.
