# 14 — Risk register

Reviewed at the start of every phase. A risk without a named mitigation and a named owner is not
a risk, it is a hope.

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **IR schema churns mid-build and breaks every track** | Fatal. Every track reads from it | Freeze by 27 Aug, version it, treat changes as breaking API changes with a migration. **This is the top project risk by a wide margin** | Track A |
| Crucible twins are wrong in hard-to-debug ways because normalisation is shaky | High. Wrong proofs are worse than no proofs | Crucible is Phase 4 for exactly this reason. It is a multiplier on a good IR, never a substitute for one. If the IR is not trustworthy by 20 Sep, Crucible does not start | Track F |
| Local model is too slow or too weak on a laptop | Medium | The model only proposes mappings for unparsed lines, a tiny fraction of input. Tier 0 handles the bulk deterministically. Benchmark a 7B quantised model in Phase 1 and fall back to embeddings-only if needed | Track C |
| Scope creep across forty vendors | High. Breadth eats depth | Six Tier-0 vendors, locked. Everything else is a training-loop demonstration, which is the stronger claim anyway | All |
| Demo failure on stage | High. One shot in front of judges | Recorded fallback video. Pre-booted containers. Rehearse twice on the actual demo machine | Track F |
| Another college team picks the same problem statement | Medium. Likely, since NTRO statements attract strong teams | Our defence is depth: the IR, the invariants and Crucible are not things a team can add in the final week | All |
| Corpus is too small or too synthetic to prove anything | High. Kills the accuracy claim | 60+ real configs across 8+ vendors in Phase 0, from containerlab, DevNet, ntc-templates fixtures and public dumps. Never demo on toy configs | Track A |
| Ground-truth labelling slips and we have no accuracy number | Medium | 20 configs hand-labelled in Phase 0, before there is any code to be distracted by. There is no shortcut here | Track A |
| Frontend bandwidth collapses and the training GUI is unfinished | High. The GUI is the artefact judges touch | Streamlit fallback specified from day one. API contracts frozen by 31 Aug so the frontend can build against mocks | Track D |
| Air-gap turns out to be aspirational when we test it | High. It is our headline claim | Egress-blocked CI job from Phase 1, not a manual check in September. The offline bundle is built by a script, never assembled by hand | Track F |
| A dependency cannot be vendored into the offline bundle | Medium | If it cannot be vendored, it cannot be a dependency. Decided at review time, not at packaging time | Track F |
| XCCDF import produces controls we cannot map to IR assertions | Medium | Unmapped controls import with identity and text intact, marked as requiring manual assertion, reported UNKNOWN. Never a silent PASS | Track B |
| Licensing objection over CIS Benchmark text in reports | Medium. Reputational, and an evaluator may well ask | Identifiers cited from our own metadata, our own rationale prose, full text quoted only from STIG and NIST. Stated explicitly in the architecture document | Track B |
| Neo4j adds operational weight we cannot afford in the bundle | Low | NetworkX fallback specified from day one; the graph model is store-agnostic | Track B |
| Someone commits real customer configuration data | High. It would be a genuine disclosure | `corpus/raw/` is gitignored, adapter export strips samples, and the pre-commit hook scans for credential patterns | All |

## The three that actually decide the project

1. **The IR freeze holds.** Everything else is recoverable. This is not.
2. **The baseline closes end to end in Phase 1.** A complete narrow pipeline beats a broad
   half-built one, every time.
3. **The air-gap claim survives being tested in public.** We are going to unplug the machine on
   stage. That has to be a demonstration, not a gamble.
