# ADR 0003 — All inference is local; no cloud model, ever

**Status:** Accepted · 25 Aug 2026 · Track C and Track F

## Context

The customer is NTRO, and NCIIPC sits under it protecting power grids, banking,
telecommunications, transport and government networks. A network device configuration is a
complete blueprint of an organisation defences: every ACL, every trust relationship, every
management interface, every credential hash.

For an NCIIPC-protected network, uploading that file to a commercial LLM API hosted in another
jurisdiction is not a policy preference to be weighed. It is a hard disqualifier. A solution that
depends on an internet-connected model is undeployable for the customer who wrote the problem
statement, at any level of technical quality.

## Decision

All inference runs on the deployment host. Ollama serving a quantised model, sentence-transformers
embeddings, a local embedded vector store. No outbound network call from any code path, at any
time, behind any flag. The offline installation bundle carries the model weights.

This is enforced, not intended: a cloud LLM SDK present in the dependency tree fails CI regardless
of whether anything calls it, and the full audit pipeline runs in an egress-blocked CI job from
Phase 1.

## Consequences

**Good.**

- The solution is deployable by the organisation that asked for it. Most submissions will not be.
- The demo has a moment nobody can copy in the final week: we disconnect the machine visibly and
  keep auditing.
- Determinism and privacy improve together — no request leaves, and no vendor changes a model
  under us mid-audit.

**Bad, and accepted.**

- A 7B quantised model is materially weaker than a frontier model. Mitigated by architecture
  rather than by hope: the model is invoked only on lines that survived Tiers 0 and 1, it proposes
  mappings rather than judgements, and low-confidence proposals go to a human. See ADR 0004.
- Inference is slower and hardware-dependent. Acceptable, because it runs on a small residue of
  each file rather than on the file.
- We give up any capability that only exists behind a cloud API. That is the price of being
  deployable, and it is the correct trade for this customer.
