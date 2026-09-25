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

## Implementation note — 25 Sep 2026

The decision held. What it looks like in the built system, where it differs from what was
anticipated above:

**The local model is real and measured.** `qwen2.5-coder:7b-instruct-q4_K_M`, served by Ollama on
loopback. On the held-out MikroTik vendor it reads **9 of 9 fields** where the deterministic
proposer reads 7, and it resolves both lines that one gets wrong. Roughly 116s for one device's
residue on a 4 GB laptop GPU with partial CPU offload — a per-vendor training cost, not a
per-audit one.

**Two proposers, not one.** Tier 2 has a deterministic TF-IDF proposer (words plus character
trigrams over a vocabulary built from the vendors already parsed) as well as the model. No
sentence-transformers and no vector store: the corpus is a few dozen field descriptions, where
lexical retrieval is both better and auditable. The deterministic proposer is the default, and
it makes the model an enhancement rather than a dependency — a deployment with no GPU still
learns vendors, more slowly and slightly less well.

**Loopback is enforced in the transport, not just the URL.** Validating the address was not
enough: `urlopen` reads `http_proxy` from the environment, so on a host with a corporate proxy —
the kind of host that also has an air gap — every prompt would have gone to that proxy. The
client is built with an empty `ProxyHandler`, and a test poisons the environment and fails if the
proxy is consulted.

**The model is opt-in.** `CRUCIBLE_OLLAMA=1` or `--ollama`. A model merely *listening* on
loopback is deliberately not adopted: an audit must give the same answer twice, and inheriting
whatever daemon happens to be running would make two machines disagree about one configuration.

**The model never sets its own confidence.** See ADR 0004 — the measurement that forced this is
recorded in [docs/16](../16-validation-plan.md).

**The bundle does not yet carry model weights.** It carries the product, every wheel and the twin
image; a deployment wanting the model installs Ollama and loads the weights alongside. Folding a
4.7 GB blob into the archive is mechanical and not yet done.
