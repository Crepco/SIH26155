# ADR 0006 — Hash-chained ledger instead of a permissioned blockchain

**Status:** Accepted · 25 Aug 2026 · Track E

## Context

The theme is *Blockchain & Cybersecurity*. The lazy reading is that a submission should contain a
chain. The honest reading is that an audit report issued by a national body must be provably
unaltered after issuance, and that is an integrity requirement, not a consensus requirement.

There is exactly one writer — the deployment that generated the report — and no distributed set of
mutually distrusting parties who must agree on ordering.

## Decision

Hash-chain findings into an append-only ledger, Merkle-root each report, sign it with Ed25519, and
print a verification hash in the PDF footer. No permissioned chain, no consensus protocol, no
peers.

Say so explicitly in the architecture document, and be prepared to defend it.

## Consequences

**Good.**

- The integrity property that is actually required is delivered: any alteration of a historical
  finding breaks the Merkle root, which breaks that ledger entry hash, which breaks every
  subsequent entry.
- Verification is offline and needs three things: the report, the ledger, and the issuing public
  key. That works in an air-gapped deployment years later.
- Nothing to operate. No peers, no availability requirement, no key ceremony beyond one signing
  key.

**Bad, and accepted.**

- A judge may expect the word blockchain and see its absence as a gap. The answer is a strength,
  not a defence: a chain adds operational weight for no additional integrity guarantee at this
  scale, and being able to explain why is worth more than a distributed ledger nobody can operate.
- Trust is anchored in one signing key rather than distributed across parties. Appropriate for a
  single-issuer audit tool; the ledger records key rotation so the chain stays continuous.
- Cross-organisation notarisation is out of scope. If NCIIPC later wants two hundred deployments
  to notarise into a shared log, the Merkle roots are already the right unit to publish — the
  design does not preclude it.
