# 09 — Ledger, hash chaining and report signing

**Owner: Track E. Phase 3.**

The theme is *Blockchain & Cybersecurity* and most teams will ignore the blockchain half
entirely. We do not bolt on a gratuitous chain. We do the thing the word actually means in an
audit context: **an audit report issued by a national body must be provably unaltered after
issuance.** That is a genuine compliance requirement, not decoration.

## What we build

    finding -> canonical serialisation -> SHA-256 leaf
            |
            v
    per-report Merkle tree -> Merkle root
            |
            v
    append-only ledger entry:
        { seq, timestamp, report_id, merkle_root, prev_entry_hash, signature }
            |
            v
    entry hash = SHA-256(seq || timestamp || report_id || merkle_root || prev_entry_hash)
            |
            v
    PDF footer prints: report id, Merkle root prefix, ledger sequence, verification hash

Each ledger entry commits to the previous entry hash. Altering any historical finding changes its
leaf, which changes the Merkle root, which changes that entry hash, which breaks every subsequent
entry. Tamper-evidence by construction, with no distributed consensus and no chain to operate.

## Verification

    crucible verify-report AUDIT-2026-09-18-0042.pdf

recomputes the leaves from the stored findings, rebuilds the Merkle tree, compares the root
against the ledger, walks the chain to the current head, and checks the Ed25519 signature. It
runs offline, against a report that may be years old, on a machine that has only the ledger and
the public key.

An independent verifier needs three things and nothing else: the report, the ledger, and the
issuing public key.

## Canonicalisation, or the whole thing is worthless

A hash over a JSON document is only meaningful if the serialisation is deterministic. The rules:

- Keys sorted lexicographically, UTF-8, no insignificant whitespace.
- Floating point is not permitted anywhere in a hashed structure. Confidence values are stored as
  integers in basis points.
- Timestamps are RFC 3339 in UTC with a fixed number of digits.
- The signature field is excluded from the material it signs.
- The canonicalisation version is recorded in every ledger entry, so a future change does not
  invalidate historical verification.

## What is committed to

A leaf covers the finding **and its evidence**: rule id, rule file version, device serial,
verdict, severity, the cited file and line, the raw line text, the finding state, and the digest
of any proof artefact produced by Crucible. Signing the verdict without the evidence would leave
the interesting half unprotected.

The ledger also records the rule set version and the IR schema version used, so a report from
September can be explained in March when both have moved on.

## Keys

Ed25519 via the cryptography package. The signing key belongs to the deployment, is generated at
installation, never leaves the host, and is not in this repository — nor is any key material,
ever. Key rotation appends a rotation entry to the ledger so the chain stays continuous across
the rotation.

## What we deliberately do not build

**No permissioned blockchain.** A chain adds operational weight — consensus, peers, availability,
key ceremonies — for no additional integrity guarantee at this scale. Merkle chaining plus signing
gives the property that is actually required, and we say so plainly rather than over-claiming.
Being able to explain *why not* is worth more in Q&A than a distributed ledger nobody can operate.
