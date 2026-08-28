"""Tamper-evident audit records.

Merkle-rooted reports, hash-chained into an append-only ledger, signed with
Ed25519. No permissioned blockchain - see ADR 0006 for why that would add
operational weight for no additional integrity guarantee at this scale.
"""

from crucible.ledger.chain import Ledger, LedgerEntry
from crucible.ledger.merkle import leaf_hash, merkle_proof, merkle_root, verify_proof
from crucible.ledger.signing import SigningKey, VerifyingKey, load_or_create_key

__all__ = [
    "Ledger",
    "LedgerEntry",
    "SigningKey",
    "VerifyingKey",
    "leaf_hash",
    "load_or_create_key",
    "merkle_proof",
    "merkle_root",
    "verify_proof",
]
