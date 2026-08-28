"""Merkle trees over findings.

One leaf per finding, one root per report. Altering any historical finding
changes its leaf, which changes the root, which breaks the ledger entry that
committed to it, which breaks every entry after that.

A leaf covers the finding **and its evidence**. Signing the verdict alone would
leave the interesting half unprotected: an attacker who could rewrite the cited
line number and raw text without breaking the root could make a report describe
a device that never existed.
"""

from __future__ import annotations

import hashlib
from typing import Any, Sequence

from crucible.common.canonical import canonical_bytes, sha256_hex

__all__ = ["leaf_hash", "merkle_root", "merkle_proof", "verify_proof"]

# Domain separation. Without distinct prefixes a leaf could be presented as an
# internal node, which is the classic second-preimage attack on Merkle trees.
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def leaf_hash(finding: dict[str, Any]) -> str:
    """Hash one finding, canonically serialised."""
    return hashlib.sha256(_LEAF_PREFIX + canonical_bytes(finding)).hexdigest()


def _pair(left: str, right: str) -> str:
    return hashlib.sha256(_NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaves: Sequence[str]) -> str:
    """Compute the root from ordered leaf hashes.

    An empty report still gets a root: a device with no findings is a real,
    signable audit result, and refusing to root it would mean the only reports
    that cannot be proven unaltered are the clean ones.
    """
    if not leaves:
        return sha256_hex(b"crucible-empty-report")

    level = list(leaves)
    while len(level) > 1:
        # An odd node is promoted rather than duplicated. Duplicating it is the
        # CVE-2012-2459 shape, where two different trees produce one root.
        nxt: list[str] = []
        for index in range(0, len(level) - 1, 2):
            nxt.append(_pair(level[index], level[index + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def merkle_proof(leaves: Sequence[str], index: int) -> list[tuple[str, str]]:
    """Inclusion proof for one leaf: a list of (side, hash) steps.

    This is what lets a single finding be proven to belong to a signed report
    without disclosing the rest of the report - useful when one finding has to
    be shared with a team that should not see the whole device audit.
    """
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf {index} out of range for {len(leaves)} leaves")

    proof: list[tuple[str, str]] = []
    level = list(leaves)
    position = index

    while len(level) > 1:
        nxt: list[str] = []
        for pair_index in range(0, len(level) - 1, 2):
            left, right = level[pair_index], level[pair_index + 1]
            if pair_index == position:
                proof.append(("right", right))
            elif pair_index + 1 == position:
                proof.append(("left", left))
            nxt.append(_pair(left, right))
        if len(level) % 2:
            nxt.append(level[-1])
        position = position // 2
        level = nxt

    return proof


def verify_proof(leaf: str, proof: list[tuple[str, str]], root: str) -> bool:
    current = leaf
    for side, sibling in proof:
        current = _pair(sibling, current) if side == "left" else _pair(current, sibling)
    return current == root
