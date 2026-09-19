"""Vendor Adapter Packs - learned vendor knowledge, signed and portable.

Deterministic by construction: a pack is data, applied the same way every
time. How a pack is *learned* (Tier 2 proposals, Tier 3 confirmation) lives in
:mod:`crucible.training`; this package never imports it.

Specification: docs/06-adapter-packs.md
"""

from crucible.adapters.apply import PackApplication, apply_pack, match_line
from crucible.adapters.pack import (
    AdapterPack,
    Mapping,
    TrustStore,
    export_ready,
    load_pack,
    load_packs,
    packs_for,
)

__all__ = [
    "AdapterPack",
    "Mapping",
    "PackApplication",
    "TrustStore",
    "apply_pack",
    "export_ready",
    "load_pack",
    "load_packs",
    "match_line",
    "packs_for",
]
