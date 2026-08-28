"""Canonical serialisation.

A hash over a JSON document is only meaningful if the serialisation is
deterministic. Without this module the ledger is decoration: two runs would
produce two Merkle roots for the same findings and verification would be
meaningless.

Rules, from docs/09-ledger-and-signing.md:

- Keys sorted lexicographically, UTF-8, no insignificant whitespace.
- Floating point is not permitted anywhere in a hashed structure.
- Timestamps are RFC 3339 in UTC with a fixed number of digits.
- The signature field is excluded from the material it signs.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from typing import Any

from crucible import CANONICALISATION_VERSION

__all__ = [
    "CANONICALISATION_VERSION",
    "canonical_bytes",
    "canonical_json",
    "sha256_hex",
    "utc_now_rfc3339",
]


def _reject_floats(value: Any, path: str = "$") -> None:
    """Floats are banned, not rounded.

    Rounding would hide the problem until two platforms disagreed about the last
    bit and a historical report stopped verifying. Confidence is carried in
    basis points precisely so that nothing here ever needs a float.
    """
    if isinstance(value, float):
        raise TypeError(
            f"float at {path}: canonical structures must not contain floating point "
            "(use integer basis points)"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"non-string key at {path}: {key!r}")
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")


def canonical_json(value: Any) -> str:
    """Serialise deterministically. Same input, same bytes, every time."""
    _reject_floats(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def utc_now_rfc3339() -> str:
    """RFC 3339 in UTC, seconds precision, fixed width.

    Fixed width matters: a variable number of fractional digits would make the
    same instant serialise two ways and break reproducibility.
    """
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
