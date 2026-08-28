"""The append-only, hash-chained audit ledger.

Each entry commits to the hash of the previous entry. Altering a historical
finding changes its Merkle leaf, which changes the report root, which changes
that entry hash, which breaks every entry after it. Tamper-evidence by
construction, with no distributed consensus and no chain to operate.

This is the honest reading of *Blockchain & Cybersecurity*: an audit report
issued by a national body must be provably unaltered after issuance. That is an
integrity requirement, not a consensus one, and there is exactly one writer.
See ADR 0006 for why we do not ship a permissioned chain.

The ledger is a JSON-lines file. Append-only, greppable, and diffable - three
properties a database would have taken away for no benefit here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from crucible import CANONICALISATION_VERSION
from crucible.common.canonical import canonical_bytes, sha256_hex, utc_now_rfc3339
from crucible.common.errors import LedgerError
from crucible.ledger.signing import SigningKey, VerifyingKey

__all__ = ["Ledger", "LedgerEntry"]

GENESIS = "0" * 64


@dataclass(slots=True)
class LedgerEntry:
    """One issued report, committed to the chain."""

    seq: int
    timestamp: str
    report_id: str
    device_id: str
    merkle_root: str
    prev_entry_hash: str
    rule_set_digest: str
    ir_schema_version: str
    canonicalisation: str = CANONICALISATION_VERSION
    signature: str = ""
    key_id: str = ""

    def signing_material(self) -> dict[str, Any]:
        """Everything the signature covers - which is everything but itself."""
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "report_id": self.report_id,
            "device_id": self.device_id,
            "merkle_root": self.merkle_root,
            "prev_entry_hash": self.prev_entry_hash,
            "rule_set_digest": self.rule_set_digest,
            "ir_schema_version": self.ir_schema_version,
            "canonicalisation": self.canonicalisation,
        }

    @property
    def entry_hash(self) -> str:
        return sha256_hex(canonical_bytes(self.signing_material()))

    def to_dict(self) -> dict[str, Any]:
        data = self.signing_material()
        data["signature"] = self.signature
        data["key_id"] = self.key_id
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LedgerEntry":
        return cls(
            seq=int(data["seq"]),
            timestamp=str(data["timestamp"]),
            report_id=str(data["report_id"]),
            device_id=str(data["device_id"]),
            merkle_root=str(data["merkle_root"]),
            prev_entry_hash=str(data["prev_entry_hash"]),
            rule_set_digest=str(data["rule_set_digest"]),
            ir_schema_version=str(data["ir_schema_version"]),
            canonicalisation=str(data.get("canonicalisation", CANONICALISATION_VERSION)),
            signature=str(data.get("signature", "")),
            key_id=str(data.get("key_id", "")),
        )

    @property
    def verification_hash(self) -> str:
        """The short hash printed in the PDF footer.

        Short enough to read off a printed page and type into a verifier, long
        enough that forging a collision is not a weekend project.
        """
        return self.entry_hash[:16]


@dataclass(slots=True)
class Ledger:
    """A JSON-lines append-only log."""

    path: Path
    entries: list[LedgerEntry] = field(default_factory=list)

    @classmethod
    def open(cls, path: str | Path) -> "Ledger":
        target = Path(path)
        ledger = cls(path=target)
        if target.exists():
            for number, raw in enumerate(target.read_text(encoding="utf-8").splitlines(), 1):
                if not raw.strip():
                    continue
                try:
                    ledger.entries.append(LedgerEntry.from_dict(json.loads(raw)))
                except (json.JSONDecodeError, KeyError) as exc:
                    raise LedgerError(f"{target}:{number} is not a valid ledger entry: {exc}") from exc
        return ledger

    @property
    def head(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def append(
        self,
        *,
        report_id: str,
        device_id: str,
        merkle_root: str,
        rule_set_digest: str,
        ir_schema_version: str,
        key: SigningKey,
    ) -> LedgerEntry:
        entry = LedgerEntry(
            seq=len(self.entries) + 1,
            timestamp=utc_now_rfc3339(),
            report_id=report_id,
            device_id=device_id,
            merkle_root=merkle_root,
            prev_entry_hash=self.head,
            rule_set_digest=rule_set_digest,
            ir_schema_version=ir_schema_version,
            key_id=key.key_id,
        )
        entry.signature = key.sign(canonical_bytes(entry.signing_material()))
        self.entries.append(entry)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def verify(self, key: VerifyingKey | None = None) -> tuple[bool, list[str]]:
        """Walk the chain from genesis, checking links and signatures.

        Returns ``(ok, problems)`` rather than raising, because a verifier is
        most useful when it can report *everything* that is wrong with a ledger
        rather than stopping at the first break.
        """
        problems: list[str] = []
        previous = GENESIS

        for position, entry in enumerate(self.entries, start=1):
            if entry.seq != position:
                problems.append(f"entry {position}: sequence is {entry.seq}, expected {position}")
            if entry.prev_entry_hash != previous:
                problems.append(
                    f"entry {entry.seq}: chain broken - links to {entry.prev_entry_hash[:12]}, "
                    f"previous entry hashes to {previous[:12]}"
                )
            if key is not None:
                if not entry.signature:
                    problems.append(f"entry {entry.seq}: unsigned")
                elif not key.verify(canonical_bytes(entry.signing_material()), entry.signature):
                    problems.append(f"entry {entry.seq}: signature does not verify")
            previous = entry.entry_hash

        return (not problems), problems

    def find(self, report_id: str) -> LedgerEntry | None:
        for entry in self.entries:
            if entry.report_id == report_id:
                return entry
        return None

    def __iter__(self) -> Iterator[LedgerEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)
