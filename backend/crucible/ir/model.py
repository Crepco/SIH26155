"""The IR document, and how a rule reads a value out of it.

The single most important behaviour in this file is the difference between a
field that is ``None`` and a field that was never observed. A rule asking about
``mgmt.telnet_enabled`` on a device where nothing about Telnet was ever parsed
must get "I do not know", not "false". Collapsing those two is precisely how a
compliance tool reports a clean audit on a device that was never checked.

:class:`Resolution` carries that distinction, and the evaluator refuses to
guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from crucible import IR_SCHEMA_VERSION
from crucible.common.types import Provenance

__all__ = ["Coverage", "IRDocument", "Resolution", "split_path"]

_INDEXED = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$")


def split_path(path: str) -> list[str | int]:
    """``interfaces[1].acl_in`` becomes ``['interfaces', 1, 'acl_in']``."""
    parts: list[str | int] = []
    for segment in path.split("."):
        match = _INDEXED.match(segment)
        if match:
            parts.append(match.group(1))
            parts.append(int(match.group(2)))
        else:
            parts.append(segment)
    return parts


@dataclass(frozen=True, slots=True)
class Resolution:
    """The result of looking a path up in the IR.

    ``found`` answers "did a parser ever write here?". ``value`` answers "what
    did it write?". A rule needs both, because ``found=False`` must produce
    UNKNOWN while ``found=True, value=None`` is a parser explicitly recording
    that a thing is absent.
    """

    path: str
    value: Any
    found: bool
    provenance: Provenance | None = None

    @property
    def known(self) -> bool:
        """True when the value can take part in a comparison."""
        return self.found and self.value is not None

    @classmethod
    def missing(cls, path: str) -> Resolution:
        return cls(path=path, value=None, found=False, provenance=None)


@dataclass(slots=True)
class Coverage:
    """Invariants 3 and 4, in one small object.

    ``parsed + unparsed == total`` is asserted here rather than trusted, because
    it is the arithmetic that makes the published coverage figure honest. If a
    parser silently drops lines, this is where it shows up.
    """

    total_lines: int = 0
    parsed_lines: int = 0
    unparsed_lines: int = 0
    by_tier: dict[str, int] = field(
        default_factory=lambda: {"tier0": 0, "tier1": 0, "tier2": 0, "tier3": 0}
    )
    #: (file, line, raw) for every line nothing understood. Printed verbatim in
    #: Appendix C, which is what turns invariant 3 from a claim into something a
    #: reader can check.
    unparsed_sample: list[dict[str, Any]] = field(default_factory=list)

    @property
    def percent(self) -> float:
        if self.total_lines == 0:
            return 0.0
        return round(100.0 * self.parsed_lines / self.total_lines, 1)

    def check(self) -> None:
        if self.parsed_lines + self.unparsed_lines != self.total_lines:
            raise AssertionError(
                "coverage does not add up: "
                f"{self.parsed_lines} parsed + {self.unparsed_lines} unparsed "
                f"!= {self.total_lines} total"
            )

    def statement(self) -> str:
        """The sentence printed in every report."""
        return (
            f"parsed {self.parsed_lines:,} of {self.total_lines:,} lines "
            f"({self.percent}%); {self.unparsed_lines:,} lines uninterpreted"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "unparsed_lines": self.unparsed_lines,
            "by_tier": dict(self.by_tier),
            "unparsed_sample": list(self.unparsed_sample),
        }


@dataclass(slots=True)
class IRDocument:
    """One device, normalised.

    Everything downstream of parsing reads this and nothing else - no raw text,
    no vendor-specific structures. That rule is what makes adding a vendor free
    for the rules engine and adding a benchmark free for the parsers.
    """

    device: dict[str, Any] = field(default_factory=dict)
    sections: dict[str, Any] = field(default_factory=dict)
    coverage: Coverage = field(default_factory=Coverage)
    provenance: dict[str, Provenance] = field(default_factory=dict)
    schema_version: str = IR_SCHEMA_VERSION
    #: Redacted source lines, per file, kept so a finding can be shown in the
    #: block it came from. Deliberately excluded from :meth:`to_dict` - the IR
    #: is a model of security posture, not a copy of the configuration, and an
    #: exported IR should not smuggle the whole device out with it.
    sources: dict[str, list[str]] = field(default_factory=dict, repr=False)

    # -- reading ----------------------------------------------------------

    def resolve(self, path: str) -> Resolution:
        """Look up a dotted IR path.

        Never raises for a missing path: absence is a normal, meaningful answer
        in this system, and turning it into an exception would tempt callers
        into treating it as false.
        """
        parts = split_path(path)
        if not parts:
            return Resolution.missing(path)

        root_name = parts[0]
        current: Any
        if root_name == "device":
            current = self.device
        elif isinstance(root_name, str) and root_name in self.sections:
            current = self.sections[root_name]
        else:
            return Resolution.missing(path)

        for part in parts[1:]:
            if isinstance(part, int):
                if not isinstance(current, list) or part >= len(current):
                    return Resolution.missing(path)
                current = current[part]
            else:
                if not isinstance(current, dict) or part not in current:
                    return Resolution.missing(path)
                current = current[part]

        return Resolution(
            path=path, value=current, found=True, provenance=self.provenance.get(path)
        )

    def excerpt(self, file: str, line: int, radius: int = 3) -> tuple[tuple[int, str, bool], ...]:
        """The lines around a citation, with the cited one marked."""
        lines = self.sources.get(file)
        if not lines:
            return ()
        start = max(1, line - radius)
        end = min(len(lines), line + radius)
        return tuple((n, lines[n - 1], n == line) for n in range(start, end + 1))

    def facts(self) -> dict[str, Provenance]:
        """Every path a parser wrote, with where it came from."""
        return dict(self.provenance)

    # -- identity ---------------------------------------------------------

    @property
    def vendor(self) -> str:
        return str(self.device.get("vendor") or "unknown")

    @property
    def hostname(self) -> str:
        return str(self.device.get("hostname") or self.device.get("serial") or "unnamed-device")

    @property
    def serial(self) -> str | None:
        value = self.device.get("serial")
        return str(value) if value else None

    # -- serialisation ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {"schema_version": self.schema_version, "device": self.device}
        document.update(self.sections)
        document["coverage"] = self.coverage.to_dict()
        document["provenance"] = {k: v.to_dict() for k, v in sorted(self.provenance.items())}
        return document
