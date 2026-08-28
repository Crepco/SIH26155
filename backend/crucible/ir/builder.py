"""The only supported way to write into the IR.

Two things are enforced here rather than remembered:

1. **No fact without provenance.** :meth:`IRBuilder.set` requires a source line.
   A parser cannot record a value it cannot cite, so invariant 2 holds by
   construction instead of by review.

2. **Every line is accounted for.** A parser calls :meth:`claim` for each line it
   consumed. Anything left over at :meth:`build` time is counted as unparsed and
   listed verbatim in the report. A parser that silently skips lines produces a
   coverage figure that visibly does not add up.
"""

from __future__ import annotations

from typing import Any

from crucible.common.redaction import redact
from crucible.common.types import Provenance
from crucible.ir.model import Coverage, IRDocument, split_path

__all__ = ["IRBuilder"]

#: How many uninterpreted lines are carried into the report verbatim. The count
#: is always exact; this caps only the appendix listing.
MAX_UNPARSED_SAMPLE = 250


class IRBuilder:
    """Accumulates facts and line accounting for one device."""

    def __init__(self) -> None:
        self._device: dict[str, Any] = {}
        self._sections: dict[str, Any] = {}
        self._provenance: dict[str, Provenance] = {}
        # file -> {line number -> raw text} for every line the file contained
        self._lines: dict[str, dict[int, str]] = {}
        # file -> {line number -> tier that claimed it}
        self._claimed: dict[str, dict[int, int]] = {}

    # -- line accounting --------------------------------------------------

    def register_file(self, filename: str, lines: list[str]) -> None:
        """Declare every line of a source file before parsing it.

        Called by the ingest layer so that the denominator of the coverage
        figure is fixed before any parser gets an opinion about it.
        """
        self._lines.setdefault(filename, {})
        self._claimed.setdefault(filename, {})
        for index, raw in enumerate(lines, start=1):
            self._lines[filename][index] = raw

    def claim(self, filename: str, line: int, tier: int = 0) -> None:
        """Record that a parser understood this line.

        Claiming a blank line or a comment is correct and expected: they are
        part of the file, and pretending otherwise would inflate coverage.
        """
        if filename not in self._lines:
            raise KeyError(f"file not registered before parsing: {filename}")
        if line not in self._lines[filename]:
            raise KeyError(f"{filename} has no line {line}")
        previous = self._claimed[filename].get(line)
        # First claim wins. Tier 0 is deterministic; a later tier must never
        # overwrite a deterministic reading of the same line.
        if previous is None or tier < previous:
            self._claimed[filename][line] = tier

    def claim_range(self, filename: str, start: int, end: int, tier: int = 0) -> None:
        for line in range(start, end + 1):
            self.claim(filename, line, tier)

    def raw_line(self, filename: str, line: int) -> str:
        return self._lines.get(filename, {}).get(line, "")

    # -- facts ------------------------------------------------------------

    def set(
        self,
        path: str,
        value: Any,
        *,
        file: str,
        line: int,
        tier: int = 0,
        adapter_pack: str | None = None,
        confidence_bp: int = 10000,
        claim: bool = True,
    ) -> None:
        """Write one fact, with the line that justifies it.

        The raw text is captured from the registered source and redacted before
        storage: evidence must be quotable in a report that may be handed to
        someone who should not see a credential hash.
        """
        raw = redact(self.raw_line(file, line))
        provenance = Provenance(
            file=file,
            line=line,
            raw=raw,
            tier=tier,
            adapter_pack=adapter_pack,
            confidence_bp=confidence_bp,
        )
        self._write(path, value)
        self._provenance[path] = provenance
        if claim:
            self.claim(file, line, tier)

    def append(
        self,
        path: str,
        value: Any,
        *,
        file: str,
        line: int,
        tier: int = 0,
        claim: bool = True,
    ) -> int:
        """Append to a list-valued path and return the index written.

        The index is returned so a caller can record provenance for the element
        it just added - ``interfaces[3].acl_in`` rather than ``interfaces``.
        """
        parts = split_path(path)
        container = self._container_for(parts, create=True)
        key = parts[-1]
        existing = container.get(key) if isinstance(container, dict) else None
        if existing is None:
            existing = []
            container[key] = existing  # type: ignore[index]
        if not isinstance(existing, list):
            raise TypeError(f"{path} is not a list")
        existing.append(value)
        index = len(existing) - 1
        raw = redact(self.raw_line(file, line))
        self._provenance[f"{path}[{index}]"] = Provenance(
            file=file, line=line, raw=raw, tier=tier
        )
        if claim:
            self.claim(file, line, tier)
        return index

    def set_device(self, key: str, value: Any, *, file: str, line: int, tier: int = 0) -> None:
        self._device[key] = value
        self._provenance[f"device.{key}"] = Provenance(
            file=file, line=line, raw=redact(self.raw_line(file, line)), tier=tier
        )
        self.claim(file, line, tier)

    def set_device_unsourced(self, key: str, value: Any) -> None:
        """Identity derived from the bundle rather than from a line.

        Used for things like a vendor guess that came from a filename. It is
        deliberately separate: an unsourced value carries no provenance, so it
        can never become the evidence behind a finding.
        """
        self._device[key] = value

    # -- internals --------------------------------------------------------

    def _write(self, path: str, value: Any) -> None:
        parts = split_path(path)
        container = self._container_for(parts, create=True)
        key = parts[-1]
        if isinstance(key, int):
            if not isinstance(container, list):
                raise TypeError(f"cannot index into {path}")
            while len(container) <= key:
                container.append({})
            container[key] = value
        else:
            container[key] = value  # type: ignore[index]

    def _container_for(self, parts: list[str | int], *, create: bool) -> Any:
        if len(parts) == 1:
            return self._sections
        root = parts[0]
        current: Any
        if root == "device":
            current = self._device
        else:
            if root not in self._sections:
                if not create:
                    raise KeyError(root)
                self._sections[root] = [] if isinstance(parts[1], int) else {}
            current = self._sections[root]

        for index, part in enumerate(parts[1:-1], start=1):
            nxt = parts[index + 1]
            if isinstance(part, int):
                if not isinstance(current, list):
                    raise TypeError("index into non-list")
                while len(current) <= part:
                    current.append({})
                if current[part] is None:
                    current[part] = [] if isinstance(nxt, int) else {}
                current = current[part]
            else:
                if part not in current or current[part] is None:
                    current[part] = [] if isinstance(nxt, int) else {}
                current = current[part]
        return current

    # -- result -----------------------------------------------------------

    def build(self) -> IRDocument:
        """Finalise, computing coverage from what was and was not claimed."""
        coverage = Coverage()
        for filename, lines in self._lines.items():
            claimed = self._claimed.get(filename, {})
            coverage.total_lines += len(lines)
            for number, raw in sorted(lines.items()):
                tier = claimed.get(number)
                if tier is None:
                    coverage.unparsed_lines += 1
                    if len(coverage.unparsed_sample) < MAX_UNPARSED_SAMPLE:
                        coverage.unparsed_sample.append(
                            {"file": filename, "line": number, "raw": redact(raw)}
                        )
                else:
                    coverage.parsed_lines += 1
                    coverage.by_tier[f"tier{tier}"] += 1

        # Invariant 4 is arithmetic, so check it rather than hope.
        coverage.check()

        return IRDocument(
            device=dict(self._device),
            sections=dict(self._sections),
            coverage=coverage,
            provenance=dict(self._provenance),
        )
