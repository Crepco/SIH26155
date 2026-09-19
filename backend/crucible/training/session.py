"""Tier 3 - an administrator teaches the engine a vendor, one family at a time.

A :class:`TrainingSession` holds one uploaded device *in memory only* (the same
rule as audit uploads: a configuration is a blueprint of a network's defences
and is not written to disk as a side effect of training). It:

1. runs the deterministic cascade (Tier 0, trusted packs, Tier 1),
2. groups the residue into **families** - lines that generalise to the same
   pattern - so an administrator maps ``snmp-agent community read X`` once
   rather than once per community,
3. attaches a Tier-2 proposal to each family,
4. previews any candidate mapping against the whole file, exactly as the
   pipeline will apply it (the same :func:`~crucible.adapters.apply.match_line`),
5. and turns confirmed mappings into a signed :class:`AdapterPack`.

Nothing here decides a verdict. After training, the file is re-audited through
the ordinary pipeline with the new pack, and the policy engine decides.
"""

from __future__ import annotations

import datetime as _dt
import re
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from crucible.adapters.apply import match_line
from crucible.adapters.pack import AdapterPack, Mapping
from crucible.adapters.transforms import TransformError, apply_transform
from crucible.cascade.structure import NodeKind, StructureReport
from crucible.common.errors import PackError
from crucible.ingest.bundle import DeviceBundle
from crucible.ledger.signing import SigningKey
from crucible.pipeline import ParsedDevice, build_ir
from crucible.training.proposer import LexicalProposer, Proposal, Proposer, _is_variable

__all__ = ["Family", "TrainingSession"]

#: Tier-2 proposals at or above this are accepted automatically by
#: :meth:`TrainingSession.accept_proposals` (docs/05, "High" band). Printed in
#: every pack's description so the posture that produced it is visible.
DEFAULT_ACCEPT_ABOVE = 0.85


@dataclass(slots=True)
class Family:
    """Uninterpreted lines that share one shape."""

    key: str
    file: str
    lines: list[int] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)
    context: tuple[str, ...] = ()
    proposal: Proposal | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "file": self.file,
            "lines": self.lines,
            "samples": self.texts[:5],
            "count": len(self.lines),
            "context": list(self.context),
            "proposal": self.proposal.to_dict() if self.proposal else None,
        }


def _shape(text: str) -> str:
    """The family key: grammar words kept, data generalised."""
    parts = []
    for token in text.split():
        if "=" in token:
            key = token.split("=", 1)[0]
            parts.append(f"{key}=*")
        elif _is_variable(token):
            parts.append("*")
        else:
            parts.append(token.lower())
    return " ".join(parts)


class TrainingSession:
    """One device being taught. Held in memory; dies with the process."""

    def __init__(
        self,
        bundle: DeviceBundle,
        *,
        packs: Iterable[AdapterPack] = (),
        hold_out: Iterable[str] = (),
        proposer: Proposer | None = None,
    ) -> None:
        self.id = secrets.token_hex(8)
        self.bundle = bundle
        self.hold_out = tuple(hold_out)
        self.packs = list(packs)
        self.proposer: Proposer = proposer or LexicalProposer()
        self.confirmed: list[Mapping] = []
        self.created = _dt.datetime.now(_dt.UTC)
        self.device: ParsedDevice = build_ir(bundle, packs=self.packs, hold_out=self.hold_out)
        self.families: list[Family] = self._group()

    # -- the residue --------------------------------------------------------

    def _unparsed(self) -> set[tuple[str, int]]:
        return {(name, n) for name, lines in self.device.unclaimed.items() for n in lines}

    def _sources(self) -> dict[str, list[str]]:
        return {s.name: s.lines for s in self.bundle.configs}

    def _group(self) -> list[Family]:
        unparsed = self._unparsed()
        families: dict[tuple[str, str, tuple[str, ...]], Family] = {}
        for name, report in self.device.structure.items():
            for node in report.nodes:
                if (name, node.line) not in unparsed:
                    continue
                if node.kind not in (NodeKind.STATEMENT, NodeKind.BLOCK_OPEN):
                    continue
                context = node.context[-1:] if node.context else ()
                key = (name, _shape(node.text), tuple(_shape(c) for c in context))
                family = families.get(key)
                if family is None:
                    family = Family(key=" | ".join([key[1], *key[2]]), file=name, context=context)
                    families[key] = family
                family.lines.append(node.line)
                family.texts.append(node.text)
        ordered = sorted(families.values(), key=lambda f: (f.file, f.lines[0]))
        for family in ordered:
            family.proposal = self.proposer.propose(family.texts[0], family.context)
        return ordered

    def structure(self, file: str) -> StructureReport | None:
        return self.device.structure.get(file)

    # -- preview ------------------------------------------------------------

    def preview(self, mapping: Mapping) -> list[dict[str, Any]]:
        """Every line in the device this mapping would fire on, and the value.

        Lines another tier already claimed are reported but marked, because a
        pack never overrides them - an administrator should see that.
        """
        mapping.validate(0)
        unparsed = self._unparsed()

        hits: list[dict[str, Any]] = []
        for name, lines in self._sources().items():
            report = self.device.structure.get(name)
            for number, raw in enumerate(lines, start=1):
                text = raw.strip()
                if not text:
                    continue
                node = report.node(number) if report else None
                captured = match_line(mapping, text, node.context if node else ())
                if captured is None:
                    continue
                try:
                    value = apply_transform(
                        mapping.transform,
                        captured if "value" in mapping.regex.groupindex else None,
                        mapping.values,
                    ).value
                    error = None
                except TransformError as exc:
                    value, error = None, str(exc)
                hits.append(
                    {
                        "file": name,
                        "line": number,
                        # The redacted form: previews are shown in a browser.
                        "text": _redacted_line(self.device, name, number, text),
                        "value": value,
                        "error": error,
                        "applies": (name, number) in unparsed and error is None,
                    }
                )
        return hits

    # -- confirmation ---------------------------------------------------------

    def confirm(self, mapping: Mapping, *, confirmed_by: str) -> Mapping:
        """Record an administrator's decision. Tier 3 by definition."""
        confirmed = Mapping(
            ir_path=mapping.ir_path,
            match=mapping.match,
            transform=mapping.transform,
            tier_learned=3,
            confidence=None,
            confirmed_by=confirmed_by or "administrator",
            samples=0,
            values=dict(mapping.values) if mapping.values else None,
            within=mapping.within,
        )
        confirmed.validate(len(self.confirmed))
        hits = [h for h in self.preview(confirmed) if h["applies"]]
        if not hits:
            raise PackError("this mapping matches no uninterpreted line in the file")
        confirmed.samples = len(hits)
        # Re-confirming the same pattern replaces the earlier decision.
        self.confirmed = [m for m in self.confirmed if m.match != confirmed.match]
        self.confirmed.append(confirmed)
        return confirmed

    def withdraw(self, match: str) -> bool:
        before = len(self.confirmed)
        self.confirmed = [m for m in self.confirmed if m.match != match]
        return len(self.confirmed) != before

    def accept_proposals(self, threshold: float = DEFAULT_ACCEPT_ABOVE) -> list[Mapping]:
        """Accept every Tier-2 proposal at or above ``threshold``, *as* Tier 2.

        These stay marked as model-proposed (tier_learned 2, with their
        confidence) in the pack, so a reader can tell them apart from what a
        human confirmed.
        """
        accepted: list[Mapping] = []
        for family in self.families:
            proposal = family.proposal
            if proposal is None or proposal.confidence < threshold:
                continue
            if any(m.match == proposal.mapping.match for m in self.confirmed):
                continue
            mapping = proposal.mapping
            mapping.samples = len(family.lines)
            self.confirmed.append(mapping)
            accepted.append(mapping)
        return accepted

    # -- the pack -------------------------------------------------------------

    def fingerprint(self) -> list[dict[str, Any]]:
        """Signatures for the new pack, from the grammar words of what was learned.

        The leading literal words of confirmed patterns are exactly the tokens
        that make this vendor's grammar recognisable, and they carry no customer
        data by construction (the patterns already passed the privacy guard).
        """
        seen: list[str] = []
        for mapping in self.confirmed:
            head = re.match(r"^\^((?:[A-Za-z/][\w/-]*)(?:\\s\+[A-Za-z][\w-]*)?)", mapping.match)
            if head and head.group(1) not in seen:
                seen.append(head.group(1))
        chosen = seen[:5]
        weight = round(min(0.9, 1.0 / max(len(chosen), 1) + 0.15), 2) if chosen else 0.0
        return [{"match": f"(?m)^\\s*{h}\\b", "confidence": weight} for h in chosen]

    def build_pack(
        self,
        *,
        pack_id: str,
        vendor: str,
        os: str | None = None,
        author: str | None = None,
        key: SigningKey,
        description: str | None = None,
    ) -> AdapterPack:
        if not self.confirmed:
            raise PackError("nothing has been confirmed yet")
        grammar_kind = "indent_blocks"
        for report in self.device.structure.values():
            if report.grammar.value not in ("unknown",):
                grammar_kind = report.grammar.value
                break
        tier2 = sum(1 for m in self.confirmed if m.tier_learned == 2)
        tier3 = len(self.confirmed) - tier2
        pack = AdapterPack(
            id=pack_id,
            vendor=vendor.lower(),
            os=os,
            created=_dt.date.today().isoformat(),
            author=author,
            description=description
            or (
                f"Learned from one configuration: {tier3} mapping(s) confirmed by an "
                f"administrator, {tier2} accepted from Tier-2 proposals at or above "
                f"{DEFAULT_ACCEPT_ABOVE:.2f} confidence."
            ),
            grammar={"kind": grammar_kind},
            fingerprint=self.fingerprint(),
            mappings=list(self.confirmed),
        )
        pack.sign(key)
        return pack

    def audit_with(self, pack: AdapterPack) -> ParsedDevice:
        """Re-run the ordinary pipeline with the new pack alongside the old ones."""
        return build_ir(self.bundle, packs=[*self.packs, pack], hold_out=self.hold_out)

    # -- serialisation ----------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        coverage = self.device.ir.coverage
        return {
            "session": self.id,
            "device_id": self.bundle.device_id,
            "vendor": self.device.identity.vendor,
            "hold_out": list(self.hold_out),
            "proposer": getattr(self.proposer, "name", "unknown"),
            "coverage": {
                "parsed": coverage.parsed_lines,
                "total": coverage.total_lines,
                "by_tier": dict(coverage.by_tier),
            },
            "grammar": {name: r.to_dict() for name, r in self.device.structure.items()},
            "families": [f.to_dict() for f in self.families],
            "confirmed": [m.to_dict() for m in self.confirmed],
        }


def _redacted_line(device: ParsedDevice, file: str, number: int, fallback: str) -> str:
    lines = device.ir.sources.get(file)
    if lines and 0 < number <= len(lines):
        return lines[number - 1].strip()
    return fallback


def families_text(families: Sequence[Family]) -> str:
    """A plain-text rendering for the CLI."""
    rows = []
    for family in families:
        proposal = family.proposal
        head = f"  {family.lines[0]:>4}  x{len(family.lines):<3} {family.texts[0][:60]}"
        if proposal:
            head += (
                f"\n        -> {proposal.ir_path}  ({proposal.confidence:.2f}, "
                f"{proposal.mapping.transform}, {proposal.source})"
            )
        else:
            head += "\n        -> no proposal"
        rows.append(head)
    return "\n".join(rows)
