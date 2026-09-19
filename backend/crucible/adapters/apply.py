"""Applying a pack to a file: deterministic, cited, and weaker than Tier 0.

A pack runs on the residue: lines no built-in parser claimed. It never overrides
a built-in parser, so it extends coverage rather than redefining it (docs/06,
*Import and precedence*).

Every fact a pack writes records three things in its provenance: the tier the
mapping was learned at (2 for model-proposed, 3 for human-confirmed), the pack
id, and the confidence. A reader of the report can therefore trace a verdict
back to the exact knowledge that produced it, and a compromised pack can be
audited backwards through every report it touched.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from crucible.adapters.pack import AdapterPack, Mapping
from crucible.adapters.transforms import TransformError, apply_transform
from crucible.cascade.structure import StructureReport
from crucible.ir.builder import IRBuilder
from crucible.ir.paths import DEVICE_PATHS, LIST_PATHS, kind_of

__all__ = ["PackApplication", "apply_pack", "match_line"]


@dataclass(slots=True)
class PackApplication:
    """What one pack did to one file."""

    pack_id: str
    file: str
    facts: int = 0
    lines: list[int] = field(default_factory=list)
    #: (line, ir_path, reason) for matches whose value did not fit the
    #: transform. Those lines stay uninterpreted.
    rejected: list[tuple[int, str, str]] = field(default_factory=list)


def match_line(mapping: Mapping, text: str, context: Sequence[str] = ()) -> str | None:
    """Return the captured value (or ``""`` for presence) if the mapping fires.

    Shared by the pipeline and the training preview, so what an administrator
    sees in the GUI is exactly what an audit will do.
    """
    within = mapping.within_regex
    if within is not None and not any(within.search(header) for header in context):
        return None
    match = mapping.regex.search(text)
    if match is None:
        return None
    if "value" in mapping.regex.groupindex:
        return match.group("value") or ""
    return ""


def apply_pack(
    pack: AdapterPack,
    builder: IRBuilder,
    file: str,
    lines: Sequence[str],
    structure: StructureReport | None = None,
) -> PackApplication:
    result = PackApplication(pack_id=pack.id, file=file)
    booleans_true: set[str] = set()

    for number in builder.unclaimed(file):
        raw = lines[number - 1] if 0 < number <= len(lines) else ""
        text = raw.strip()
        if not text:
            continue
        node = structure.node(number) if structure else None
        context = node.context if node else ()

        for mapping in pack.mappings:
            captured = match_line(mapping, text, context)
            if captured is None:
                continue
            try:
                outcome = apply_transform(
                    mapping.transform,
                    captured if "value" in mapping.regex.groupindex else None,
                    mapping.values,
                )
            except TransformError as exc:
                result.rejected.append((number, mapping.ir_path, str(exc)))
                continue

            path = mapping.ir_path
            tier = mapping.tier_learned
            if path in LIST_PATHS:
                builder.append(
                    path,
                    outcome.value,
                    adapter_pack=pack.id,
                    confidence_bp=mapping.confidence_bp,
                    secret=outcome.secret,
                    file=file,
                    line=number,
                    tier=tier,
                )
            elif path in DEVICE_PATHS:
                builder.set_device(
                    path.split(".", 1)[1], str(outcome.value), file=file, line=number, tier=tier
                )
            else:
                value = outcome.value
                if kind_of(path) == "bool":
                    # A boolean some line asserted true stays true. For every
                    # enable flag this vocabulary covers, that means the
                    # riskier reading wins when a file contradicts itself,
                    # which is the fail-closed direction.
                    if path in booleans_true and value is False:
                        builder.claim(file, number, tier)
                        result.lines.append(number)
                        break
                    if value is True:
                        booleans_true.add(path)
                builder.set(
                    path,
                    value,
                    adapter_pack=pack.id,
                    confidence_bp=mapping.confidence_bp,
                    secret=outcome.secret,
                    file=file,
                    line=number,
                    tier=tier,
                )
            result.facts += 1
            result.lines.append(number)
            break  # first matching mapping wins; order in the pack is precedence

    return result
