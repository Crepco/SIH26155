"""Stages 1 to 3: bundle in, normalised IR out.

This is the only module that is allowed to know about both raw files and the IR.
Everything downstream - policy, graph, report, sandbox - takes the IR and never
sees a configuration line again. Keeping that seam in one small file is what
makes the architecture rule checkable rather than aspirational.

The ordering matters more than it looks:

1. Register every line first, so the coverage denominator is fixed before any
   parser gets an opinion about it.
2. Fingerprint, and refuse to name a vendor we are not sure about.
3. Parse - or, when no Tier-0 parser applies, do not parse at all and let every
   line fall through as unparsed. A device we cannot read produces a report full
   of UNKNOWN, which is the honest outcome and the one invariant 3 demands.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from crucible.adapters.apply import PackApplication, apply_pack
from crucible.adapters.pack import AdapterPack, packs_for
from crucible.cascade.structure import StructureReport, analyse, claim_structural
from crucible.fingerprint.detect import DeviceIdentity, fingerprint
from crucible.ingest.bundle import DeviceBundle
from crucible.ir.builder import IRBuilder
from crucible.ir.model import IRDocument
from crucible.parsers.base import ParseContext, get_parser
from crucible.parsers.show_output import claim_show_output, parse_identity

__all__ = ["ParsedDevice", "build_ir"]

#: A pack's fingerprint must reach this score before it may name a device the
#: built-in fingerprinter could not. Lower, and one stray keyword would route a
#: file through the wrong grammar.
PACK_FINGERPRINT_THRESHOLD = 0.6


@dataclass(slots=True)
class ParsedDevice:
    """An IR document plus how it was produced."""

    ir: IRDocument
    identity: DeviceIdentity
    bundle: DeviceBundle
    #: False when no Tier-0 parser ran. The report says so rather than implying
    #: that a low coverage figure was the parser having a bad day.
    parser_applied: bool
    #: Tier 1's view of each configuration file, keyed by file name. Kept so
    #: the training GUI can show an unrecognised line in its block.
    structure: dict[str, StructureReport] = field(default_factory=dict)
    #: Which adapter packs contributed, and what each did.
    packs: list[PackApplication] = field(default_factory=list)

    @property
    def device_id(self) -> str:
        return self.bundle.device_id

    @property
    def pack_ids(self) -> list[str]:
        return sorted({p.pack_id for p in self.packs if p.facts})


def build_ir(
    bundle: DeviceBundle,
    *,
    packs: Iterable[AdapterPack] = (),
    hold_out: Iterable[str] = (),
) -> ParsedDevice:
    """Ingest, fingerprint and parse one device bundle into the IR.

    ``packs`` must already have been admitted by a trust store; this function
    applies them and does not re-check signatures. ``hold_out`` names vendors
    whose built-in parser is switched off, which is how the unseen-vendor
    demonstration is run honestly against a vendor the build does know.
    """
    available = list(packs)
    held_out = {v.lower() for v in hold_out}
    builder = IRBuilder()

    for source in bundle.files:
        builder.register_file(source.name, source.lines)

    identity = fingerprint(bundle)

    # A device the built-in signatures cannot name may still be one a trusted
    # pack knows. The pack's own fingerprint decides, and its confidence is
    # what gets recorded.
    if not identity.recognised and available:
        sources = bundle.configs or bundle.files
        config_text = "\n".join(s.text for s in sources)
        scored = sorted(
            ((pack.fingerprint_score(config_text), pack) for pack in available),
            key=lambda item: item[0],
            reverse=True,
        )
        if scored and scored[0][0] >= PACK_FINGERPRINT_THRESHOLD:
            score, pack = scored[0]
            identity.vendor = pack.vendor
            identity.os = pack.os
            identity.confidence = score

    if not identity.recognised:
        # A below-threshold guess is not a vendor. Recording it would put
        # "cisco" in the report of a device that is nothing of the kind.
        identity.vendor = "unknown"
        identity.os = None
        identity.version = None

    builder.set_device_unsourced("vendor", identity.vendor)
    if identity.os:
        builder.set_device_unsourced("os", identity.os)
    if identity.version:
        builder.set_device_unsourced("version", identity.version)
    if identity.hostname:
        builder.set_device_unsourced("hostname", identity.hostname)
    # Basis points, not a float. Floating point is banned from anything that
    # gets canonically serialised: the last bit can differ between platforms,
    # and an IR export that is not byte-identical between runs cannot be diffed
    # for drift or committed to reproducibly.
    builder.set_device_unsourced("fingerprint_confidence_bp", round(identity.confidence * 10000))

    # Identity from command output overwrites the guess, and does so with a
    # citation - a serial read off show version beats anything inferred.
    parse_identity(bundle, builder)
    claim_show_output(bundle, builder)

    parser = None
    if identity.recognised and identity.vendor not in held_out:
        parser = get_parser(identity.vendor)
    if parser is not None:
        for source in bundle.configs:
            parser(ParseContext(source=source, builder=builder))

    structure: dict[str, StructureReport] = {}
    applications: list[PackApplication] = []
    matching = packs_for(available, identity.vendor, identity.os) if identity.recognised else []
    if not matching and not identity.recognised:
        matching = [p for p in available if p.vendor == identity.vendor]
    for source in bundle.configs:
        report = analyse(source.name, source.lines)
        structure[source.name] = report
        # Precedence: built-in Tier 0, then signed packs in load order, then
        # Tier 1 structure. A pack never overrides a line Tier 0 claimed.
        for pack in matching:
            applications.append(apply_pack(pack, builder, source.name, source.lines, report))
        claim_structural(builder, report)

    return ParsedDevice(
        ir=builder.build(),
        identity=identity,
        bundle=bundle,
        parser_applied=parser is not None,
        structure=structure,
        packs=applications,
    )
