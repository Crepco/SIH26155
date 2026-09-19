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

from dataclasses import dataclass

from crucible.fingerprint.detect import DeviceIdentity, fingerprint
from crucible.ingest.bundle import DeviceBundle
from crucible.ir.builder import IRBuilder
from crucible.ir.model import IRDocument
from crucible.parsers.base import ParseContext, get_parser
from crucible.parsers.show_output import claim_show_output, parse_identity

__all__ = ["ParsedDevice", "build_ir"]


@dataclass(slots=True)
class ParsedDevice:
    """An IR document plus how it was produced."""

    ir: IRDocument
    identity: DeviceIdentity
    bundle: DeviceBundle
    #: False when no Tier-0 parser ran. The report says so rather than implying
    #: that a low coverage figure was the parser having a bad day.
    parser_applied: bool

    @property
    def device_id(self) -> str:
        return self.bundle.device_id


def build_ir(bundle: DeviceBundle) -> ParsedDevice:
    """Ingest, fingerprint and parse one device bundle into the IR."""
    builder = IRBuilder()

    for source in bundle.files:
        builder.register_file(source.name, source.lines)

    identity = fingerprint(bundle)
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

    parser = get_parser(identity.vendor) if identity.recognised else None
    if parser is not None:
        for source in bundle.configs:
            parser(ParseContext(source=source, builder=builder))

    return ParsedDevice(
        ir=builder.build(),
        identity=identity,
        bundle=bundle,
        parser_applied=parser is not None,
    )
