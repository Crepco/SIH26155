"""Command output - where device identity actually lives.

Every other parser in this package reads a configuration. This one reads
``show version`` and friends, because the serial number and hardware model that
the problem statement explicitly requires in the report are usually nowhere in
the running configuration.

It writes only into ``device``. Command output describes the box; it does not
describe the security posture, and letting it write elsewhere would blur the
line between what is configured and what happens to be running.
"""

from __future__ import annotations

from crucible.fingerprint.identity import extract_identity
from crucible.ingest.bundle import DeviceBundle
from crucible.ir.builder import IRBuilder

__all__ = ["claim_show_output", "parse_identity"]


def parse_identity(bundle: DeviceBundle, builder: IRBuilder) -> None:
    """Write serial, model, version and hostname into ``device``, with citations.

    Device identity is printed on the front page of a signed report, so it is
    held to the same evidence standard as any finding: each value records the
    file and line it was read from.
    """
    for key, fact in extract_identity(bundle).items():
        builder.set_device(key, fact.value, file=fact.file, line=fact.line)


def claim_show_output(bundle: DeviceBundle, builder: IRBuilder) -> None:
    """Account for every line of command output.

    Show output is mostly prose, banners and licence tables. None of it is a
    security fact, but all of it is lines in the bundle, and coverage must add
    up over the whole input rather than over the convenient part of it.

    Counting it honestly costs us a percentage point of coverage and buys a
    number an auditor can actually check.
    """
    for source in bundle.show_outputs:
        for number in range(1, source.line_count + 1):
            builder.claim(source.name, number, 0)
