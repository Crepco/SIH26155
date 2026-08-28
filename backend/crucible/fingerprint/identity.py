"""Serial number, model and hardware, extracted from command output.

This module exists because of one sentence in the problem statement: the report
must carry device identity *including serial and hardware*. Serial numbers are
usually not in the running configuration at all - they live in ``show version``.

A tool that accepts only a config file cannot produce them, and quietly ships a
report with an empty serial field. Ingestion therefore takes a bundle, and this
is the half of the bundle that answers "which physical box was this?".

Every extraction returns the line it came from, because device identity is
printed on the front page of a signed report and must be as citable as any
finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from crucible.ingest.bundle import DeviceBundle

__all__ = ["IdentityFact", "extract_identity"]


@dataclass(frozen=True, slots=True)
class IdentityFact:
    """One identity value plus where it was read from."""

    value: str
    file: str
    line: int


# Ordered by trustworthiness. "System serial number" is what a Cisco chassis
# label says; "Processor board ID" is the same value on most platforms but not
# all, so it is a fallback rather than a peer.
_SERIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*System serial number\s*:\s*(\S+)", re.I),
    re.compile(r"^\s*Chassis Serial Number\s*:\s*(\S+)", re.I),
    re.compile(r"^\s*Serial Number\s*:\s*(\S+)", re.I),
    # RouterOS writes it into a comment header at the top of an export, so the
    # comment marker has to be part of the pattern rather than stripped first.
    re.compile(r"^[#\s]*serial number\s*=\s*(\S+)", re.I),
    re.compile(r"^\s*Processor board ID\s+(\S+)", re.I),
    re.compile(r"^\s*[Ss]erial[- ]?[Nn]um(?:ber)?\s+(\S+)"),
)

_MODEL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*Model number\s*:\s*(\S+)", re.I),
    re.compile(r"^\s*Model\s*:\s*(\S+)", re.I),
    re.compile(r"^\s*#\s*model\s*=\s*(\S+)", re.I),
    re.compile(r"^cisco (\S+) \(.*processor", re.I),
    re.compile(r"^\s*Hardware model\s*:\s*(\S+)", re.I),
)

_VERSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"Cisco IOS Software.*Version (\S+?),", re.I),
    re.compile(r"^\s*Software image version\s*:\s*(\S+)", re.I),
    re.compile(r"^\s*Version\s*:\s*(\S+)", re.I),
    re.compile(r"by RouterOS ([\d.]+)", re.I),
    re.compile(r"EOS-(\S+?)\)", re.I),
)

_HOSTNAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(\S+)[#>]\s*show version", re.I),
    re.compile(r"^\s*Hostname\s*:\s*(\S+)", re.I),
)


def _first_match(
    bundle: DeviceBundle, patterns: tuple[re.Pattern[str], ...], *, show_output_only: bool
) -> IdentityFact | None:
    """Scan patterns in priority order, files in bundle order.

    Priority is by pattern, not by file: a strong pattern in the second file
    beats a weak one in the first, because "System serial number" is the answer
    and "Serial Number" on a transceiver line is not.
    """
    sources = bundle.show_outputs if show_output_only else bundle.files
    for pattern in patterns:
        for source in sources:
            for number, raw in enumerate(source.lines, start=1):
                match = pattern.search(raw)
                if match:
                    value = match.group(1).strip().strip('",;')
                    if value:
                        return IdentityFact(value=value, file=source.name, line=number)
    return None


def extract_identity(bundle: DeviceBundle) -> dict[str, IdentityFact]:
    """Pull serial, model, OS version and hostname out of a bundle.

    Show output is searched first and, for the serial, exclusively: a string
    that looks like a serial inside a running configuration is far more likely
    to be a description or a licence key than the chassis identifier.
    """
    facts: dict[str, IdentityFact] = {}

    serial = _first_match(bundle, _SERIAL_PATTERNS, show_output_only=True)
    if serial is None:
        # RouterOS puts it in a comment header at the top of the export, which
        # is a config file. Worth a second look before giving up.
        serial = _first_match(bundle, _SERIAL_PATTERNS[3:4], show_output_only=False)
    if serial:
        facts["serial"] = serial

    for key, patterns, show_only in (
        ("model", _MODEL_PATTERNS, False),
        ("version", _VERSION_PATTERNS, False),
        ("hostname", _HOSTNAME_PATTERNS, True),
    ):
        found = _first_match(bundle, patterns, show_output_only=show_only)
        if found:
            facts[key] = found

    return facts
