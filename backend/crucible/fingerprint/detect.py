"""Vendor and OS detection from configuration text.

Signature scoring rather than a first-match cascade. Real configurations share
vocabulary - Arista EOS reads a lot like Cisco IOS, and a single ``interface``
line proves nothing - so the answer comes from weighing several signals and
reporting how sure we are.

The confidence is not decoration. Below :data:`MIN_CONFIDENCE` the file is not
handed to a Tier-0 parser at all: it falls through the cascade, where being
unrecognised is a normal outcome that ends in an honest UNKNOWN rather than in a
device silently parsed by the wrong grammar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from crucible.ingest.bundle import DeviceBundle, SourceFile

__all__ = ["MIN_CONFIDENCE", "DeviceIdentity", "fingerprint"]

#: Below this, we decline to name a vendor rather than guess.
MIN_CONFIDENCE = 0.45

# (compiled pattern, weight). Weights are deliberately lopsided: a marker that
# only one vendor could produce is worth far more than a generic keyword.
_SIGNATURES: dict[tuple[str, str], list[tuple[re.Pattern[str], int]]] = {
    ("cisco", "IOS"): [
        (re.compile(r"^service timestamps ", re.M), 5),
        (re.compile(r"^line vty \d+ \d+", re.M), 5),
        (re.compile(r"^ip ssh version", re.M), 3),
        (re.compile(r"^spanning-tree mode (rapid-)?pvst", re.M), 4),
        (re.compile(r"^switchport mode ", re.M), 2),
        (re.compile(r"^snmp-server community ", re.M), 2),
        (re.compile(r"^boot-(start|end)-marker", re.M), 4),
        (re.compile(r"^interface (Gigabit|Fast|Ten)Ethernet", re.M), 3),
    ],
    ("arista", "EOS"): [
        (re.compile(r"^management (ssh|telnet|api http-commands)", re.M), 8),
        (re.compile(r"role network-admin", re.M), 6),
        (re.compile(r"^transceiver qsfp default-mode", re.M), 6),
        (re.compile(r"EOS-4\.", re.M), 6),
        (re.compile(r"^interface Ethernet\d", re.M), 3),
        (re.compile(r"^no aaa root", re.M), 5),
    ],
    ("fortinet", "FortiOS"): [
        (re.compile(r"^#config-version=", re.M), 10),
        (re.compile(r"^config system global", re.M), 8),
        (re.compile(r"^\s*set admintimeout ", re.M), 6),
        (re.compile(r"^\s*next$", re.M), 3),
        (re.compile(r"^\s*edit \"", re.M), 3),
    ],
    ("juniper", "JUNOS"): [
        (re.compile(r"^system \{", re.M), 8),
        (re.compile(r"^\s*host-name \S+;", re.M), 6),
        (re.compile(r"protocol-version v2;", re.M), 5),
        (re.compile(r"^\s*unit \d+ \{", re.M), 5),
        (re.compile(r"^version \d+\.\dR", re.M), 6),
        (re.compile(r"^interfaces \{", re.M), 5),
    ],
    ("mikrotik", "RouterOS"): [
        (re.compile(r"^/ip service set ", re.M), 9),
        (re.compile(r"^/system identity set ", re.M), 8),
        (re.compile(r"^/interface bridge add ", re.M), 6),
        (re.compile(r"by RouterOS", re.M), 8),
        (re.compile(r"^/ip firewall filter add ", re.M), 5),
    ],
    ("paloalto", "PAN-OS"): [
        (re.compile(r"<config .*urldb=", re.M), 10),
        (re.compile(r"<devices>\s*<entry name=\"localhost.localdomain\"", re.M), 10),
        (re.compile(r"<deviceconfig>", re.M), 8),
    ],
}

_HOSTNAME_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cisco", re.compile(r"^hostname (\S+)", re.M)),
    ("arista", re.compile(r"^hostname (\S+)", re.M)),
    ("fortinet", re.compile(r'^\s*set hostname "([^"]+)"', re.M)),
    ("juniper", re.compile(r"^\s*host-name (\S+);", re.M)),
    ("mikrotik", re.compile(r"^/system identity set name=(\S+)", re.M)),
)

_VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "cisco": re.compile(r"^version (\S+)", re.M),
    "arista": re.compile(r"EOS-(\S+?)\)", re.M),
    "fortinet": re.compile(r"^#config-version=\S+?-(v?[\d.]+)-", re.M),
    "juniper": re.compile(r"^version (\S+);", re.M),
    "mikrotik": re.compile(r"by RouterOS ([\d.]+)", re.M),
}


@dataclass(slots=True)
class DeviceIdentity:
    """What we think this device is, and how sure we are."""

    vendor: str = "unknown"
    os: str | None = None
    version: str | None = None
    model: str | None = None
    serial: str | None = None
    hostname: str | None = None
    confidence: float = 0.0
    #: Path of the file the vendor decision came from, so the decision itself is
    #: traceable rather than merely asserted.
    evidence_file: str | None = None
    scores: dict[str, int] = field(default_factory=dict)

    @property
    def recognised(self) -> bool:
        return self.vendor != "unknown" and self.confidence >= MIN_CONFIDENCE

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "os": self.os,
            "version": self.version,
            "model": self.model,
            "serial": self.serial,
            "hostname": self.hostname,
            "fingerprint_confidence_bp": round(self.confidence * 10000),
        }


def _score_text(text: str) -> dict[tuple[str, str], int]:
    scores: dict[tuple[str, str], int] = {}
    for key, signatures in _SIGNATURES.items():
        total = 0
        for pattern, weight in signatures:
            if pattern.search(text):
                total += weight
        if total:
            scores[key] = total
    return scores


def _pick_config(bundle: DeviceBundle) -> SourceFile | None:
    configs = bundle.configs
    if configs:
        # The largest config is the running configuration in every bundle shape
        # we have seen; smaller ones tend to be fragments or partial exports.
        return max(configs, key=lambda f: f.line_count)
    return bundle.files[0] if bundle.files else None


def fingerprint(bundle: DeviceBundle) -> DeviceIdentity:
    """Determine vendor, OS, version and hostname for a bundle."""
    source = _pick_config(bundle)
    if source is None:
        return DeviceIdentity()

    scores = _score_text(source.text)
    if not scores:
        return DeviceIdentity(evidence_file=source.name)

    (vendor, os_name), best = max(scores.items(), key=lambda item: item[1])
    runner_up = sorted(scores.values(), reverse=True)
    second = runner_up[1] if len(runner_up) > 1 else 0

    # Confidence blends absolute evidence with how far ahead the winner is. Two
    # vendors scoring similarly is exactly the case where a confident answer
    # would be most damaging - IOS and EOS, for instance.
    absolute = min(best / 20.0, 1.0)
    margin = (best - second) / best if best else 0.0
    confidence = round(min(0.5 * absolute + 0.5 * margin + 0.15, 1.0), 3)

    identity = DeviceIdentity(
        vendor=vendor,
        os=os_name,
        confidence=confidence,
        evidence_file=source.name,
        scores={f"{v}/{o}": s for (v, o), s in scores.items()},
    )

    for candidate, pattern in _HOSTNAME_PATTERNS:
        if candidate == vendor:
            match = pattern.search(source.text)
            if match:
                identity.hostname = match.group(1).strip('"')
                break

    version_pattern = _VERSION_PATTERNS.get(vendor)
    if version_pattern:
        match = version_pattern.search(source.text)
        if match:
            identity.version = match.group(1)

    return identity
