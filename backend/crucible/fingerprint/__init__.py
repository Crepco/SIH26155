"""Device fingerprinting - which vendor, which OS, which box.

Fingerprinting decides which Tier-0 parser runs, so a wrong answer here is a
whole device parsed by the wrong grammar. It therefore reports a confidence and
never asserts: a low-confidence guess routes the file down the cascade rather
than into a parser that will misread it.
"""

from crucible.fingerprint.detect import DeviceIdentity, fingerprint
from crucible.fingerprint.identity import extract_identity

__all__ = ["DeviceIdentity", "extract_identity", "fingerprint"]
