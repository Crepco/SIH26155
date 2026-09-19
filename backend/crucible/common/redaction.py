"""Secret redaction and credential fingerprinting.

A configuration file is a blueprint of an organisation's defences. This module
is the reason a credential hash can be *correlated across a fleet* without ever
being *stored*.

Two operations, and the difference between them is the whole point:

- :func:`redact` replaces secret material with a marker. Used on every raw line
  before it is stored as evidence or printed in a report.
- :func:`fingerprint` produces a salted, deployment-local digest. Two devices
  carrying the same credential produce the same fingerprint, so the fleet graph
  can find a lateral-movement highway - and an attacker who steals the database
  gets nothing back out.
"""

from __future__ import annotations

import hashlib
import hmac
import re

__all__ = ["REDACTED", "fingerprint", "hash_algorithm_of", "redact", "redact_literal"]

REDACTED = "<redacted>"

# Ordered: the first pattern that matches a line wins for that span. Each entry
# is (pattern, index of the group holding the secret).
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    # Cisco: username admin secret 9 $9$abc...   /  password 7 070C285F4D06
    (re.compile(r"(\bsecret\s+\d\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bpassword\s+\d\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bsecret\s+)(?!\d\s)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bpassword\s+)(?!\d\s)(\S+)", re.IGNORECASE), 2),
    # SNMP community strings
    (re.compile(r"(\bsnmp-server\s+community\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bcommunity\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bname=)(\S+)(?=.*\bcommunity)", re.IGNORECASE), 2),
    # Keys and shared secrets
    (re.compile(r"(\bkey\s+\d\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bpre-shared-key\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bauthentication-key\s+)(\S+)", re.IGNORECASE), 2),
    # Junos / VyOS style
    (re.compile(r"(\bencrypted-password\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bplain-text-password\s+)(\S+)", re.IGNORECASE), 2),
    # FortiOS
    (re.compile(r"(\bset\s+passwd\s+)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bset\s+psksecret\s+)(\S+)", re.IGNORECASE), 2),
    # key=value grammars (RouterOS and friends), where the secret is glued to
    # its key with no whitespace for the patterns above to anchor on.
    (re.compile(r"(\bpassword=)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bsecret=)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bpsk=)(\S+)", re.IGNORECASE), 2),
    (re.compile(r"(\bkey=)(\S+)", re.IGNORECASE), 2),
)

# Recognised password hash algorithms, keyed by the marker that identifies them.
# Cisco type numbers are the awkward case: type 7 is reversible obfuscation, not
# a hash, and reporting it as "encrypted" is exactly the false comfort we exist
# to remove.
_CISCO_TYPE_TO_ALGORITHM = {
    "0": "plaintext",
    "4": "sha256",
    "5": "md5",
    "7": "reversible",
    "8": "pbkdf2",
    "9": "scrypt",
}

_HASH_PREFIX_TO_ALGORITHM = {
    "$1$": "md5",
    "$5$": "sha256",
    "$6$": "sha512",
    "$8$": "pbkdf2",
    "$9$": "scrypt",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
}


def redact(line: str) -> str:
    """Strip secret material from a line, preserving its shape.

    The shape is preserved on purpose: a redacted line still shows an auditor
    which command was present and at which indentation, which is what makes the
    evidence citation useful.
    """
    result = line
    for pattern, group in _SECRET_PATTERNS:

        def _mask(match: re.Match[str], group: int | str = group) -> str:
            return match.group(0).replace(match.group(group), REDACTED, 1)

        result = pattern.sub(_mask, result)
    return result


def redact_literal(line: str, secret: str | None) -> str:
    """Strip a specific value a parser knows to be secret.

    Line-local patterns cannot catch everything. FortiOS writes a community
    string as `set name "public"` inside a `config system snmp community`
    block: nothing on that line marks it as sensitive, and a pattern broad
    enough to catch it would also redact every interface and policy name.

    The parser has the block context, so it names the literal and this removes
    it. Context-aware redaction beats a more aggressive regex.
    """
    line = redact(line)
    if not secret:
        return line
    token = secret.strip().strip('"')
    if not token or len(token) < 2:
        return line
    return line.replace(token, REDACTED)


def hash_algorithm_of(token: str, cisco_type: str | None = None) -> str | None:
    """Identify the *algorithm* behind a credential without keeping the digest.

    Returns a name such as ``scrypt`` or ``reversible``, or ``None`` when the
    material is unrecognised. ``None`` is not ``"weak"``: an unrecognised
    algorithm is something we do not know, and it must reach the report as
    UNKNOWN rather than as a guess.
    """
    if cisco_type is not None:
        return _CISCO_TYPE_TO_ALGORITHM.get(cisco_type.strip())
    token = token.strip()
    for prefix, algorithm in _HASH_PREFIX_TO_ALGORITHM.items():
        if token.startswith(prefix):
            return algorithm
    return None


def fingerprint(secret: str, salt: bytes) -> str:
    """Salted, deployment-local digest for credential-reuse correlation.

    The salt is generated per deployment and never leaves it, so fingerprints
    are comparable *within* a fleet and meaningless outside it. That is the
    property that lets us report "the same administrator credential appears on
    30 devices" without ever holding the credential.
    """
    if not salt:
        raise ValueError("a deployment salt is required; an unsalted digest is a rainbow table")
    digest = hmac.new(salt, secret.strip().encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:32]
