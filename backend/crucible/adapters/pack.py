"""Vendor Adapter Packs: signed, portable, data-only vendor knowledge.

Export a pack from one deployment, import it into another, and that instance
speaks the new vendor too - with no code written and no software update
shipped. Specification: docs/06-adapter-packs.md.

Three refusals are enforced here, because each one closes a real attack:

1. **Unsigned or badly signed packs are refused**, never warned about. A pack
   that maps ``telnet disabled=no`` to ``telnet_enabled: false`` would produce a
   clean audit on a wide-open device.
2. **Packs from keys outside the local trust store are refused.** Trusting a
   key is an explicit administrative act, never a side effect of importing a
   file.
3. **Packs that carry customer data are refused at export.** A pack is shared
   between organisations, so it may carry knowledge of a grammar and never a
   fragment of someone's configuration: no literal addresses, hostnames or
   credential-shaped strings in any match expression.
"""

from __future__ import annotations

import base64
import datetime as _dt
import re
from collections.abc import Iterable
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from crucible import IR_SCHEMA_VERSION
from crucible.adapters.transforms import TRANSFORMS
from crucible.common.canonical import canonical_bytes, sha256_hex
from crucible.common.errors import LedgerError, PackError
from crucible.ir.paths import PACK_PATHS
from crucible.ledger.signing import SigningKey, VerifyingKey

__all__ = [
    "PACK_SCHEMA_VERSION",
    "AdapterPack",
    "Mapping",
    "TrustStore",
    "load_pack",
    "load_packs",
]

PACK_SCHEMA_VERSION = "1.0.0"
GRAMMARS = frozenset(
    {"brace_hierarchy", "indent_blocks", "marker_blocks", "flat_path_prefixed", "xml", "json"}
)
_PACK_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_MAX_PATTERN = 400

# -- privacy guard ----------------------------------------------------------

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?i)\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_FQDN = re.compile(r"(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+){2,}\b")
_SECRETISH = re.compile(r"(?<![\w\\])[A-Za-z0-9+/$]{24,}")
_CRYPT = re.compile(r"\$\d\$")


def _unescape(pattern: str) -> str:
    """Reduce a pattern to the literal text it would match.

    An escaped address must be seen as the address it is. Character-class
    escapes such as ``\\s+`` and ``\\d`` are not literals, so they become spaces
    rather than the letters ``s`` and ``d`` - otherwise a harmless
    ``telnet\\s+server`` reads as one long credential-shaped token.
    """
    classes = re.sub(r"\\[sSdDwWbB][+*?]?", " ", pattern)
    return re.sub(r"\\(.)", r"\1", classes)


def customer_data_in(pattern: str) -> str | None:
    """Return a description of any customer data found, or ``None``."""
    text = _unescape(pattern)
    for name, detector in (
        ("an IPv4 address", _IPV4),
        ("an IPv6 address", _IPV6),
        ("an email address", _EMAIL),
        ("a hostname", _FQDN),
        ("a credential hash", _CRYPT),
        ("a credential-shaped literal", _SECRETISH),
    ):
        match = detector.search(text)
        if match:
            return f"{name} ({match.group(0)!r})"
    return None


# A pattern like (a+)+ can take exponential time on a crafted line. Packs come
# from other organisations, so the cheapest known shapes are refused outright.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


def _compile(pattern: str, where: str) -> re.Pattern[str]:
    if len(pattern) > _MAX_PATTERN:
        raise PackError(f"{where}: pattern longer than {_MAX_PATTERN} characters")
    if _NESTED_QUANTIFIER.search(pattern):
        raise PackError(f"{where}: nested quantifiers are refused (catastrophic backtracking)")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise PackError(f"{where}: invalid pattern: {exc}") from exc


# -- model ------------------------------------------------------------------


@dataclass(slots=True)
class Mapping:
    """One learned line-to-IR mapping. Applied deterministically, always."""

    ir_path: str
    match: str
    transform: str
    tier_learned: int
    confidence: float | None = None
    confirmed_by: str | None = None
    samples: int = 0
    #: For ``lookup``: captured token -> IR value.
    values: dict[str, Any] | None = None
    #: Only apply inside a block whose header matches this pattern, for
    #: statements whose meaning depends on where they sit.
    within: str | None = None
    _regex: re.Pattern[str] | None = field(default=None, repr=False, compare=False)
    _within: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    @property
    def regex(self) -> re.Pattern[str]:
        if self._regex is None:
            self._regex = _compile(self.match, self.ir_path)
        return self._regex

    @property
    def within_regex(self) -> re.Pattern[str] | None:
        if self.within and self._within is None:
            self._within = _compile(self.within, f"{self.ir_path} within")
        return self._within

    @property
    def confidence_bp(self) -> int:
        if self.tier_learned == 3:
            # A human confirmed it against their own file.
            return 10000
        return round((self.confidence or 0.0) * 10000)

    def validate(self, index: int) -> None:
        where = f"mapping {index} ({self.ir_path})"
        if self.ir_path not in PACK_PATHS:
            raise PackError(f"{where}: {self.ir_path!r} is not an IR {IR_SCHEMA_VERSION} path")
        if self.transform not in TRANSFORMS:
            raise PackError(f"{where}: unknown transform {self.transform!r}")
        if self.tier_learned not in (2, 3):
            raise PackError(f"{where}: tier_learned must be 2 or 3")
        if self.tier_learned == 2 and self.confidence is None:
            raise PackError(f"{where}: a tier-2 mapping must record its confidence")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise PackError(f"{where}: confidence out of range")
        regex = self.regex
        needs_value = self.transform not in ("presence", "negated_presence")
        if needs_value and "value" not in regex.groupindex:
            raise PackError(f"{where}: pattern has no (?P<value>...) group")
        if self.transform == "lookup" and not self.values:
            raise PackError(f"{where}: lookup transform needs a values table")
        if self.values:
            for mapped in self.values.values():
                if not isinstance(mapped, bool | int | str):
                    raise PackError(f"{where}: lookup values must be plain scalars")
        _ = self.within_regex
        for label, pattern in (("match", self.match), ("within", self.within or "")):
            leak = customer_data_in(pattern)
            if leak:
                raise PackError(f"{where}: {label} contains {leak}; packs carry grammar, not data")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ir_path": self.ir_path,
            "match": self.match,
            "transform": self.transform,
            "tier_learned": self.tier_learned,
        }
        if self.confidence is not None:
            data["confidence"] = round(self.confidence, 4)
        if self.confirmed_by:
            data["confirmed_by"] = self.confirmed_by
        data["samples"] = int(self.samples)
        if self.values:
            data["values"] = dict(self.values)
        if self.within:
            data["within"] = self.within
        return data

    @classmethod
    def from_dict(cls, raw: MappingABC[str, Any]) -> Mapping:
        allowed = {
            "ir_path",
            "match",
            "transform",
            "tier_learned",
            "confidence",
            "confirmed_by",
            "samples",
            "values",
            "within",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise PackError(f"mapping has unknown fields: {', '.join(sorted(unknown))}")
        try:
            return cls(
                ir_path=str(raw["ir_path"]),
                match=str(raw["match"]),
                transform=str(raw["transform"]),
                tier_learned=int(raw["tier_learned"]),
                confidence=float(raw["confidence"]) if raw.get("confidence") is not None else None,
                confirmed_by=str(raw["confirmed_by"]) if raw.get("confirmed_by") else None,
                samples=int(raw.get("samples") or 0),
                values=dict(raw["values"]) if raw.get("values") else None,
                within=str(raw["within"]) if raw.get("within") else None,
            )
        except KeyError as exc:
            raise PackError(f"mapping is missing {exc.args[0]}") from exc


@dataclass(slots=True)
class AdapterPack:
    """A whole pack. Construct via :func:`load_pack` or the training session."""

    id: str
    vendor: str
    mappings: list[Mapping]
    grammar: dict[str, Any] = field(default_factory=lambda: {"kind": "indent_blocks"})
    os: str | None = None
    os_versions: str | None = None
    created: str = ""
    author: str | None = None
    description: str | None = None
    ir_version: str = IR_SCHEMA_VERSION
    fingerprint: list[dict[str, Any]] = field(default_factory=list)
    signature: dict[str, str] | None = None

    # -- validation ---------------------------------------------------------

    def validate(self) -> None:
        if not _PACK_ID.match(self.id):
            raise PackError(f"pack id {self.id!r} must be 3-64 lowercase characters")
        if not self.vendor or not re.match(r"^[a-z0-9_-]+$", self.vendor):
            raise PackError(f"{self.id}: vendor must be a lowercase identifier")
        if self.ir_version != IR_SCHEMA_VERSION:
            raise PackError(
                f"{self.id}: targets IR {self.ir_version}, this build speaks {IR_SCHEMA_VERSION}"
            )
        kind = self.grammar.get("kind")
        if kind not in GRAMMARS:
            raise PackError(f"{self.id}: unknown grammar kind {kind!r}")
        if not self.mappings:
            raise PackError(f"{self.id}: a pack must carry at least one mapping")
        for index, mapping in enumerate(self.mappings):
            mapping.validate(index)
        for index, signature in enumerate(self.fingerprint):
            pattern = str(signature.get("match", ""))
            _compile(pattern, f"fingerprint {index}")
            leak = customer_data_in(pattern)
            if leak:
                raise PackError(f"{self.id}: fingerprint {index} contains {leak}")
            confidence = signature.get("confidence", 0.5)
            if not isinstance(confidence, int | float) or not 0 <= confidence <= 1:
                raise PackError(f"{self.id}: fingerprint {index} confidence out of range")

    # -- identity -----------------------------------------------------------

    def fingerprint_score(self, text: str) -> float:
        """How strongly this pack's signatures match a file, 0 to 1."""
        score = 0.0
        for signature in self.fingerprint:
            if re.search(str(signature["match"]), text, re.MULTILINE):
                score += float(signature.get("confidence", 0.5))
        return min(score, 1.0)

    @property
    def digest(self) -> str:
        return sha256_hex(self.signing_material())[:16]

    # -- serialisation ------------------------------------------------------

    def to_dict(self, *, signature: bool = True) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema_version": PACK_SCHEMA_VERSION,
            "pack": {
                "id": self.id,
                "vendor": self.vendor,
                "os": self.os,
                "os_versions": self.os_versions,
                "ir_version": self.ir_version,
                "created": self.created,
                "author": self.author,
                "description": self.description,
            },
            "grammar": dict(self.grammar),
            "fingerprint": [dict(f) for f in self.fingerprint],
            "mappings": [m.to_dict() for m in self.mappings],
        }
        if signature and self.signature:
            document["signature"] = dict(self.signature)
        return document

    def to_yaml(self) -> str:
        header = (
            "# Crucible Vendor Adapter Pack - data only, signed. See docs/06-adapter-packs.md.\n"
            "# Editing this file by hand invalidates the signature; re-export instead.\n"
        )
        return header + yaml.safe_dump(self.to_dict(), sort_keys=False, allow_unicode=True)

    def signing_material(self) -> bytes:
        """Canonical bytes of everything except the signature.

        Floats are banned from canonical serialisation, so confidences are
        committed to as fixed four-decimal strings.
        """
        return canonical_bytes(_floats_to_text(self.to_dict(signature=False)))

    # -- signing ------------------------------------------------------------

    def sign(self, key: SigningKey) -> None:
        self.validate()
        signature = bytes.fromhex(key.sign(self.signing_material()))
        self.signature = {
            "algorithm": "ed25519",
            "key_id": key.key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        }

    def verify_with(self, key: VerifyingKey) -> bool:
        if not self.signature or self.signature.get("algorithm") != "ed25519":
            return False
        if self.signature.get("key_id") != key.key_id:
            return False
        try:
            raw = base64.b64decode(self.signature.get("value", ""), validate=True)
        except (ValueError, TypeError):
            return False
        return key.verify(self.signing_material(), raw.hex())

    # -- construction -------------------------------------------------------

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterPack:
        if not isinstance(raw, dict):
            raise PackError("a pack must be a mapping")
        if str(raw.get("schema_version")) != PACK_SCHEMA_VERSION:
            raise PackError(f"unsupported pack schema {raw.get('schema_version')!r}")
        meta = raw.get("pack")
        if not isinstance(meta, dict):
            raise PackError("pack metadata is missing")
        mappings = raw.get("mappings")
        if not isinstance(mappings, list):
            raise PackError("mappings must be a list")
        created = meta.get("created") or ""
        if isinstance(created, _dt.date):
            created = created.isoformat()
        pack = cls(
            id=str(meta.get("id", "")),
            vendor=str(meta.get("vendor", "")),
            os=meta.get("os"),
            os_versions=meta.get("os_versions"),
            created=str(created),
            author=meta.get("author"),
            description=meta.get("description"),
            ir_version=str(meta.get("ir_version", "")),
            grammar=dict(raw.get("grammar") or {}),
            fingerprint=[dict(f) for f in raw.get("fingerprint") or []],
            mappings=[Mapping.from_dict(m) for m in mappings],
            signature=dict(raw["signature"]) if raw.get("signature") else None,
        )
        pack.validate()
        return pack


def _floats_to_text(value: Any) -> Any:
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, dict):
        return {k: _floats_to_text(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_floats_to_text(v) for v in value]
    return value


def load_pack(source: str | Path) -> AdapterPack:
    """Parse and validate a pack from a path or from YAML text.

    Validation only. Whether the pack is *trusted* is a separate question,
    answered by :class:`TrustStore` - see :meth:`TrustStore.admit`.
    """
    text: str
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source):
        path = Path(source)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise PackError(f"cannot read pack {path}: {exc}") from exc
    else:
        text = source
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PackError(f"pack is not valid YAML: {exc}") from exc
    return AdapterPack.from_dict(raw)


# -- trust ------------------------------------------------------------------


class TrustStore:
    """Public keys whose packs this deployment accepts. Offline, file-based.

    One PEM file per key, named by key id. Adding a key is an explicit call to
    :meth:`add` - importing a pack never adds its signer.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def keys(self) -> dict[str, VerifyingKey]:
        found: dict[str, VerifyingKey] = {}
        if not self.directory.is_dir():
            return found
        for path in sorted(self.directory.glob("*.pub")):
            try:
                key = VerifyingKey.load(path)
            except Exception:  # noqa: S112 - a corrupt key file is skipped, never trusted
                continue
            found[key.key_id] = key
        return found

    def add(self, public_pem: bytes) -> str:
        """Trust a publisher. Returns the key id now accepted."""
        try:
            key = VerifyingKey.from_pem(public_pem)
        except LedgerError as exc:
            raise PackError(str(exc)) from exc
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / f"{key.key_id}.pub").write_bytes(key.public_pem())
        return key.key_id

    def remove(self, key_id: str) -> bool:
        target = self.directory / f"{key_id}.pub"
        if target.exists():
            target.unlink()
            return True
        return False

    def admit(self, pack: AdapterPack) -> str:
        """Return the signing key id if the pack is signed by a trusted key.

        Raises :class:`PackError` otherwise. There is no "import anyway".
        """
        if not pack.signature:
            raise PackError(f"{pack.id}: pack is unsigned and was refused")
        key_id = pack.signature.get("key_id", "")
        key = self.keys().get(key_id)
        if key is None:
            raise PackError(
                f"{pack.id}: signed by {key_id or 'an unnamed key'}, which is not in the trust "
                "store. Trusting a publisher is an explicit administrative action."
            )
        if not pack.verify_with(key):
            raise PackError(f"{pack.id}: signature does not verify - the pack was altered")
        return key_id


def load_packs(directory: str | Path, trust: TrustStore) -> list[AdapterPack]:
    """Every trusted pack in a directory. An untrusted one stops the load.

    Refusing loudly is deliberate: a deployment that silently skips a pack it
    was told to use audits a vendor with less knowledge than its operator
    believes it has.
    """
    root = Path(directory)
    if not root.is_dir():
        return []
    packs: list[AdapterPack] = []
    seen: set[str] = set()
    for path in sorted(root.glob("*.y*ml")):
        pack = load_pack(path)
        trust.admit(pack)
        if pack.id in seen:
            raise PackError(f"two packs share the id {pack.id}")
        seen.add(pack.id)
        packs.append(pack)
    return packs


def export_ready(pack: AdapterPack) -> str:
    """The YAML to hand to another organisation. Must already be signed."""
    pack.validate()
    if not pack.signature:
        raise PackError(f"{pack.id}: sign a pack before exporting it")
    return pack.to_yaml()


def packs_for(packs: Iterable[AdapterPack], vendor: str, os_name: str | None) -> list[AdapterPack]:
    """Packs that apply to a device the fingerprinter has already named."""
    return [
        p
        for p in packs
        if p.vendor == vendor and (p.os is None or os_name is None or p.os == os_name)
    ]
