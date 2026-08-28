"""Ed25519 signing for reports and adapter packs.

The signing key belongs to the deployment, is generated at installation, never
leaves the host, and is not in this repository - nor is any key material, ever.

Verification needs three things and nothing else: the report, the ledger, and
the issuing public key. That is what makes an air-gapped deployment able to
prove a report from three years ago is unaltered, on a machine with no network.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from crucible.common.canonical import sha256_hex
from crucible.common.errors import LedgerError

__all__ = ["SigningKey", "VerifyingKey", "load_or_create_key"]


class SigningKey:
    """A deployment signing key. Private material never leaves this object."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: Ed25519PrivateKey, key_id: str) -> None:
        self._key = key
        self.key_id = key_id

    @classmethod
    def generate(cls) -> "SigningKey":
        key = Ed25519PrivateKey.generate()
        return cls(key, _key_id(key.public_key()))

    @classmethod
    def load(cls, path: str | Path) -> "SigningKey":
        data = Path(path).read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise LedgerError(f"{path} is not an Ed25519 private key")
        return cls(key, _key_id(key.public_key()))

    def save(self, path: str | Path) -> None:
        """Write the key with owner-only permissions.

        The mode is set before any bytes are written, not after. A key that is
        world-readable for even a moment has been disclosed.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def verifying_key(self) -> "VerifyingKey":
        return VerifyingKey(self._key.public_key(), self.key_id)

    def public_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class VerifyingKey:
    """The public half. This is what an independent verifier needs."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: Ed25519PublicKey, key_id: str) -> None:
        self._key = key
        self.key_id = key_id

    @classmethod
    def load(cls, path: str | Path) -> "VerifyingKey":
        key = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise LedgerError(f"{path} is not an Ed25519 public key")
        return cls(key, _key_id(key))

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            self._key.verify(bytes.fromhex(signature), message)
        except (InvalidSignature, ValueError):
            return False
        return True


def _key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sha256_hex(raw)[:16]


def load_or_create_key(path: str | Path) -> SigningKey:
    """Load the deployment key, generating it on first run.

    Generating on first use is deliberate: an installation that requires a key
    ceremony before it can produce a report is an installation that gets run
    with signing switched off.
    """
    target = Path(path)
    if target.exists():
        return SigningKey.load(target)
    key = SigningKey.generate()
    key.save(target)
    public_path = target.with_suffix(".pub")
    public_path.write_bytes(key.public_pem())
    return key
