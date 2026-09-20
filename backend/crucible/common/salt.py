"""The deployment salt behind credential fingerprints.

Credential reuse across a fleet is detected by comparing salted digests of
credential material, never the material itself. The salt is generated once per
deployment, stays in its state directory, and never leaves it - so fingerprints
are comparable *within* one fleet and meaningless anywhere else.

It must also be stable: an IR export is canonicalised and hashed into the
ledger, so a salt that changed per process would make two audits of one
unchanged device produce two different reports.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

__all__ = ["deployment_salt", "salt_path"]

_ENV = "CRUCIBLE_FINGERPRINT_SALT"
_cache: bytes | None = None


def salt_path() -> Path:
    home = os.environ.get("CRUCIBLE_HOME") or str(Path.home() / ".crucible")
    return Path(home) / "signing" / "fingerprint.salt"


def deployment_salt() -> bytes:
    """Load the salt, generating it on first use.

    ``CRUCIBLE_FINGERPRINT_SALT`` overrides it, which is how a test, a CI job
    or a second instance reproduces another deployment's fingerprints
    deliberately.
    """
    global _cache
    override = os.environ.get(_ENV)
    if override:
        return override.encode("utf-8")
    if _cache is not None:
        return _cache

    path = salt_path()
    if path.exists():
        _cache = path.read_bytes().strip()
        if _cache:
            return _cache
    generated = secrets.token_bytes(32).hex().encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(generated)
    _cache = generated
    return generated
