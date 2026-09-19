"""Where a deployment keeps what outlives a single audit.

::

    $CRUCIBLE_HOME/                 (default ~/.crucible)
      signing/publisher.key         this deployment's Ed25519 key for signing packs
      signing/publisher.pub
      trust/<key id>.pub            publishers whose packs this deployment accepts
      packs/<pack id>.yaml          installed adapter packs, all signed

The deployment trusts its own publisher key: a pack you trained here is one you
already vouched for. Every other publisher is trusted only by an explicit
``crucible trust add`` or the equivalent button, never by importing a file.
"""

from __future__ import annotations

import os
from pathlib import Path

from crucible.adapters.pack import AdapterPack, TrustStore, export_ready, load_pack, load_packs
from crucible.common.errors import PackError
from crucible.ledger.signing import SigningKey, load_or_create_key

__all__ = ["Home"]


class Home:
    """A deployment's durable state directory."""

    def __init__(self, root: str | Path | None = None) -> None:
        default = os.environ.get("CRUCIBLE_HOME") or str(Path.home() / ".crucible")
        self.root = Path(root or default)

    @property
    def packs_dir(self) -> Path:
        return self.root / "packs"

    @property
    def trust(self) -> TrustStore:
        return TrustStore(self.root / "trust")

    def publisher_key(self) -> SigningKey:
        key = load_or_create_key(self.root / "signing" / "publisher.key")
        # Trusting yourself is the one implicit act, and it is safe: the key
        # never leaves this directory.
        if key.key_id not in self.trust.keys():
            self.trust.add(key.public_pem())
        return key

    def public_pem(self) -> bytes:
        return self.publisher_key().public_pem()

    def packs(self) -> list[AdapterPack]:
        """Every installed pack, each admitted by the trust store."""
        self.publisher_key()
        return load_packs(self.packs_dir, self.trust)

    def install(self, pack: AdapterPack, *, replace: bool = False) -> Path:
        """Install a pack after the trust store admits it."""
        self.publisher_key()
        self.trust.admit(pack)
        self.packs_dir.mkdir(parents=True, exist_ok=True)
        target = self.packs_dir / f"{pack.id}.yaml"
        if target.exists() and not replace:
            existing = load_pack(target)
            if existing.digest != pack.digest:
                raise PackError(
                    f"a different pack with id {pack.id} is already installed; remove it first"
                )
        target.write_text(export_ready(pack), encoding="utf-8")
        return target

    def remove(self, pack_id: str) -> bool:
        target = self.packs_dir / f"{pack_id}.yaml"
        if target.exists():
            target.unlink()
            return True
        return False

    def get(self, pack_id: str) -> AdapterPack:
        target = self.packs_dir / f"{pack_id}.yaml"
        if not target.exists():
            raise PackError(f"no installed pack {pack_id}")
        pack = load_pack(target)
        self.trust.admit(pack)
        return pack
