"""HTTP routes for Tiers 2 and 3, adapter packs and publisher trust.

Kept apart from :mod:`crucible.api.main` so the audit surface stays small. The
same rule applies here as to audit uploads: a configuration is a blueprint of
a network's defences, so a training session holds it **in memory only** and
forgets it when the session ends, expires, or the process stops.
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse, Response

from crucible.adapters.pack import Mapping, export_ready, load_pack
from crucible.adapters.transforms import TRANSFORMS
from crucible.api.home import Home
from crucible.api.runner import run_audit
from crucible.common.errors import CrucibleError, PackError
from crucible.ingest.bundle import DeviceBundle, load
from crucible.ir.paths import PACK_PATHS
from crucible.training.proposer import default_proposer
from crucible.training.session import DEFAULT_ACCEPT_ABOVE, TrainingSession
from crucible.training.vocabulary import VOCABULARY

__all__ = ["register_learning"]

#: How many sessions are held at once, and for how long. Old ones are dropped,
#: and with them the configuration they held.
MAX_SESSIONS = 16
SESSION_TTL_SECONDS = 3600

_REPO = Path(__file__).resolve().parents[3]
SAMPLES: dict[str, tuple[Path, tuple[str, ...]]] = {
    # An unseen vendor: no Tier-0 parser, no fingerprint signature in this build.
    "huawei-vrp": (_REPO / "backend" / "tests" / "fixtures" / "unseen" / "huawei-vrp-agg-01", ()),
    # The held-out vendor: its built-in parser is switched off for the session.
    "mikrotik-held-out": (
        _REPO / "backend" / "tests" / "fixtures" / "devices" / "routeros-branch-01",
        ("mikrotik",),
    ),
}


class _Sessions:
    def __init__(self) -> None:
        self._items: OrderedDict[str, tuple[float, TrainingSession]] = OrderedDict()
        self._lock = threading.Lock()

    def add(self, session: TrainingSession) -> None:
        with self._lock:
            self._expire()
            self._items[session.id] = (time.monotonic(), session)
            while len(self._items) > MAX_SESSIONS:
                self._items.popitem(last=False)

    def get(self, session_id: str) -> TrainingSession:
        with self._lock:
            self._expire()
            item = self._items.get(session_id)
            if item is None:
                raise HTTPException(status_code=404, detail="no such training session")
            self._items[session_id] = (time.monotonic(), item[1])
            return item[1]

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._items.pop(session_id, None)

    def _expire(self) -> None:
        now = time.monotonic()
        for key in [k for k, (t, _) in self._items.items() if now - t > SESSION_TTL_SECONDS]:
            del self._items[key]


def _mapping(payload: Any) -> Mapping:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="mapping must be an object")
    body = dict(payload)
    body.setdefault("tier_learned", 3)
    try:
        mapping = Mapping.from_dict(body)
        mapping.validate(0)
    except (PackError, ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return mapping


def register_learning(app: FastAPI, *, rules: Path, data: Path, home: Home) -> None:
    sessions = _Sessions()

    def proposer() -> Any:
        # Ollama when a local model is up; the offline lexical proposer otherwise.
        return default_proposer()

    # -- vocabulary -------------------------------------------------------------

    @app.get("/train/fields")
    def fields() -> dict[str, Any]:
        described = {spec.path: spec.description for spec in VOCABULARY}
        return {
            "fields": [
                {"path": path, "kind": kind, "description": described.get(path, "")}
                for path, kind in PACK_PATHS.items()
            ],
            "transforms": sorted(TRANSFORMS),
            "accept_above": DEFAULT_ACCEPT_ABOVE,
        }

    # -- sessions ---------------------------------------------------------------

    def _open(bundle: DeviceBundle, hold_out: tuple[str, ...]) -> dict[str, Any]:
        session = TrainingSession(
            bundle, packs=home.packs(), hold_out=hold_out, proposer=proposer()
        )
        sessions.add(session)
        return session.summary()

    @app.post("/train")
    async def train_upload(files: list[UploadFile], hold_out: str | None = None) -> dict[str, Any]:
        if not files:
            raise HTTPException(status_code=400, detail="no files supplied")
        # Through the ordinary ingest path, so show-version files and archives
        # are classified exactly as an audit would. The files are read into
        # memory and the directory is gone before the response is sent.
        workdir = Path(tempfile.mkdtemp(prefix="crucible-train-", dir=data))
        try:
            names = [Path(u.filename or "config.txt").name for u in files]
            primary = next((n for n in names if "version" not in n.lower()), names[0])
            device_dir = workdir / (primary.split(".")[0] or "device")
            device_dir.mkdir(parents=True, exist_ok=True)
            for upload, name in zip(files, names, strict=True):
                (device_dir / name).write_bytes(await upload.read())
            bundles = load(workdir, workdir=workdir)
        except CrucibleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        if not bundles:
            raise HTTPException(status_code=422, detail="no readable configuration in that upload")
        return _open(bundles[0], (hold_out,) if hold_out else ())

    @app.post("/train/sample/{name}")
    def train_sample(name: str) -> dict[str, Any]:
        if name not in SAMPLES:
            raise HTTPException(status_code=404, detail="no such sample")
        path, hold_out = SAMPLES[name]
        if not path.exists():
            raise HTTPException(status_code=404, detail="the sample is not installed")
        return _open(load(path)[0], hold_out)

    @app.get("/train/{session_id}")
    def train_get(session_id: str) -> dict[str, Any]:
        return sessions.get(session_id).summary()

    @app.delete("/train/{session_id}")
    def train_drop(session_id: str) -> dict[str, Any]:
        sessions.drop(session_id)
        return {"dropped": session_id}

    @app.post("/train/{session_id}/preview")
    def train_preview(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
        session = sessions.get(session_id)
        mapping = _mapping(body.get("mapping"))
        return {"hits": session.preview(mapping)}

    @app.post("/train/{session_id}/confirm")
    def train_confirm(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
        session = sessions.get(session_id)
        mapping = _mapping(body.get("mapping"))
        try:
            session.confirm(mapping, confirmed_by=str(body.get("confirmed_by") or "administrator"))
        except PackError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return session.summary()

    @app.post("/train/{session_id}/withdraw")
    def train_withdraw(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
        session = sessions.get(session_id)
        session.withdraw(str(body.get("match", "")))
        return session.summary()

    @app.post("/train/{session_id}/accept")
    def train_accept(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
        session = sessions.get(session_id)
        threshold = float(body.get("threshold", DEFAULT_ACCEPT_ABOVE))
        session.accept_proposals(max(threshold, 0.5))
        return session.summary()

    @app.post("/train/{session_id}/pack")
    def train_pack(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Sign the pack, install it, and re-audit the file through the normal pipeline."""
        session = sessions.get(session_id)
        try:
            pack = session.build_pack(
                pack_id=str(body.get("pack_id", "")).strip().lower(),
                vendor=str(body.get("vendor", "")).strip().lower(),
                os=(str(body["os"]).strip() or None) if body.get("os") else None,
                author=(str(body["author"]).strip() or None) if body.get("author") else None,
                key=home.publisher_key(),
            )
            home.install(pack, replace=True)
        except PackError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        workdir = Path(tempfile.mkdtemp(prefix="crucible-train-", dir=data))
        try:
            device_dir = workdir / session.bundle.device_id
            for source in session.bundle.files:
                target = device_dir / Path(source.name).name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source.text, encoding="utf-8")
            job = run_audit(
                workdir,
                rules_path=rules,
                output_dir=data / "reports",
                formats=("json", "md", "pdf"),
                packs=home.packs(),
                hold_out=session.hold_out,
                workdir=workdir,
            )
        except CrucibleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

        before = session.device.ir.coverage
        after = job.results[0].report.coverage if job.results else {}
        return {
            "pack": {
                "id": pack.id,
                "vendor": pack.vendor,
                "mappings": len(pack.mappings),
                "digest": pack.digest,
                "key_id": (pack.signature or {}).get("key_id"),
            },
            "coverage_before": {"parsed": before.parsed_lines, "total": before.total_lines},
            "coverage_after": {
                "parsed": after.get("parsed_lines", 0),
                "total": after.get("total_lines", 0),
            },
            "audit": job.to_dict(),
        }

    # -- packs ------------------------------------------------------------------

    @app.get("/packs")
    def packs_list() -> dict[str, Any]:
        own = home.publisher_key().key_id
        return {
            "publisher": own,
            "packs": [
                {
                    "id": p.id,
                    "vendor": p.vendor,
                    "os": p.os,
                    "mappings": len(p.mappings),
                    "tier3": sum(1 for m in p.mappings if m.tier_learned == 3),
                    "key_id": (p.signature or {}).get("key_id"),
                    "own": (p.signature or {}).get("key_id") == own,
                    "digest": p.digest,
                    "created": p.created,
                }
                for p in home.packs()
            ],
        }

    @app.get("/packs/{pack_id}/export")
    def packs_export(pack_id: str) -> Response:
        try:
            text = export_ready(home.get(pack_id))
        except PackError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            text,
            media_type="application/x-yaml",
            headers={"Content-Disposition": f'attachment; filename="{pack_id}.yaml"'},
        )

    @app.delete("/packs/{pack_id}")
    def packs_remove(pack_id: str) -> dict[str, Any]:
        return {"removed": home.remove(pack_id)}

    @app.post("/packs/import")
    async def packs_import(file: UploadFile) -> dict[str, Any]:
        text = (await file.read()).decode("utf-8", errors="replace")
        try:
            pack = load_pack(text if "\n" in text else text + "\n")
            home.install(pack)
        except PackError as exc:
            # 403 for an untrusted signer, so the console can offer the explicit
            # "trust this publisher" step rather than a generic failure.
            status = 403 if "trust store" in str(exc) else 422
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {"imported": pack.id, "key_id": (pack.signature or {}).get("key_id")}

    # -- trust ------------------------------------------------------------------

    @app.get("/trust")
    def trust_list() -> dict[str, Any]:
        own = home.publisher_key().key_id
        return {"publisher": own, "trusted": sorted(home.trust.keys())}

    @app.get("/trust/key")
    def trust_key() -> PlainTextResponse:
        return PlainTextResponse(
            home.public_pem().decode("ascii"),
            headers={"Content-Disposition": 'attachment; filename="publisher.pub"'},
        )

    @app.post("/trust")
    async def trust_add(file: UploadFile) -> dict[str, Any]:
        try:
            key_id = home.trust.add(await file.read())
        except PackError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"trusted": key_id}
