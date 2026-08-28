"""HTTP API for the dashboard.

The same :func:`crucible.api.runner.run_audit` the CLI drives, exposed over
HTTP so the Next.js frontend can bulk-upload and render results. There is
deliberately no second code path: a dashboard that computed its own verdicts
would eventually disagree with the signed PDF, and then neither could be
trusted.

**Deployment note.** This service binds to the deployment only. It makes no
outbound requests of any kind, and it must be run behind the operator's own
authentication - there is none here, because inventing a half-authentication
scheme is worse than being explicit that this belongs on an internal network.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from crucible import IR_SCHEMA_VERSION, __version__
from crucible.api.runner import run_audit
from crucible.common.errors import CrucibleError
from crucible.ledger.chain import Ledger
from crucible.ledger.signing import VerifyingKey
from crucible.policy.ruleset import load_rules

__all__ = ["app", "create_app"]

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_RULES = REPO_ROOT / "rules" / "cis"
DATA_DIR = Path(tempfile.gettempdir()) / "crucible-data"


def create_app(rules_path: Path | None = None, data_dir: Path | None = None) -> FastAPI:
    rules = rules_path or DEFAULT_RULES
    data = data_dir or DATA_DIR
    data.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="Crucible",
        version=__version__,
        description=(
            "AI-driven multi-vendor network security compliance auditor. "
            "Runs fully offline: no outbound network call in any code path."
        ),
    )

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Liveness, and the posture the service is running under.

        The offline flag is reported rather than assumed, so an operator can see
        on the dashboard what the reports being generated are claiming.
        """
        return {
            "status": "ok",
            "version": __version__,
            "ir_schema_version": IR_SCHEMA_VERSION,
            "offline": True,
        }

    @app.get("/rules")
    def rules_endpoint(framework: str | None = None) -> dict[str, Any]:
        ruleset = load_rules(rules)
        if framework:
            ruleset = ruleset.for_framework(framework)
        return {
            "count": len(ruleset),
            "digest": ruleset.version_digest,
            "frameworks": ruleset.frameworks(),
            "rules": [
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity.value,
                    "frameworks": rule.frameworks,
                    "assert": rule.assertion.source,
                    "verifiable": rule.verifiable,
                }
                for rule in ruleset
            ],
        }

    @app.post("/audit")
    async def audit(files: list[UploadFile], framework: str | None = None) -> JSONResponse:
        """Upload one or many configuration files and audit them.

        Uploads land in a per-request directory that is deleted before the
        response is returned. Configuration files are blueprints of a network's
        defences; the service should not accumulate them on disk as a side
        effect of someone clicking a button.
        """
        if not files:
            raise HTTPException(status_code=400, detail="no files supplied")

        workdir = Path(tempfile.mkdtemp(prefix="crucible-upload-", dir=data))
        try:
            names = [Path(u.filename or "unnamed.cfg").name for u in files]
            # Group the upload under a directory named after the configuration
            # file, so the device is identified as "core-sw-01" rather than as
            # the temporary directory it happened to land in. That name reaches
            # the report id, the artefact filenames and the ledger entry.
            primary = next(
                (n for n in names if "version" not in n.lower()), names[0]
            )
            device_dir = workdir / (primary.split(".")[0] or "device")
            device_dir.mkdir(parents=True, exist_ok=True)

            for upload, name in zip(files, names):
                (device_dir / name).write_bytes(await upload.read())

            job = run_audit(
                workdir,
                rules_path=rules,
                output_dir=data / "reports",
                framework=framework,
                formats=("json", "md", "pdf"),
                workdir=workdir,
            )
            payload = job.to_dict()
            payload["artefacts"] = {
                result.device_id: {k: Path(v).name for k, v in result.artefacts.items()}
                for result in job.results
            }
            return JSONResponse(payload)
        except CrucibleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    @app.get("/reports/{filename}")
    def download(filename: str) -> FileResponse:
        # Resolve and confine: a report name arrives from the client, and path
        # traversal here would serve any file the process can read.
        target = (data / "reports" / Path(filename).name).resolve()
        root = (data / "reports").resolve()
        if root not in target.parents or not target.exists():
            raise HTTPException(status_code=404, detail="no such report")
        return FileResponse(target)

    @app.get("/ledger")
    def ledger_endpoint() -> dict[str, Any]:
        """Ledger state and whether it still verifies."""
        path = data / "reports" / "ledger.jsonl"
        if not path.exists():
            return {"entries": 0, "verified": None, "problems": []}

        ledger = Ledger.open(path)
        key_path = data / "reports" / "signing" / "ed25519.pub"
        key = VerifyingKey.load(key_path) if key_path.exists() else None
        ok, problems = ledger.verify(key)
        return {
            "entries": len(ledger),
            "head": ledger.head,
            "verified": ok,
            "signature_checked": key is not None,
            "problems": problems,
            "log": [
                {
                    "seq": entry.seq,
                    "timestamp": entry.timestamp,
                    "device_id": entry.device_id,
                    "report_id": entry.report_id,
                    "verification_hash": entry.verification_hash,
                }
                for entry in ledger
            ],
        }

    return app


app = create_app()
