"""The training and pack routes, end to end over HTTP.

Skipped when FastAPI is not installed, like the console tests: the pipeline
itself must run on the standard library plus three packages.
"""

from __future__ import annotations

import tempfile
from pathlib import Path


def _client(home: Path | None = None):  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from crucible.api.main import create_app

    data = Path(tempfile.mkdtemp(prefix="crucible-api-data-"))
    home = home or Path(tempfile.mkdtemp(prefix="crucible-api-home-"))
    return TestClient(create_app(data_dir=data, home_dir=home)), home


def _have_fastapi() -> bool:
    try:
        import fastapi  # noqa: F401
        import httpx  # noqa: F401
    except ImportError:
        return False
    return True


def test_vocabulary_endpoint_lists_pack_writable_fields():
    if not _have_fastapi():
        return
    client, _ = _client()
    body = client.get("/train/fields").json()
    paths = {f["path"] for f in body["fields"]}
    assert "mgmt.telnet_enabled" in paths
    assert "lookup" in body["transforms"]


def test_train_the_unseen_sample_sign_and_reaudit():
    if not _have_fastapi():
        return
    client, _ = _client()
    session = client.post("/train/sample/huawei-vrp").json()
    assert session["vendor"] == "unknown"
    assert session["families"], "the unseen file should leave families to train"
    sid = session["session"]

    session = client.post(f"/train/{sid}/accept", json={"threshold": 0.85}).json()
    assert session["confirmed"], "confident proposals should have been accepted"

    preview = client.post(
        f"/train/{sid}/preview",
        json={
            "mapping": {
                "ir_path": "mgmt.ssh.enabled",
                "match": r"^stelnet\s+server\s+enable$",
                "transform": "presence",
            }
        },
    ).json()
    assert [h["line"] for h in preview["hits"]] == [12]

    confirmed = client.post(
        f"/train/{sid}/confirm",
        json={
            "mapping": {
                "ir_path": "mgmt.ssh.enabled",
                "match": r"^stelnet\s+server\s+enable$",
                "transform": "presence",
            },
            "confirmed_by": "admin@test",
        },
    ).json()
    assert any(m["tier_learned"] == 3 for m in confirmed["confirmed"])

    result = client.post(
        f"/train/{sid}/pack",
        json={"pack_id": "huawei-vrp", "vendor": "huawei", "os": "VRP", "author": "admin@test"},
    )
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["coverage_after"]["parsed"] > body["coverage_before"]["parsed"]
    report = body["audit"]["reports"][0]
    assert report["adapter_packs"] == ["huawei-vrp"]
    verdicts = {f["rule_id"]: f["verdict"] for f in report["findings"]}
    assert verdicts["CIS-NET-1.1.1"] == "fail"

    packs = client.get("/packs").json()["packs"]
    assert [p["id"] for p in packs] == ["huawei-vrp"]
    assert packs[0]["own"] is True


def test_an_unknown_mapping_field_is_rejected_with_a_reason():
    if not _have_fastapi():
        return
    client, _ = _client()
    sid = client.post("/train/sample/huawei-vrp").json()["session"]
    response = client.post(
        f"/train/{sid}/confirm",
        json={
            "mapping": {"ir_path": "mgmt.everything_ok", "match": "^x$", "transform": "presence"}
        },
    )
    assert response.status_code == 422
    assert "IR" in response.json()["detail"]


def test_import_needs_an_explicit_trust_decision():
    """Instance B refuses A's pack until an operator trusts A's publisher key."""
    if not _have_fastapi():
        return
    a, _ = _client()
    sid = a.post("/train/sample/huawei-vrp").json()["session"]
    a.post(f"/train/{sid}/accept", json={"threshold": 0.85})
    assert (
        a.post(f"/train/{sid}/pack", json={"pack_id": "vrp", "vendor": "huawei"}).status_code == 200
    )
    pack_yaml = a.get("/packs/vrp/export").text
    publisher = a.get("/trust/key").text

    b, _ = _client()
    refused = b.post("/packs/import", files={"file": ("vrp.yaml", pack_yaml)})
    assert refused.status_code == 403
    assert "trust store" in refused.json()["detail"]

    assert b.post("/trust", files={"file": ("a.pub", publisher)}).status_code == 200
    accepted = b.post("/packs/import", files={"file": ("vrp.yaml", pack_yaml)})
    assert accepted.status_code == 200, accepted.text

    audit = b.post(
        "/audit",
        files={"files": ("current-configuration.cfg", _vrp_text())},
    ).json()
    assert audit["reports"][0]["adapter_packs"] == ["vrp"]


def test_a_tampered_pack_is_refused_even_from_a_trusted_publisher():
    if not _have_fastapi():
        return
    a, _ = _client()
    sid = a.post("/train/sample/huawei-vrp").json()["session"]
    a.post(f"/train/{sid}/accept", json={"threshold": 0.85})
    a.post(f"/train/{sid}/pack", json={"pack_id": "vrp", "vendor": "huawei"})
    tampered = a.get("/packs/vrp/export").text.replace("to_bool", "invert_yes_no", 1)
    b, _ = _client()
    b.post("/trust", files={"file": ("a.pub", a.get("/trust/key").text)})
    response = b.post("/packs/import", files={"file": ("vrp.yaml", tampered)})
    assert response.status_code == 422
    assert "altered" in response.json()["detail"]


def test_uploaded_training_files_do_not_stay_on_disk():
    if not _have_fastapi():
        return
    from fastapi.testclient import TestClient

    from crucible.api.main import create_app

    data = Path(tempfile.mkdtemp(prefix="crucible-api-data-"))
    client = TestClient(create_app(data_dir=data, home_dir=Path(tempfile.mkdtemp())))
    response = client.post("/train", files={"files": ("current-configuration.cfg", _vrp_text())})
    assert response.status_code == 200, response.text
    leftovers = list(data.rglob("*.cfg"))
    assert leftovers == []


def _vrp_text() -> str:
    from conftest import TESTS

    path = TESTS / "fixtures" / "unseen" / "huawei-vrp-agg-01" / "current-configuration.cfg"
    return path.read_text(encoding="utf-8")
