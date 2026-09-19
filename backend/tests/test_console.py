"""The audit console, and the one property it must never lose.

A single Google Fonts link in a layout file makes the offline claim false in
front of an evaluator, and it is exactly the kind of thing that arrives silently
with a copied component. So it is checked here rather than remembered.
"""

from __future__ import annotations

import re

from conftest import REPO

CONSOLE = REPO / "frontend" / "public"

#: Anything that would make the browser reach off the deployment.
_EXTERNAL = re.compile(
    r"""(?:src|href|action|poster|data-src)\s*=\s*["']\s*(?:https?:)?//"""
    r"""|@import\s+(?:url\()?["']?\s*(?:https?:)?//"""
    r"""|url\(\s*["']?\s*(?:https?:)?//""",
    re.IGNORECASE,
)

_FONT_HOSTS = ("fonts.googleapis.com", "fonts.gstatic.com", "cdn.", "unpkg.com", "jsdelivr")


def _assets() -> list:  # type: ignore[type-arg]
    return sorted(p for p in CONSOLE.rglob("*") if p.suffix in {".html", ".css", ".js"})


def test_the_console_ships_with_the_repository():
    names = {p.name for p in _assets()}
    assert {"index.html", "styles.css", "app.js"} <= names


def test_no_asset_reaches_off_the_deployment():
    """The air-gap claim, enforced on the thing a judge will actually look at."""
    for path in _assets():
        text = path.read_text(encoding="utf-8")
        match = _EXTERNAL.search(text)
        assert match is None, (
            f"{path.name} references an external URL at offset {match.start()}: "
            f"{text[match.start() : match.start() + 60]!r}"
        )
        for host in _FONT_HOSTS:
            assert host not in text, f"{path.name} references {host}"


def test_typography_uses_system_faces_only():
    """No web fonts, so the type has to come from stacks the host already has.

    This is a design constraint the air gap imposed, and the styling depends on
    it: if someone swaps in a single-family declaration with no fallbacks, the
    page silently degrades to a default serif on half the machines it runs on.
    """
    css = (CONSOLE / "styles.css").read_text(encoding="utf-8")
    assert "@font-face" not in css, "an embedded font would have to be vendored and checked"
    for stack in ("--mono:", "--serif:"):
        assert stack in css
    # Every declared stack ends in a generic family.
    for declaration in re.findall(r"--(?:mono|serif):([^;]+);", css):
        assert declaration.strip().rstrip().split(",")[-1].strip() in {"monospace", "serif"}


def test_the_console_is_served_by_the_api():
    import tempfile
    from pathlib import Path

    from fastapi.testclient import TestClient

    from crucible.api.main import create_app

    client = TestClient(
        create_app(rules_path=REPO / "rules" / "cis", data_dir=Path(tempfile.mkdtemp()))
    )

    page = client.get("/")
    assert page.status_code == 200
    assert "CRUCIBLE" in page.text

    for asset in ("/static/styles.css", "/static/app.js"):
        response = client.get(asset)
        assert response.status_code == 200, asset
        assert response.content


def test_the_sample_fleet_endpoint_returns_a_full_audit():
    """The empty state offers one click. It has to produce something true."""
    import tempfile
    from pathlib import Path

    from fastapi.testclient import TestClient

    from crucible.api.main import create_app

    client = TestClient(
        create_app(rules_path=REPO / "rules" / "cis", data_dir=Path(tempfile.mkdtemp()))
    )
    payload = client.post("/demo").json()

    assert payload["devices"] == 5
    report = payload["reports"][0]
    assert report["findings"], "the sample fleet is deliberately misconfigured"
    assert report["coverage"]["total_lines"] > 0
    assert report["integrity"]["verification_hash"], "the console shows a hash that must be real"


def test_findings_carry_the_excerpt_the_console_renders():
    """The evidence gutter is the signature element; it needs real context.

    Without surrounding lines it degrades to a single quoted string, which is
    what every other tool already shows.
    """
    import tempfile
    from pathlib import Path

    from fastapi.testclient import TestClient

    from crucible.api.main import create_app

    client = TestClient(
        create_app(rules_path=REPO / "rules" / "cis", data_dir=Path(tempfile.mkdtemp()))
    )
    payload = client.post("/demo").json()

    checked = 0
    for report in payload["reports"]:
        for finding in report["findings"]:
            for evidence in finding["evidence"]:
                context = evidence["context"]
                assert context, f"{finding['rule_id']}: citation has no surrounding lines"
                cited = [line for line in context if line["cited"]]
                assert len(cited) == 1, "exactly one line in an excerpt is the cited one"
                assert cited[0]["line"] == evidence["line"]
                checked += 1
    assert checked > 10, "expected the sample fleet to produce evidence worth checking"
