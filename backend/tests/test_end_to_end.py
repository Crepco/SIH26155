"""The whole loop: files in, signed PDF out.

The Phase 1 definition of done, asserted. If this file passes, the baseline
pipeline works end to end across six vendors - which is the thing that has to
be true before any differentiator is worth starting.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from conftest import DEVICES, RULES

from crucible.api.runner import run_audit
from crucible.ledger.chain import Ledger
from crucible.ledger.signing import VerifyingKey


def _out() -> Path:
    return Path(tempfile.mkdtemp())


def test_bulk_audit_produces_a_report_per_device():
    """Drop in six devices from six vendors, get six signed reports."""
    output = _out()
    job = run_audit(DEVICES, rules_path=RULES, output_dir=output)

    assert len(job.results) == 6
    for result in job.results:
        assert result.artefacts["pdf"], f"{result.device_id}: no PDF"
        assert Path(result.artefacts["pdf"]).stat().st_size > 4000
        assert Path(result.artefacts["json"]).exists()
        assert Path(result.artefacts["markdown"]).exists()
        assert result.report.verification_hash, f"{result.device_id}: not committed to the ledger"


def test_every_report_is_committed_to_the_ledger_and_verifies():
    output = _out()
    job = run_audit(DEVICES, rules_path=RULES, output_dir=output)

    ledger = Ledger.open(job.ledger_path)
    assert len(ledger) == len(job.results)

    key = VerifyingKey.load(output / "signing" / "ed25519.pub")
    ok, problems = ledger.verify(key)
    assert ok, problems

    for result in job.results:
        entry = ledger.find(result.report.report_id)
        assert entry is not None
        assert entry.merkle_root == result.report.merkle_root


def test_the_printed_verification_hash_matches_the_ledger():
    """The footer of the PDF is the tamper-evidence surface.

    If the number an auditor reads off the page is not the number in the ledger,
    the whole chain is decoration.
    """
    output = _out()
    job = run_audit(DEVICES / "cisco-ios-core-01", rules_path=RULES, output_dir=output)
    report = job.results[0].report

    ledger = Ledger.open(job.ledger_path)
    entry = ledger.find(report.report_id)
    assert entry is not None
    assert report.verification_hash == entry.verification_hash

    markdown = Path(job.results[0].artefacts["markdown"]).read_text(encoding="utf-8")
    assert report.verification_hash in markdown


def test_the_pipeline_is_deterministic():
    """Run it twice, get the same findings and the same Merkle root.

    An audit that is not reproducible is not an audit. The generated timestamp
    differs between runs by design; nothing the ledger commits to may.
    """
    first = run_audit(DEVICES, rules_path=RULES, output_dir=_out())
    second = run_audit(DEVICES, rules_path=RULES, output_dir=_out())

    roots_a = {r.device_id: r.report.merkle_root for r in first.results}
    roots_b = {r.device_id: r.report.merkle_root for r in second.results}
    assert roots_a == roots_b

    scores_a = {r.device_id: r.report.score for r in first.results}
    scores_b = {r.device_id: r.report.score for r in second.results}
    assert scores_a == scores_b


def test_serial_number_reaches_the_report_when_show_output_is_supplied():
    """Deliverable 4 names serial and hardware explicitly.

    A tool that accepts only a config file cannot produce these and quietly
    ships a report with an empty identity block.
    """
    output = _out()
    job = run_audit(DEVICES / "cisco-ios-core-01", rules_path=RULES, output_dir=output)
    device = job.results[0].report.device

    assert device["serial"] == "FDO1234ABCD"
    assert device["model"] == "WS-C2960X-48FPD-L"
    assert device["version"].startswith("15.2")

    payload = json.loads(Path(job.results[0].artefacts["json"]).read_text(encoding="utf-8"))
    assert payload["device"]["serial"] == "FDO1234ABCD"


def test_framework_selection_regroups_without_reparsing():
    """One IR, several frameworks. Selecting one must not change the parse.

    Coverage is a property of parsing, so it has to be identical no matter which
    standard the findings are grouped under.
    """
    full = run_audit(DEVICES, rules_path=RULES, output_dir=_out(), formats=("json",))
    cis = run_audit(
        DEVICES, rules_path=RULES, output_dir=_out(), formats=("json",), framework="CIS"
    )
    stig = run_audit(
        DEVICES, rules_path=RULES, output_dir=_out(), formats=("json",), framework="STIG"
    )

    assert full.mean_coverage == cis.mean_coverage == stig.mean_coverage
    for job in (cis, stig):
        assert len(job.results) == len(full.results)


def test_audit_runs_without_signing_when_asked():
    """Signing is the default, not a requirement to get a report out."""
    output = _out()
    job = run_audit(DEVICES / "junos-edge-01", rules_path=RULES, output_dir=output, sign=False)
    assert job.ledger_path is None
    assert not (output / "ledger.jsonl").exists()
    assert job.results[0].report.verification_hash == ""


def test_ir_export_is_byte_identical_between_runs():
    """A drift diff is only meaningful if the export is canonical."""
    first = _out()
    second = _out()
    run_audit(DEVICES / "arista-leaf-01", rules_path=RULES, output_dir=first, formats=("ir",))
    run_audit(DEVICES / "arista-leaf-01", rules_path=RULES, output_dir=second, formats=("ir",))

    a = next(first.glob("*.ir.json")).read_bytes()
    b = next(second.glob("*.ir.json")).read_bytes()
    assert a == b


# -- CLI -------------------------------------------------------------------


def test_cli_exit_code_signals_findings_not_crashes():
    """1 means "found something serious". 2 means "could not run".

    A pipeline that treats those the same will eventually read a crash as a
    clean bill of health.
    """
    from crucible.api.cli import main

    output = _out()
    code = main(["audit", str(DEVICES), "--rules", str(RULES), "--out", str(output), "--json"])
    assert code == 1, "fixtures contain critical failures; exit code should say so"

    code = main(["audit", str(output / "nope"), "--rules", str(RULES)])
    assert code == 2, "an unrunnable audit must not exit 0"


def test_cli_verify_reports_tampering():
    from crucible.api.cli import main

    output = _out()
    main(["audit", str(DEVICES), "--rules", str(RULES), "--out", str(output), "--json"])

    ledger_path = output / "ledger.jsonl"
    assert main(["verify", str(ledger_path)]) == 0

    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["merkle_root"] = "0" * 64
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["verify", str(ledger_path)]) == 2, "a tampered ledger verified clean"
