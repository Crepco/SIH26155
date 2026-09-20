"""Phase 5: bulk audits, one bad device among many, and drift between runs."""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path

import pytest
from conftest import DEVICES, RULES

from crucible.api.runner import run_audit
from crucible.report.drift import compare

# -- bulk ---------------------------------------------------------------------


def _fleet_of(count: int) -> Path:
    """``count`` devices, copied from the fixtures."""
    root = Path(tempfile.mkdtemp(prefix="crucible-bulk-"))
    sources = sorted(p for p in DEVICES.iterdir() if p.is_dir())
    for index in range(count):
        source = sources[index % len(sources)]
        shutil.copytree(source, root / f"{source.name}-{index:03d}")
    return root


def test_a_sixty_device_fleet_audits_in_seconds():
    """A guard on the fleet correlation, which once took two minutes at 200.

    The path search ran once per entry point, target and service. It now runs
    once per segment and port, which is the same answer in a fraction of the
    time. This test is the tripwire for that regression coming back.
    """
    root = _fleet_of(60)
    started = time.monotonic()
    job = run_audit(root, rules_path=RULES, formats=(), sign=False)
    elapsed = time.monotonic() - started
    assert len(job.results) == 60
    assert job.fleet is not None
    assert elapsed < 30, f"60 devices took {elapsed:.0f}s"


def test_one_unreadable_device_does_not_take_the_fleet_with_it():
    """A parser failure on device 7 must not blind the audit to devices 1-200."""
    root = _fleet_of(3)
    broken = root / "broken-device"
    broken.mkdir()
    (broken / "running-config.xml").write_text(
        '<?xml version="1.0"?>\n<config urldb="x"><devices><entry name="localhost.localdomain">\n',
        encoding="utf-8",
    )
    job = run_audit(root, rules_path=RULES, formats=(), sign=False)
    assert len(job.results) == 3
    assert len(job.failures) == 1
    assert job.failures[0]["device_id"] == "broken-device"
    assert "well-formed" in job.failures[0]["error"]
    assert job.to_dict()["failures"] == job.failures


def test_a_job_where_nothing_could_be_audited_exits_two():
    from crucible.api.cli import _exit_code

    root = Path(tempfile.mkdtemp(prefix="crucible-broken-"))
    broken = root / "broken-device"
    broken.mkdir()
    (broken / "running-config.xml").write_text("<config urldb=", encoding="utf-8")
    job = run_audit(root, rules_path=RULES, formats=(), sign=False)
    assert job.results == []
    assert job.failures
    assert _exit_code(job) == 2, "an audit that could not run must not look like a clean one"


# -- drift ----------------------------------------------------------------------


def _audit(root: Path, out: Path, device: str) -> tuple[dict, dict]:  # type: ignore[type-arg]
    run_audit(root / device, rules_path=RULES, output_dir=out, formats=("json", "ir"), sign=False)
    return (
        json.loads((out / f"{device}.audit.json").read_text(encoding="utf-8")),
        json.loads((out / f"{device}.ir.json").read_text(encoding="utf-8")),
    )


def _changed_device() -> tuple[dict, dict, dict, dict]:  # type: ignore[type-arg]
    work = Path(tempfile.mkdtemp(prefix="crucible-drift-"))
    device = work / "core-sw-01"
    shutil.copytree(DEVICES / "cisco-ios-core-01", device)
    before, before_ir = _audit(work, work / "before", "core-sw-01")

    text = (device / "running-config.txt").read_text(encoding="utf-8")
    text = text.replace(" transport input telnet ssh", " transport input ssh")
    text = text.replace(" exec-timeout 30 0", " exec-timeout 45 0")
    (device / "running-config.txt").write_text(text, encoding="utf-8")

    after, after_ir = _audit(work, work / "after", "core-sw-01")
    return before, after, before_ir, after_ir


def test_drift_reports_what_was_fixed_and_what_quietly_got_worse():
    before, after, before_ir, after_ir = _changed_device()
    report = compare(before, after, before_ir=before_ir, after_ir=after_ir)

    fixed = {c.rule_id for c in report.improvements}
    assert "CIS-NET-1.1.1" in fixed
    assert report.score_after > report.score_before
    assert not report.regressed

    # The timeout went from 30 to 45. No control flipped, because it was
    # already failing - and that is exactly the change a report-to-report
    # comparison would miss without fact-level drift.
    facts = {f.ir_path: (f.before, f.after) for f in report.fact_changes}
    assert facts["mgmt.idle_timeout_min"] == (30, 45)
    assert facts["mgmt.telnet_enabled"] == (True, False)


def test_a_regression_is_reported_as_one():
    before, after, _b, _a = _changed_device()
    backwards = compare(after, before)  # the device "improves" in reverse
    assert backwards.regressed
    assert {c.rule_id for c in backwards.regressions} == {"CIS-NET-1.1.1"}


def test_an_unchanged_device_drifts_not_at_all():
    work = Path(tempfile.mkdtemp(prefix="crucible-same-"))
    shutil.copytree(DEVICES / "cisco-ios-core-01", work / "core-sw-01")
    before, _ = _audit(work, work / "a", "core-sw-01")
    after, _ = _audit(work, work / "b", "core-sw-01")
    report = compare(before, after)
    assert report.unchanged
    assert "Nothing changed" in report.text()


def test_comparing_two_different_devices_is_refused():
    work = Path(tempfile.mkdtemp(prefix="crucible-two-"))
    shutil.copytree(DEVICES / "cisco-ios-core-01", work / "core-sw-01")
    shutil.copytree(DEVICES / "arista-leaf-01", work / "leaf-01")
    run_audit(work, rules_path=RULES, output_dir=work / "out", formats=("json",), sign=False)
    cisco = json.loads((work / "out" / "core-sw-01.audit.json").read_text(encoding="utf-8"))
    arista = json.loads((work / "out" / "leaf-01.audit.json").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="different devices"):
        compare(cisco, arista)


def test_a_changed_rule_set_is_flagged_so_the_diff_is_not_misread():
    before, after, _b, _a = _changed_device()
    after = {**after, "rule_set_digest": "0000000000000000"}
    report = compare(before, after)
    assert report.rule_set_changed
    assert "the standard moving rather than the device" in report.text()
