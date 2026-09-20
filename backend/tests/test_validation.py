"""Measuring against ground truth - and the arithmetic that keeps it honest."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from conftest import DEVICES, REPO, RULES, ruleset

from crucible.validation import load_labels, validate
from crucible.validation.labels import LabelError

LABELS = REPO / "corpus" / "labels" / "fixtures"


def _report():  # type: ignore[no-untyped-def]
    return validate(load_labels(LABELS), ruleset(), devices_root=DEVICES)


def test_every_shipped_fixture_is_labelled():
    labels = {label.config_id for label in load_labels(LABELS)}
    shipped = {p.name for p in DEVICES.iterdir() if p.is_dir()}
    assert labels == shipped


def test_labels_cover_every_control():
    rule_ids = {rule.id for rule in ruleset()}
    for label in load_labels(LABELS):
        assert set(label.verdicts) == rule_ids, label.config_id


def test_a_malformed_label_is_an_error_not_a_skip():
    """A label that does not load is a measurement quietly not taken."""
    directory = Path(tempfile.mkdtemp())
    (directory / "broken.yaml").write_text("config_id: x\nlabelled_by: y\n", encoding="utf-8")
    with pytest.raises(LabelError, match="expected_verdicts"):
        load_labels(directory)

    (directory / "broken.yaml").write_text(
        "config_id: x\nlabelled_by: y\nexpected_verdicts: {CIS-NET-1.1.1: maybe}\n",
        encoding="utf-8",
    )
    with pytest.raises(LabelError, match="verdict"):
        load_labels(directory)


def test_the_measurement_runs_and_reports_every_control():
    report = _report()
    assert len(report.devices) == 6
    assert report.to_dict()["counts"]["controls_compared"] == 6 * len(ruleset())


def test_precision_and_recall_hold_at_the_measured_level():
    """A floor, not a target. If a change drops these, the change is wrong."""
    report = _report()
    assert report.precision >= 0.95
    assert report.recall >= 0.85
    assert report.fact_accuracy >= 0.95
    assert report.agreement >= 0.90


def test_a_cautious_miss_is_not_counted_as_a_silent_pass():
    """The three-state model, as arithmetic.

    Reporting UNKNOWN where a labeller found a failure is a gap. Reporting PASS
    there is a different and much worse thing, and the measurement must not let
    the two blur together.
    """
    report = _report()
    totals = report.to_dict()["counts"]
    assert totals["false_negatives"] == 0, "a labelled failure was reported as a pass"
    assert totals["cautious_misses"] > 0
    assert report.recall < 1.0  # the cautious misses are counted against recall


def test_unreviewed_labels_are_reported_as_provisional():
    report = _report()
    assert report.human_reviewed is False
    assert "provisional" in report.text()
    assert report.to_dict()["human_reviewed_labels"] is False


def test_a_differently_cited_line_is_not_scored_as_a_wrong_value():
    report = _report()
    data = report.to_dict()
    assert data["fact_accuracy"] >= 0.95
    assert data["citation_agreement"] <= data["fact_accuracy"]


def test_labels_were_not_written_from_the_tool_output():
    """The labels disagree with the tool somewhere, which is the point.

    A label set that agrees everywhere is evidence that it was written by
    running the auditor first, and it measures nothing.
    """
    report = _report()
    assert any(device.disagreements for device in report.devices)


def test_the_rule_set_matches_the_labelled_rule_set():
    from crucible.policy.ruleset import load_rules

    assert {r.id for r in load_rules(RULES)} == {r.id for r in ruleset()}
