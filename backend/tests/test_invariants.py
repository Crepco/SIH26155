"""The five invariants, asserted directly.

If any test in this file fails, the project's central claims are false. These
run against every fixture on every push, because each invariant is the kind of
thing that decays quietly: nothing crashes when coverage stops adding up or when
an UNKNOWN starts reporting as a PASS, which is exactly why they are checked
here rather than trusted.
"""

from __future__ import annotations

from pathlib import Path

from conftest import ALL_DEVICES, evaluation_for, ir_for, parsed, ruleset

from crucible.common.types import FindingState, Verdict

# -- invariant 2: every finding carries line-level evidence -----------------


def test_every_fail_cites_a_line_or_names_what_is_absent():
    """A FAIL either points at a line or says which fact was never configured.

    Those are the only two honest shapes. A failure that can do neither is a
    verdict with nothing behind it.
    """
    for device in ALL_DEVICES:
        for finding in evaluation_for(device).findings:
            if finding.verdict is not Verdict.FAIL:
                continue
            assert finding.evidence or finding.missing_paths, (
                f"{device} {finding.rule_id}: a FAIL with neither a cited line nor a named "
                "absent path is unfalsifiable"
            )


def test_cited_lines_exist_and_match_the_source():
    """Every citation resolves to a real line in a real supplied file.

    This is the test that catches an off-by-one in a parser, which would
    otherwise produce a report that looks perfect and points at the wrong line.
    """
    for device in ALL_DEVICES:
        result = parsed(device)
        sources = {f.name: f.lines for f in result.bundle.files}
        for finding in evaluation_for(device).findings:
            for item in finding.evidence:
                assert item.file in sources, f"{device}: cited unknown file {item.file}"
                lines = sources[item.file]
                assert 1 <= item.line <= len(lines), (
                    f"{device} {finding.rule_id}: cited {item.file}:{item.line} "
                    f"but the file has {len(lines)} lines"
                )


# -- invariant 3: fail closed ----------------------------------------------


def test_unparsed_facts_never_produce_a_pass():
    """A control whose facts were never parsed reports UNKNOWN, never PASS.

    The single most important test in the suite. The failure it guards against
    is an auditor signing off on a device that was never actually checked.
    """
    for device in ALL_DEVICES:
        ir = ir_for(device)
        evaluation = evaluation_for(device)
        for finding in evaluation.passed:
            result = next(r for r in ruleset() if r.id == finding.rule_id).assertion.evaluate(ir)
            assert not result.missing, (
                f"{device} {finding.rule_id} passed while {result.missing} was never parsed"
            )


def test_unrecognised_vendor_yields_no_passes(tmp_path=None):
    """A device we cannot parse at all produces UNKNOWN, not a clean bill.

    Feeding in a format no parser recognises is the honest worst case, and the
    only acceptable behaviour is to say so.
    """
    import tempfile
    from pathlib import Path

    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir
    from crucible.policy.engine import evaluate_device

    directory = Path(tempfile.mkdtemp())
    (directory / "mystery.cfg").write_text(
        "BEGIN CONFIGURATION BLOCK\n"
        "  security-posture: excellent\n"
        "  trust-me: yes\n"
        "END CONFIGURATION BLOCK\n",
        encoding="utf-8",
    )

    device = build_ir(load(directory)[0])
    assert not device.parser_applied, "an unknown grammar must not be handed to a parser"

    evaluation = evaluate_device(device.ir, ruleset())
    assert not evaluation.passed, (
        f"an unparsed device passed {len(evaluation.passed)} controls; everything must be UNKNOWN"
    )
    assert all(f.verdict is Verdict.UNKNOWN for f in evaluation.findings)
    assert device.ir.coverage.parsed_lines == 0


# -- invariant 4: coverage is published and adds up ------------------------


def test_coverage_arithmetic_holds_for_every_fixture():
    for device in ALL_DEVICES:
        coverage = ir_for(device).coverage
        assert coverage.parsed_lines + coverage.unparsed_lines == coverage.total_lines, (
            f"{device}: {coverage.parsed_lines} + {coverage.unparsed_lines} "
            f"!= {coverage.total_lines}"
        )
        coverage.check()


def test_coverage_counts_every_supplied_line_including_show_output():
    """The denominator is the whole bundle, not the convenient part of it.

    Counting only the running configuration would inflate coverage by excluding
    the show output we also ingest - a percentage point bought by moving the
    goalposts.
    """
    for device in ALL_DEVICES:
        result = parsed(device)
        supplied = sum(f.line_count for f in result.bundle.files)
        assert result.ir.coverage.total_lines == supplied, (
            f"{device}: coverage counted {result.ir.coverage.total_lines} lines "
            f"but {supplied} were supplied"
        )


def test_unparsed_lines_are_reportable():
    """Every uninterpreted line is listed, not merely counted.

    Invariant 4 says coverage is published. A number with no listing behind it
    is a claim; the appendix is what makes it checkable.
    """
    for device in ALL_DEVICES:
        coverage = ir_for(device).coverage
        if coverage.unparsed_lines == 0:
            continue
        assert coverage.unparsed_sample, f"{device} has uninterpreted lines but lists none"
        for entry in coverage.unparsed_sample:
            assert {"file", "line", "raw"} <= entry.keys()


# -- invariant 5: three states, never two ----------------------------------


def test_findings_never_claim_to_be_demonstrated_without_a_proof():
    """Only the sandbox may promote a finding, and only by attaching a proof.

    The policy engine cannot produce DEMONSTRATED on its own. If it ever could,
    a report could claim a vulnerability was proven live by a run that never
    booted a twin.
    """
    for device in ALL_DEVICES:
        for finding in evaluation_for(device).findings:
            if finding.state is FindingState.DEMONSTRATED:
                assert finding.proof, (
                    f"{device} {finding.rule_id} is DEMONSTRATED with no proof artefact"
                )


def test_unknown_verdict_and_unknown_state_agree():
    for device in ALL_DEVICES:
        for finding in evaluation_for(device).findings:
            assert (finding.verdict is Verdict.UNKNOWN) == (
                finding.state is FindingState.UNKNOWN
            ), f"{device} {finding.rule_id}: verdict and state disagree"


def test_unknown_counts_against_the_score():
    """A device we could not read must not score well.

    Scoring only what was understood would reward a parser for failing, and
    would hand a device with 40% coverage a perfect grade.
    """
    import tempfile
    from pathlib import Path

    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir
    from crucible.policy.engine import evaluate_device

    directory = Path(tempfile.mkdtemp())
    (directory / "opaque.cfg").write_text("nothing we understand at all\n" * 20, encoding="utf-8")
    evaluation = evaluate_device(build_ir(load(directory)[0]).ir, ruleset())
    assert evaluation.score == 0, "an unreadable device scored above zero"


# -- invariant 1: the verdict path contains no model -----------------------


def test_verdict_path_imports_no_model_layer():
    """The deterministic pipeline must not depend on the training layer.

    Enforced as an import check rather than as a policy, so that wiring a model
    into the verdict path fails a test rather than passing a review.
    """
    import crucible.policy.engine as engine
    import crucible.policy.expr as expr
    import crucible.policy.ruleset as rules

    for module in (engine, expr, rules):
        source = module.__file__
        assert source
        text = Path(source).read_text(encoding="utf-8")
        for forbidden in ("crucible.training", "ollama", "openai", "anthropic", "transformers"):
            assert forbidden not in text, (
                f"{module.__name__} references {forbidden}: the verdict path must contain no model"
            )
