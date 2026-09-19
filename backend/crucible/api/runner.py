"""End-to-end audit orchestration.

Ingest, fingerprint, parse, evaluate, report, sign. One function, so the CLI,
the HTTP API and the test suite all exercise the same path rather than three
subtly different ones.

Nothing in this module reaches the network. That is not a comment, it is the
deployment requirement: the customer is NCIIPC, and a configuration file is a
blueprint of a national network's defences.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crucible.adapters.pack import AdapterPack
from crucible.common.canonical import canonical_bytes
from crucible.ingest.bundle import load
from crucible.ledger.chain import Ledger
from crucible.ledger.signing import load_or_create_key
from crucible.pipeline import build_ir
from crucible.policy.engine import evaluate_device
from crucible.policy.ruleset import RuleSet, load_rules
from crucible.report.build import AuditReport, build_report
from crucible.report.text import render_markdown

__all__ = ["AuditJob", "AuditResult", "run_audit"]


@dataclass(slots=True)
class AuditResult:
    """One device audited, plus wherever its artefacts were written."""

    report: AuditReport
    #: The normalised IR this report was derived from. Kept so that `--format ir`
    #: exports the actual intermediate representation rather than a summary of
    #: it - the IR is the artefact other tools would want to consume.
    ir: dict[str, Any] = field(default_factory=dict)
    artefacts: dict[str, str] = field(default_factory=dict)

    @property
    def device_id(self) -> str:
        return self.report.device_id


@dataclass(slots=True)
class AuditJob:
    """A whole run - one device or two hundred."""

    results: list[AuditResult] = field(default_factory=list)
    ruleset_size: int = 0
    rule_set_digest: str = ""
    ledger_path: str | None = None

    @property
    def fleet_score(self) -> int:
        if not self.results:
            return 0
        return round(sum(r.report.score for r in self.results) / len(self.results))

    @property
    def mean_coverage(self) -> float:
        if not self.results:
            return 0.0
        total = sum(r.report.coverage["total_lines"] for r in self.results)
        parsed = sum(r.report.coverage["parsed_lines"] for r in self.results)
        return round(100.0 * parsed / total, 1) if total else 0.0

    def totals(self) -> dict[str, int]:
        totals = {"fail": 0, "unknown": 0, "pass": 0, "not_applicable": 0}
        for result in self.results:
            for key, value in result.report.evaluation.counts().items():
                totals[key] += value
        return totals

    def to_dict(self) -> dict[str, Any]:
        return {
            "devices": len(self.results),
            "fleet_score": self.fleet_score,
            "mean_coverage": self.mean_coverage,
            "totals": self.totals(),
            "rule_set_digest": self.rule_set_digest,
            "rules_evaluated": self.ruleset_size,
            "reports": [r.report.to_dict() for r in self.results],
        }


def _report_id(index: int, device_id: str) -> str:
    stamp = _dt.datetime.now(_dt.UTC).strftime("%Y%m%d")
    slug = "".join(c for c in device_id.upper() if c.isalnum())[:12] or "DEVICE"
    return f"AUDIT-{stamp}-{slug}-{index:04d}"


def run_audit(
    target: str | Path,
    *,
    rules_path: str | Path,
    output_dir: str | Path | None = None,
    framework: str | None = None,
    formats: tuple[str, ...] = ("json", "md", "pdf"),
    sign: bool = True,
    key_path: str | Path | None = None,
    ledger_path: str | Path | None = None,
    workdir: str | Path | None = None,
    packs: Sequence[AdapterPack] = (),
    hold_out: Sequence[str] = (),
) -> AuditJob:
    """Audit every device under ``target``.

    ``framework`` filters the rule set by control-identifier family. It does not
    re-parse anything: one IR, four frameworks, which is the IR paying for
    itself.

    ``packs`` must already be admitted by a trust store (see
    :func:`crucible.api.home.trusted_packs`). ``hold_out`` switches off the
    built-in parser for the named vendors.
    """
    ruleset: RuleSet = load_rules(rules_path)
    if framework:
        ruleset = ruleset.for_framework(framework)
        if not len(ruleset):
            raise ValueError(f"no rules match framework {framework!r}")

    bundles = load(target, workdir=Path(workdir) if workdir else None)
    job = AuditJob(ruleset_size=len(ruleset), rule_set_digest=ruleset.version_digest)

    output = Path(output_dir) if output_dir else None
    if output:
        output.mkdir(parents=True, exist_ok=True)

    ledger = None
    key = None
    if sign and output:
        key = load_or_create_key(Path(key_path) if key_path else output / "signing" / "ed25519.key")
        ledger = Ledger.open(Path(ledger_path) if ledger_path else output / "ledger.jsonl")
        job.ledger_path = str(ledger.path)

    for index, bundle in enumerate(bundles, start=1):
        parsed = build_ir(bundle, packs=packs, hold_out=hold_out)
        evaluation = evaluate_device(parsed.ir, ruleset)
        report = build_report(
            report_id=_report_id(index, bundle.device_id),
            device_id=bundle.device_id,
            ir=parsed.ir,
            evaluation=evaluation,
            rule_set_digest=ruleset.version_digest,
            frameworks=ruleset.frameworks(),
            parser_applied=parsed.parser_applied,
            adapter_packs=parsed.pack_ids,
        )

        # Commit to the ledger before rendering, so the verification hash the
        # renderers print is the real one rather than a placeholder.
        if ledger is not None and key is not None:
            entry = ledger.append(
                report_id=report.report_id,
                device_id=report.device_id,
                merkle_root=report.merkle_root,
                rule_set_digest=report.rule_set_digest,
                ir_schema_version=report.ir_schema_version,
                key=key,
            )
            report.verification_hash = entry.verification_hash
            report.ledger_seq = entry.seq

        result = AuditResult(report=report, ir=parsed.ir.to_dict())
        if output:
            _write_artefacts(report, output, formats, result)
        job.results.append(result)

    return job


def _write_artefacts(
    report: AuditReport, output: Path, formats: tuple[str, ...], result: AuditResult
) -> None:
    import json

    stem = output / report.device_id

    if "json" in formats:
        path = stem.with_suffix(".audit.json")
        path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
        result.artefacts["json"] = str(path)

    if "md" in formats:
        path = stem.with_suffix(".md")
        path.write_text(render_markdown(report), encoding="utf-8")
        result.artefacts["markdown"] = str(path)

    if "pdf" in formats:
        from crucible.report import render_pdf

        result.artefacts["pdf"] = render_pdf(report, str(stem.with_suffix(".pdf")))

    if "ir" in formats:
        path = stem.with_suffix(".ir.json")
        # Canonical bytes, so two runs over the same input produce two
        # byte-identical files. An IR export that differs run to run cannot be
        # diffed for drift, which is most of what it is for.
        path.write_bytes(canonical_bytes(result.ir))
        result.artefacts["ir"] = str(path)
