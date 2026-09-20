"""The four-phase verification run.

::

    PHASE 1  DEMONSTRATE   probe the twin          -> CONFIRMED
    PHASE 2  REMEDIATE     apply the printed fix
    PHASE 3  RE-TEST       probe again             -> CLOSED
    PHASE 4  REGRESSION    is management still up? -> NO LOCKOUT

Phase 4 is the one no compliance product performs, and it is the difference
between a report an administrator files and a report an administrator acts on.

Nothing here can invent a demonstration. A twin that will not boot, a property
the twin cannot model, a probe that does not exist: every one of those leaves
the finding ASSERTED and says why. A finding only reaches DEMONSTRATED when a
probe ran and came back confirming it.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from crucible.common.canonical import canonical_bytes, sha256_hex
from crucible.common.errors import SandboxError
from crucible.common.types import Finding, FindingState, Verdict
from crucible.ir.model import IRDocument
from crucible.sandbox.apply import apply_remediation
from crucible.sandbox.harness import Sandbox, Twin, docker_available
from crucible.sandbox.probes import PROBES, ProbeResult
from crucible.sandbox.spec import TwinSpec, spec_from_ir

__all__ = ["SandboxRun", "Verification", "verify_device"]


@dataclass(slots=True)
class Verification:
    """One finding, put to the test."""

    rule_id: str
    probe: str
    demonstrated: bool = False
    closed: bool | None = None
    commands: list[str] = field(default_factory=list)
    unsupported_commands: list[str] = field(default_factory=list)
    before: ProbeResult | None = None
    after: ProbeResult | None = None
    skipped: str | None = None

    def proof(self) -> dict[str, Any] | None:
        """What gets attached to the finding and hashed into the ledger."""
        if self.before is None:
            return None
        proof: dict[str, Any] = {
            "probe": self.probe,
            "demonstrated": self.demonstrated,
            "before": self.before.to_dict(),
        }
        if self.after is not None:
            proof["after"] = self.after.to_dict()
            proof["closed_by_remediation"] = bool(self.closed)
            proof["remediation_applied"] = list(self.commands)
        proof["digest"] = sha256_hex(canonical_bytes(proof))[:32]
        return proof

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "probe": self.probe,
            "demonstrated": self.demonstrated,
            "closed": self.closed,
            "skipped": self.skipped,
            "proof": self.proof(),
        }


@dataclass(slots=True)
class SandboxRun:
    """Everything one twin proved, and everything it could not."""

    device_id: str
    available: bool = True
    verifications: list[Verification] = field(default_factory=list)
    regression: list[ProbeResult] = field(default_factory=list)
    lockout: bool = False
    not_modelled: dict[str, str] = field(default_factory=dict)
    boot_ms: int = 0
    duration_ms: int = 0
    log: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def demonstrated(self) -> int:
        return sum(1 for v in self.verifications if v.demonstrated)

    @property
    def closed(self) -> int:
        return sum(1 for v in self.verifications if v.closed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "available": self.available,
            "demonstrated": self.demonstrated,
            "closed": self.closed,
            "lockout": self.lockout,
            "boot_ms": self.boot_ms,
            "duration_ms": self.duration_ms,
            "not_modelled": self.not_modelled,
            "verifications": [v.to_dict() for v in self.verifications],
            "regression": [r.to_dict() for r in self.regression],
            "log": self.log,
            "error": self.error,
        }

    def text(self) -> str:
        lines = [f"  twin for {self.device_id}: booted in {self.boot_ms} ms", ""]
        for verification in self.verifications:
            if verification.skipped:
                lines.append(f"    --  {verification.rule_id:14} {verification.skipped}")
                continue
            mark = "CONFIRMED" if verification.demonstrated else "not reproduced"
            lines.append(f"    {mark:14} {verification.rule_id:14} {verification.probe}")
            if verification.before is not None:
                lines.append(f"                   {verification.before.detail}")
            if verification.closed is not None:
                closed = "CLOSED by the printed fix" if verification.closed else "STILL OPEN"
                lines.append(f"                   {closed}")
        lines.append("")
        for probe in self.regression:
            state = "reachable" if probe.confirmed else "UNREACHABLE"
            lines.append(f"    regression     management {state} after the fix ({probe.probe})")
        if self.lockout:
            lines.append("    WARNING: the fix would have locked the operator out")
        lines.append("")
        return "\n".join(lines)


def _candidates(findings: Sequence[Finding], rules: dict[str, Any], only: str | None) -> list[Any]:
    chosen = []
    for finding in findings:
        if finding.verdict is not Verdict.FAIL:
            continue
        rule = rules.get(finding.rule_id)
        if rule is None or not rule.verifiable:
            continue
        if only and finding.rule_id != only:
            continue
        chosen.append((finding, rule))
    return chosen


def verify_device(
    ir: IRDocument,
    device_id: str,
    findings: Sequence[Finding],
    ruleset: Any,
    *,
    only: str | None = None,
    sandbox: Sandbox | None = None,
) -> SandboxRun:
    """Boot a twin, demonstrate what can be demonstrated, and prove the fix.

    Mutates the findings it demonstrates: state becomes DEMONSTRATED and the
    proof is attached, so the report and the ledger carry the evidence.
    """
    start = time.monotonic()
    run = SandboxRun(device_id=device_id)
    rules = {rule.id: rule for rule in ruleset}
    candidates = _candidates(findings, rules, only)

    if not candidates:
        run.log.append("no verifiable finding: nothing to boot a twin for")
        return run

    if sandbox is None and not docker_available():
        run.available = False
        run.error = "no Docker daemon: findings stay ASSERTED"
        return run

    spec = spec_from_ir(ir, device_id)
    run.not_modelled = spec.unsupported()

    owned = sandbox is None
    box = sandbox or Sandbox()
    try:
        if owned:
            box.__enter__()
            box.ensure_image()
        twin = box.boot(spec)
        run.boot_ms = twin.boot_ms
        run.log.extend(box.log)
        mgmt_prober = box.prober(box.mgmt_network)
        untrust_prober = box.prober(box.untrust_network)

        _demonstrate(box, twin, run, candidates, mgmt_prober, untrust_prober)
        _remediate_and_retest(box, twin, run, candidates, mgmt_prober, untrust_prober)
        _regression(box, twin, run, mgmt_prober)
    except SandboxError as exc:
        # A sandbox failure degrades to ASSERTED. It never becomes a false
        # DEMONSTRATED, and it never becomes a pass.
        run.available = False
        run.error = str(exc)
    finally:
        if owned:
            box.destroy()
        run.duration_ms = int((time.monotonic() - start) * 1000)

    _attach(findings, run)
    return run


def _target(twin: Twin, probe: str) -> tuple[str, str]:
    """(prober, address). Where a probe runs from decides what it proves."""
    if probe == "acl_bypass":
        return "untrust", twin.untrust_ip
    return "mgmt", twin.mgmt_ip


def _demonstrate(
    box: Sandbox,
    twin: Twin,
    run: SandboxRun,
    candidates: list[Any],
    mgmt_prober: str,
    untrust_prober: str,
) -> None:
    for finding, rule in candidates:
        probe_name = str((rule.verify or {}).get("probe", ""))
        verification = Verification(rule_id=finding.rule_id, probe=probe_name)
        if probe_name not in PROBES:
            verification.skipped = (
                f"no probe implements {probe_name!r}: this property is not runtime-testable"
            )
            run.verifications.append(verification)
            continue
        side, address = _target(twin, probe_name)
        prober = untrust_prober if side == "untrust" else mgmt_prober
        verification.before = box.probe(prober, probe_name, address)
        verification.demonstrated = verification.before.confirmed
        run.verifications.append(verification)


def _remediate_and_retest(
    box: Sandbox,
    twin: Twin,
    run: SandboxRun,
    candidates: list[Any],
    mgmt_prober: str,
    untrust_prober: str,
) -> None:
    demonstrated = [v for v in run.verifications if v.demonstrated]
    if not demonstrated:
        return

    rules = {finding.rule_id: rule for finding, rule in candidates}
    spec: TwinSpec = twin.spec
    for verification in demonstrated:
        rule = rules[verification.rule_id]
        commands = list(rule.remediation.get("vyos") or [])
        if not commands:
            verification.unsupported_commands = ["no vyos remediation in this rule"]
            continue
        application = apply_remediation(spec, commands)
        spec = application.spec
        verification.commands = application.applied
        verification.unsupported_commands = application.unsupported

    box.reconfigure(twin, spec)
    run.log.append("applied the printed remediation to the twin")

    for verification in demonstrated:
        if not verification.commands:
            continue
        side, address = _target(twin, verification.probe)
        prober = untrust_prober if side == "untrust" else mgmt_prober
        verification.after = box.probe(prober, verification.probe, address)
        verification.closed = not verification.after.confirmed


def _regression(box: Sandbox, twin: Twin, run: SandboxRun, mgmt_prober: str) -> None:
    """The question nobody else asks: can the operator still get in?"""
    if not twin.spec.ssh:
        return
    probe = box.probe(mgmt_prober, "acl_bypass", twin.mgmt_ip, 22)
    probe.probe = "management_still_reachable"
    probe.detail = (
        "SSH from the management segment still answers after the fix"
        if probe.confirmed
        else "SSH from the management segment no longer answers: this fix would lock you out"
    )
    run.regression.append(probe)
    run.lockout = not probe.confirmed


def _attach(findings: Sequence[Finding], run: SandboxRun) -> None:
    """Promote what was demonstrated. Nothing else changes."""
    by_rule = {v.rule_id: v for v in run.verifications}
    for finding in findings:
        verification = by_rule.get(finding.rule_id)
        if verification is None:
            continue
        proof = verification.proof()
        if proof is None:
            continue
        finding.proof = proof
        if verification.demonstrated:
            finding.state = FindingState.DEMONSTRATED
