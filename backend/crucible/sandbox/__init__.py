"""Stage 7 - Crucible, the verification sandbox.

Every compliance tool in this category ends its sentence at *this line violates
CIS-NET-1.1.1*. That is an assertion. This package boots a disposable replica
of the audited device, demonstrates the finding against it, applies the
remediation the report prints, proves the finding is closed, and checks that
the operator can still log in.

Findings are promoted from ASSERTED to DEMONSTRATED only by a probe that ran.
A twin that will not boot, a property the twin cannot model, or a probe that
does not exist all leave the finding ASSERTED and say why. Nothing here can
manufacture a proof, and nothing here can turn a finding into a pass.

Specification: docs/07-crucible-sandbox.md · ADR 0008
"""

from crucible.sandbox.apply import Application, apply_remediation
from crucible.sandbox.harness import Sandbox, Twin, docker_available
from crucible.sandbox.probes import PROBES, ProbeResult, run_probe
from crucible.sandbox.run import SandboxRun, Verification, verify_device
from crucible.sandbox.spec import TwinSpec, spec_from_ir

__all__ = [
    "PROBES",
    "Application",
    "ProbeResult",
    "Sandbox",
    "SandboxRun",
    "Twin",
    "TwinSpec",
    "Verification",
    "apply_remediation",
    "docker_available",
    "run_probe",
    "spec_from_ir",
    "verify_device",
]
