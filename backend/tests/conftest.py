"""Shared test fixtures and helpers.

Kept as plain functions rather than pytest fixtures so that the standalone
runner in ``run_tests.py`` can use them too. The suite has to pass on a machine
with nothing but the standard library installed - that is the deployment target,
so it is also the test target.
"""

from __future__ import annotations

import os
import sys
import tempfile
from functools import cache, lru_cache
from pathlib import Path

TESTS = Path(__file__).parent
ROOT = TESTS.parent
REPO = ROOT.parent
DEVICES = TESTS / "fixtures" / "devices"
RULES = REPO / "rules" / "cis"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Tests never touch the operator's real deployment state: installed packs and
# trusted publishers in ~/.crucible would otherwise change audit results.
os.environ["CRUCIBLE_HOME"] = tempfile.mkdtemp(prefix="crucible-test-home-")
# A fixed salt so credential fingerprints - and therefore the fleet report and
# every hash derived from it - are identical on every run and every machine.
os.environ.setdefault("CRUCIBLE_FINGERPRINT_SALT", "test-salt-not-a-secret")


@lru_cache(maxsize=1)
def ruleset():  # type: ignore[no-untyped-def]
    from crucible.policy.ruleset import load_rules

    return load_rules(RULES)


@cache
def parsed(device_id: str):  # type: ignore[no-untyped-def]
    """Parse one fixture device into a :class:`ParsedDevice`.

    Cached because parsing the same fixture forty times across the suite is
    wasted work, and because a cached result proves parsing is deterministic -
    if it were not, tests would disagree with each other.
    """
    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    bundle = load(DEVICES / device_id)[0]
    return build_ir(bundle)


def ir_for(device_id: str):  # type: ignore[no-untyped-def]
    return parsed(device_id).ir


def evaluation_for(device_id: str):  # type: ignore[no-untyped-def]
    from crucible.policy.engine import evaluate_device

    return evaluate_device(ir_for(device_id), ruleset())


ALL_DEVICES = (
    "cisco-ios-core-01",
    "arista-leaf-01",
    "fortios-fw-01",
    "junos-edge-01",
    "routeros-branch-01",
    "panos-fw-01",
)
