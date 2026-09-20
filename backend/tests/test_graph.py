"""The fleet graph: four correlations no per-device checklist can see."""

from __future__ import annotations

from conftest import ALL_DEVICES, ir_for

from crucible.graph import DeviceInput, build_fleet, build_fleet_report, correlate
from crucible.graph.model import EdgeKind, NodeKind


def _devices() -> list[DeviceInput]:
    return [DeviceInput(name, ir_for(name)) for name in ALL_DEVICES]


def _report():  # type: ignore[no-untyped-def]
    return build_fleet_report(_devices())


def _by_id(report, prefix: str):  # type: ignore[no-untyped-def]
    return [c for c in report.correlations if c.id.startswith(prefix)]


# -- the graph --------------------------------------------------------------


def test_devices_on_one_subnet_become_adjacent():
    graph = build_fleet(_devices())
    management = next(n for n in graph.of_kind(NodeKind.SEGMENT) if n.label == "10.0.0.0/24")
    members = {n.attrs["device"] for n, _e in graph.neighbours(management.id, NodeKind.INTERFACE)}
    assert {"cisco-ios-core-01", "arista-leaf-01", "junos-edge-01", "panos-fw-01"} <= members


def test_adjacency_inferred_from_addressing_is_marked_inferred():
    graph = build_fleet(_devices())
    connects = [e for e in graph.edges if e.kind == EdgeKind.CONNECTS_TO]
    assert connects and all(e.inferred for e in connects)


def test_an_address_without_a_prefix_joins_a_declared_subnet():
    """Several vendors print a bare address; it must not become its own island."""
    graph = build_fleet(_devices())
    cisco = next(
        n
        for n in graph.of_kind(NodeKind.INTERFACE)
        if n.attrs["device"] == "cisco-ios-core-01" and n.label == "Vlan900"
    )
    segments = [s.label for s, _e in graph.neighbours(cisco.id, NodeKind.SEGMENT)]
    assert segments == ["10.0.0.0/24"]


# -- 1. management plane exposure ---------------------------------------------


def test_a_hardened_device_is_exposed_by_another_device_s_edge():
    """The finding in docs/08: both devices pass their own audit."""
    report = _report()
    exposures = _by_id(report, "FLEET-EXPOSURE-ARISTA-LEAF-01")
    assert exposures, "the leaf's management plane should be reachable from the internet edge"
    paths = exposures[0].paths
    assert any(p.source.startswith("junos-edge-01") for p in paths)
    assert all(p.target.startswith("arista-leaf-01") for p in paths)
    assert exposures[0].confidence == "inferred"


def test_a_device_with_a_management_acl_is_not_reported_as_exposed():
    """core-sw-01 restricts management access, so it is not in the exposure set."""
    report = _report()
    assert not _by_id(report, "FLEET-EXPOSURE-CISCO-IOS-CORE-01")


def test_paths_are_only_reported_between_devices_that_can_reach_each_other():
    report = _report()
    for correlation in _by_id(report, "FLEET-EXPOSURE"):
        for path in correlation.paths:
            assert len(path.hops) >= 2
            assert path.hops[0] == path.source


# -- 2. NTP drift ---------------------------------------------------------------


def test_ntp_drift_names_the_devices_that_differ():
    report = _report()
    drift = _by_id(report, "FLEET-NTP-DRIFT")
    assert len(drift) == 1
    # The Arista fixture authenticates NTP; the others do not say so.
    assert "arista-leaf-01" not in drift[0].devices
    assert "cisco-ios-core-01" in drift[0].devices


# -- 3. credential reuse ----------------------------------------------------------


def test_the_same_credential_on_two_devices_is_found_without_storing_it():
    report = _report()
    reuse = _by_id(report, "FLEET-CREDENTIAL")
    assert len(reuse) == 1
    assert reuse[0].devices == ["arista-leaf-01", "junos-edge-01"]
    # The digest never appears: only a salted fingerprint, and only its prefix.
    blob = str(reuse[0].to_dict())
    assert "$6$" not in blob and "abcsalt" not in blob


# -- 4. ACL shadowing --------------------------------------------------------------


def test_a_permissive_entry_above_a_restrictive_one_is_found():
    report = _report()
    shadows = _by_id(report, "FLEET-SHADOW")
    assert shadows, "the shadowed deny in SERVER_IN should be found"
    denied = next(c for c in shadows if "entry 30" in c.title)
    assert denied.severity == "high"  # a deny that never fires, not a redundancy
    assert "arista-leaf-01" in denied.devices
    assert "never reached" in denied.summary or "never fires" in denied.title


# -- ranking ------------------------------------------------------------------------


def test_fixes_are_ranked_by_paths_severed_not_by_severity():
    report = _report()
    assert report.fixes
    severed = [f.paths_severed for f in report.fixes]
    assert severed == sorted(severed, reverse=True)
    assert report.fixes[0].paths_severed > 1
    assert "management ACL" in report.fixes[0].action


def test_the_headline_names_one_fix_and_what_it_severs():
    report = _report()
    headline = report.headline()
    assert "attack paths" in headline
    assert "severs" in headline


def test_a_single_device_has_no_fleet_to_correlate():
    report = build_fleet_report([DeviceInput("cisco-ios-core-01", ir_for("cisco-ios-core-01"))])
    assert report.correlations == [] or all(
        c.id.startswith("FLEET-SHADOW") for c in report.correlations
    )


def test_the_fleet_report_is_the_same_on_two_runs():
    """A report that differs run to run cannot be diffed for drift."""
    assert _report().to_dict() == _report().to_dict()


def test_correlations_never_read_configuration_text():
    """Everything here comes from the IR; the graph never sees a config line."""
    import inspect

    from crucible.graph import build, rank
    from crucible.graph import correlate as correlate_module

    for module in (build, correlate_module, rank):
        source = inspect.getsource(module)
        for forbidden in ("running-config", "transport input", "set admintimeout", "/ip service"):
            assert forbidden not in source, f"{module.__name__} reads vendor syntax"


def test_correlate_is_callable_without_a_report_wrapper():
    graph = build_fleet(_devices())
    assert correlate(graph, _devices())
