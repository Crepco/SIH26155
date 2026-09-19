"""Vendor Adapter Packs: validation, signing, trust, privacy, application."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from conftest import REPO, TESTS, ruleset

from crucible.adapters.pack import AdapterPack, Mapping, TrustStore, load_pack, load_packs
from crucible.common.errors import PackError
from crucible.ledger.signing import SigningKey

VRP = TESTS / "fixtures" / "unseen" / "huawei-vrp-agg-01"


def vrp_pack() -> AdapterPack:
    """What an administrator would confirm for the VRP fixture, at Tier 3."""

    def m(path: str, match: str, transform: str, **extra: object) -> Mapping:
        return Mapping(
            ir_path=path,
            match=match,
            transform=transform,
            tier_learned=3,
            confirmed_by="admin@test",
            samples=1,
            **extra,  # type: ignore[arg-type]
        )

    return AdapterPack(
        id="huawei-vrp-5",
        vendor="huawei",
        os="VRP",
        created="2026-09-20",
        grammar={"kind": "marker_blocks"},
        fingerprint=[
            {"match": r"^\s*sysname ", "confidence": 0.4},
            {"match": r"^user-interface vty", "confidence": 0.4},
            {"match": r"^\s*info-center ", "confidence": 0.3},
        ],
        mappings=[
            m("device.hostname", r"^sysname (?P<value>\S+)$", "identity"),
            m("mgmt.telnet_enabled", r"^telnet server enable$", "presence"),
            m("mgmt.telnet_enabled", r"^undo telnet server enable$", "negated_presence"),
            m("mgmt.ssh.enabled", r"^stelnet server enable$", "presence"),
            m("mgmt.http_enabled", r"^http server enable$", "presence"),
            m(
                "snmp.communities",
                r"^snmp-agent community (?:read|write) (?:cipher )?(?P<value>\S+)$",
                "collect_redacted",
            ),
            m(
                "snmp.version",
                r"^snmp-agent sys-info version (?P<value>v1|v2c|v3)$",
                "lookup",
                values={"v1": 1, "v2c": 2, "v3": 3},
            ),
            m("logging.servers", r"^info-center loghost (?P<value>\S+)$", "collect"),
            m("ntp.servers", r"^ntp-service unicast-server (?P<value>\S+)$", "collect"),
            m(
                "mgmt.idle_timeout_min",
                r"^idle-timeout (?P<value>\d+)",
                "to_int",
                within=r"^user-interface vty",
            ),
        ],
    )


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="crucible-packs-"))


def _signed() -> tuple[AdapterPack, SigningKey]:
    key = SigningKey.generate()
    pack = vrp_pack()
    pack.sign(key)
    return pack, key


def _audit_vrp(packs):  # type: ignore[no-untyped-def]
    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    return build_ir(load(VRP)[0], packs=packs)


# -- validation ---------------------------------------------------------------


def test_the_documented_example_pack_is_valid():
    pack = load_pack(REPO / "adapters" / "_template" / "mikrotik-routeros-7.example.yaml")
    assert pack.vendor == "mikrotik"
    assert len(pack.mappings) >= 3


def test_an_ir_path_that_does_not_exist_is_refused():
    pack = vrp_pack()
    pack.mappings[0].ir_path = "mgmt.telnet_is_fine"
    with pytest.raises(PackError):
        pack.validate()


def test_an_unknown_transform_is_refused():
    pack = vrp_pack()
    pack.mappings[1].transform = "eval"
    with pytest.raises(PackError):
        pack.validate()


def test_a_value_transform_needs_a_capture_group():
    pack = vrp_pack()
    pack.mappings[-1].match = r"^idle-timeout \d+"
    with pytest.raises(PackError):
        pack.validate()


def test_catastrophic_patterns_are_refused():
    pack = vrp_pack()
    pack.mappings[0].match = r"^sysname (?P<value>(a+)+)$"
    with pytest.raises(PackError):
        pack.validate()


def test_customer_data_cannot_leave_in_a_pack():
    for leak in (
        r"^info-center loghost 10\.0\.0\.5$",
        r"^snmp-agent community read s3cr3tc0mmunityStringValue$",
        r"^ntp-service unicast-server ntp\.corp\.example\.in$",
    ):
        pack = vrp_pack()
        pack.mappings[0].match = leak.replace("$", "(?P<value>)$")
        with pytest.raises(PackError):
            pack.validate()


# -- signing and trust --------------------------------------------------------


def test_a_signed_pack_round_trips_through_yaml():
    pack, key = _signed()
    reloaded = load_pack(pack.to_yaml())
    assert reloaded.verify_with(key.verifying_key())
    assert reloaded.digest == pack.digest


def test_an_unsigned_pack_is_refused():
    trust = TrustStore(_tmp())
    with pytest.raises(PackError, match="unsigned"):
        trust.admit(vrp_pack())


def test_a_pack_from_an_untrusted_key_is_refused():
    pack, _key = _signed()
    trust = TrustStore(_tmp())
    with pytest.raises(PackError, match="trust store"):
        trust.admit(pack)


def test_a_tampered_pack_is_refused():
    """The attack in docs/06: remap Telnet so a wide-open device audits clean."""
    pack, key = _signed()
    trust = TrustStore(_tmp())
    trust.add(key.public_pem())
    text = pack.to_yaml().replace("transform: presence", "transform: negated_presence", 1)
    with pytest.raises(PackError, match="altered"):
        trust.admit(load_pack(text))


def test_trusting_a_key_is_explicit_and_then_admits_its_packs():
    pack, key = _signed()
    trust = TrustStore(_tmp())
    assert trust.add(key.public_pem()) == key.key_id
    assert trust.admit(pack) == key.key_id


def test_a_directory_with_one_bad_pack_refuses_to_load():
    pack, key = _signed()
    directory = _tmp()
    (directory / "good.yaml").write_text(pack.to_yaml(), encoding="utf-8")
    (directory / "bad.yaml").write_text(vrp_pack().to_yaml(), encoding="utf-8")  # unsigned
    trust = TrustStore(_tmp())
    trust.add(key.public_pem())
    with pytest.raises(PackError):
        load_packs(directory, trust)


# -- application --------------------------------------------------------------


def test_a_pack_teaches_the_pipeline_an_unseen_vendor():
    pack, _ = _signed()
    device = _audit_vrp([pack])
    ir = device.ir
    assert device.identity.vendor == "huawei"
    assert ir.device["hostname"] == "agg-sw-01"
    assert ir.resolve("mgmt.telnet_enabled").value is True
    assert ir.resolve("mgmt.ssh.enabled").value is True
    assert ir.resolve("snmp.communities").value == ["default"]
    assert ir.resolve("snmp.version").value == 2
    assert ir.resolve("mgmt.idle_timeout_min").value == 30
    assert ir.coverage.by_tier["tier3"] >= 9
    assert device.pack_ids == ["huawei-vrp-5"]


def test_pack_facts_carry_the_pack_and_tier_in_their_provenance():
    pack, _ = _signed()
    ir = _audit_vrp([pack]).ir
    provenance = ir.resolve("mgmt.telnet_enabled").provenance
    assert provenance is not None
    assert provenance.tier == 3
    assert provenance.adapter_pack == "huawei-vrp-5"
    assert provenance.raw.strip() == "telnet server enable"


def test_community_strings_never_reach_evidence_through_a_pack():
    pack, _ = _signed()
    ir = _audit_vrp([pack]).ir
    for key, provenance in ir.provenance.items():
        if key.startswith("snmp"):
            assert "public" not in provenance.raw, provenance.raw


def test_rules_decide_on_pack_facts_exactly_as_on_tier_zero_facts():
    from crucible.common.types import Verdict
    from crucible.policy.engine import evaluate_device

    pack, _ = _signed()
    evaluation = evaluate_device(_audit_vrp([pack]).ir, ruleset())
    verdicts = {f.rule_id: f.verdict for f in evaluation.all_results}
    assert verdicts["CIS-NET-1.1.1"] is Verdict.FAIL  # telnet server enable
    assert verdicts["CIS-NET-2.1.2"] is Verdict.FAIL  # community "public"


def test_without_the_pack_the_same_file_is_honestly_unknown():
    from crucible.common.types import Verdict
    from crucible.policy.engine import evaluate_device

    evaluation = evaluate_device(_audit_vrp([]).ir, ruleset())
    for finding in evaluation.all_results:
        assert finding.verdict in (Verdict.UNKNOWN, Verdict.NOT_APPLICABLE), finding.rule_id


def test_a_pack_never_overrides_a_built_in_parser():
    """A pack for Cisco must not rewrite what the Tier-0 parser read."""
    from conftest import DEVICES

    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    pack = AdapterPack(
        id="rogue-cisco",
        vendor="cisco",
        created="2026-09-20",
        mappings=[
            Mapping(
                ir_path="mgmt.telnet_enabled",
                match=r"transport input",
                transform="negated_presence",
                tier_learned=3,
            )
        ],
    )
    baseline = build_ir(load(DEVICES / "cisco-ios-core-01")[0])
    with_pack = build_ir(load(DEVICES / "cisco-ios-core-01")[0], packs=[pack])
    assert with_pack.ir.resolve("mgmt.telnet_enabled").value is True
    assert (
        with_pack.ir.resolve("mgmt.telnet_enabled").provenance
        == baseline.ir.resolve("mgmt.telnet_enabled").provenance
    )


def test_holding_out_a_vendor_disables_only_its_parser():
    from conftest import DEVICES

    from crucible.ingest.bundle import load
    from crucible.pipeline import build_ir

    device = build_ir(load(DEVICES / "routeros-branch-01")[0], hold_out=["mikrotik"])
    assert device.identity.vendor == "mikrotik"
    assert device.parser_applied is False
    # Identity (serial, model, version) is read by the vendor-neutral identity
    # reader and stays. No security fact may come from the held-out parser.
    tier0_facts = [
        path
        for path, prov in device.ir.provenance.items()
        if prov.tier == 0 and not path.startswith("device.")
    ]
    assert tier0_facts == []
