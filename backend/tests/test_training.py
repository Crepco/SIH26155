"""Tiers 2 and 3: proposals, the training session, the held-out measurement."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest
from conftest import DEVICES, TESTS, ruleset

from crucible.adapters.pack import Mapping, TrustStore, load_pack
from crucible.common.errors import PackError
from crucible.ingest.bundle import load
from crucible.ledger.signing import SigningKey
from crucible.training.evaluate import evaluate_held_out
from crucible.training.proposer import LexicalProposer, OllamaProposer
from crucible.training.session import TrainingSession
from crucible.training.vocabulary import VOCABULARY

VRP = TESTS / "fixtures" / "unseen" / "huawei-vrp-agg-01"


def _vrp_session() -> TrainingSession:
    return TrainingSession(load(VRP)[0])


# -- the hold-out is real -------------------------------------------------------


def test_the_vocabulary_contains_no_held_out_or_unseen_syntax():
    """If RouterOS or VRP syntax leaked into the precedent, the transfer is fake."""
    forbidden = re.compile(
        r"(^/(ip|system|snmp|interface|user)\b|disabled=|name=|sysname|info-center|"
        r"snmp-agent|user-interface|stelnet|undo |ntp-service|local-user|loghost)",
        re.IGNORECASE,
    )
    for spec in VOCABULARY:
        for text in (*spec.examples, *spec.keywords):
            assert not forbidden.search(text), f"{spec.path}: {text!r}"


def test_every_vocabulary_path_is_pack_writable():
    from crucible.ir.paths import PACK_PATHS

    for spec in VOCABULARY:
        assert spec.path in PACK_PATHS


# -- proposals ------------------------------------------------------------------


def test_obvious_lines_from_an_unseen_vendor_get_confident_correct_proposals():
    proposer = LexicalProposer()
    cases = {
        "telnet server enable": ("mgmt.telnet_enabled", True),
        "http server enable": ("mgmt.http_enabled", True),
        "snmp-agent community read public": ("snmp.communities", "default"),
        "ntp-service unicast-server 10.0.0.1": ("ntp.servers", "10.0.0.1"),
    }
    for line, (path, value) in cases.items():
        proposal = proposer.propose(line)
        assert proposal is not None, line
        assert proposal.ir_path == path, (line, proposal.ir_path)
        assert proposal.preview == value, (line, proposal.preview)
        assert proposal.confidence >= 0.85, (line, proposal.confidence)


def test_a_proposal_is_a_parser_not_a_verdict():
    proposal = LexicalProposer().propose("telnet server enable")
    assert proposal is not None
    assert proposal.mapping.tier_learned == 2
    assert proposal.mapping.regex.search("telnet server enable")
    assert "pass" not in json.dumps(proposal.to_dict()).lower().split('"')


def test_credentials_are_never_captured():
    proposer = LexicalProposer()
    for line in (
        "/user add name=monitor group=read password=readonly123",
        "local-user admin password irreversible-cipher $1a$Kx9T2p$Ab3dEf6hIj9kLmN0pQr2sTu5vWx8yZ$",
        "set admin-password hunter2",
    ):
        proposal = proposer.propose(line)
        if proposal is None:
            continue
        assert proposal.preview not in ("readonly123", "hunter2"), line
        for secret in ("readonly123", "hunter2", "$1a$"):
            assert secret not in proposal.mapping.match, proposal.mapping.match


def test_organisation_data_is_generalised_out_of_proposed_patterns():
    proposal = LexicalProposer().propose("info-center loghost 10.0.0.5")
    assert proposal is not None
    assert "10" not in proposal.mapping.match.replace(r"\d", "")
    assert proposal.mapping.regex.search("info-center loghost 192.0.2.44")


def test_nonsense_gets_no_proposal():
    proposer = LexicalProposer()
    for line in ("return", "port link-type trunk", "interface Vlanif10"):
        assert proposer.propose(line) is None, line


def test_ollama_must_be_on_loopback():
    with pytest.raises(ValueError, match="loopback"):
        OllamaProposer("http://10.0.0.7:11434")
    with pytest.raises(ValueError, match="loopback"):
        OllamaProposer("http://ollama.example.com:11434")


class _FakeOllama(BaseHTTPRequestHandler):
    reply: ClassVar[dict[str, object]] = {}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps({"response": json.dumps(type(self).reply)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def _serve(reply: dict[str, object]) -> tuple[HTTPServer, str]:
    handler = type("Handler", (_FakeOllama,), {"reply": reply})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_a_local_model_chooses_but_the_pattern_is_built_deterministically():
    server, url = _serve({"ir_path": "ntp.servers", "value_token": "10.0.0.1", "confidence": 0.9})
    try:
        proposal = OllamaProposer(url, "test-model").propose("ntp-service unicast-server 10.0.0.1")
    finally:
        server.shutdown()
    assert proposal is not None
    assert proposal.source == "ollama:test-model"
    assert proposal.ir_path == "ntp.servers"
    assert proposal.preview == "10.0.0.1"
    assert "10\\.0" not in proposal.mapping.match


def test_a_model_that_names_a_field_outside_the_candidates_is_overruled():
    server, url = _serve({"ir_path": "aaa.enabled", "value_token": None, "confidence": 0.99})
    try:
        proposal = OllamaProposer(url, "test-model").propose("telnet server enable")
    finally:
        server.shutdown()
    assert proposal is not None
    assert proposal.ir_path == "mgmt.telnet_enabled"
    assert proposal.source.startswith("lexical")


def test_an_unreachable_model_falls_back_to_the_lexical_proposer():
    proposal = OllamaProposer("http://127.0.0.1:9", "absent", timeout=0.5).propose(
        "telnet server enable"
    )
    assert proposal is not None
    assert proposal.source == "lexical (ollama unavailable)"


# -- the training session ---------------------------------------------------------


def test_the_residue_is_grouped_into_families_with_proposals():
    session = _vrp_session()
    keys = [f.key for f in session.families]
    assert any(k.startswith("snmp-agent community read") for k in keys)
    telnet = next(f for f in session.families if f.texts[0] == "telnet server enable")
    assert telnet.proposal is not None
    assert telnet.proposal.ir_path == "mgmt.telnet_enabled"


def test_preview_shows_exactly_what_an_audit_will_do():
    session = _vrp_session()
    mapping = Mapping(
        ir_path="mgmt.idle_timeout_min",
        match=r"^idle-timeout\s+(?P<value>\d+)",
        transform="to_int",
        tier_learned=3,
        within=r"^user-interface\s+vty\b",
    )
    hits = session.preview(mapping)
    assert [(h["line"], h["value"], h["applies"]) for h in hits] == [(38, 30, True)]


def test_a_confirmation_that_matches_nothing_is_refused():
    session = _vrp_session()
    with pytest.raises(PackError):
        session.confirm(
            Mapping(
                ir_path="mgmt.telnet_enabled",
                match=r"^telnet enabled everywhere$",
                transform="presence",
                tier_learned=3,
            ),
            confirmed_by="admin",
        )


def test_train_a_vendor_cold_export_import_and_audit_elsewhere():
    """The Phase 2 definition of done, end to end, on a vendor the build never saw.

    Instance A trains VRP, signs and exports the pack. Instance B trusts A's
    key explicitly, imports the pack, and audits the same file - with rules
    now deciding on facts that no built-in parser could have produced.
    """
    from crucible.common.types import Verdict
    from crucible.pipeline import build_ir
    from crucible.policy.engine import evaluate_device

    session = _vrp_session()
    session.accept_proposals(0.85)
    for family in session.families:
        text = family.texts[0]
        if text.startswith("stelnet server enable"):
            # Tier 2 guessed Telnet from the character overlap; the
            # administrator corrects it to SSH. This is what Tier 3 is for.
            session.confirm(
                Mapping("mgmt.ssh.enabled", r"^stelnet\s+server\s+enable$", "presence", 3),
                confirmed_by="admin@org-a",
            )
        if text == "snmp-agent sys-info version v2c":
            session.confirm(
                Mapping(
                    "snmp.version",
                    r"^snmp-agent\s+sys-info\s+version\s+(?P<value>v1|v2c|v3)$",
                    "lookup",
                    3,
                    values={"v1": 1, "v2c": 2, "v3": 3},
                ),
                confirmed_by="admin@org-a",
            )
    session.confirm(
        Mapping("device.hostname", r"^sysname\s+(?P<value>\S+)$", "identity", 3),
        confirmed_by="admin@org-a",
    )

    key_a = SigningKey.generate()
    pack = session.build_pack(pack_id="huawei-vrp", vendor="huawei", os="VRP", key=key_a)
    exported = pack.to_yaml()
    assert "10.0.0" not in exported and "agg-sw-01" not in exported and "public" not in exported

    import tempfile
    from pathlib import Path

    trust_b = TrustStore(Path(tempfile.mkdtemp()))
    imported = load_pack(exported)
    with pytest.raises(PackError):
        trust_b.admit(imported)  # B has not trusted A yet
    trust_b.add(key_a.public_pem())
    trust_b.admit(imported)

    device = build_ir(load(VRP)[0], packs=[imported])
    assert device.identity.vendor == "huawei"
    verdicts = {f.rule_id: f.verdict for f in evaluate_device(device.ir, ruleset()).all_results}
    assert verdicts["CIS-NET-1.1.1"] is Verdict.FAIL  # telnet server enable
    assert verdicts["CIS-NET-2.1.2"] is Verdict.FAIL  # community "public"
    assert verdicts["CIS-NET-2.1.1"] is Verdict.FAIL  # v2c, not v3
    assert device.ir.coverage.by_tier["tier2"] + device.ir.coverage.by_tier["tier3"] >= 8


# -- the held-out number ----------------------------------------------------------


def test_held_out_routeros_measurement_is_reproducible_and_honest():
    report = evaluate_held_out(load(DEVICES / "routeros-branch-01")[0])
    assert report.vendor == "mikrotik"
    assert report.lines_with_truth >= 8
    # A floor, not a target: this test exists so a regression shows up, and so
    # the number quoted in the docs is one anyone can re-run.
    assert report.field_accuracy >= 0.7
    assert report.precision_at_threshold >= 0.6
    again = evaluate_held_out(load(DEVICES / "routeros-branch-01")[0])
    assert again.to_dict() == report.to_dict()
