"""Tamper evidence.

These tests are the difference between a ledger and a log file. A log file
records what happened; a ledger makes altering the record detectable. Each test
below alters something and asserts that the alteration is caught.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from crucible.common.canonical import canonical_json
from crucible.common.errors import LedgerError
from crucible.ledger.chain import GENESIS, Ledger
from crucible.ledger.merkle import leaf_hash, merkle_proof, merkle_root, verify_proof
from crucible.ledger.signing import SigningKey, load_or_create_key


def _tmp() -> Path:
    return Path(tempfile.mkdtemp())


def _leaves(n: int = 5) -> list[str]:
    return [leaf_hash({"rule_id": f"R{i}", "verdict": "fail"}) for i in range(n)]


# -- canonicalisation ------------------------------------------------------


def test_serialisation_is_order_independent():
    """Two dicts with the same content hash the same regardless of key order.

    If this were false, the same findings would produce two Merkle roots and
    verification would be meaningless.
    """
    assert canonical_json({"b": 1, "a": [1, 2]}) == canonical_json({"a": [1, 2], "b": 1})


def test_floats_are_rejected_from_hashed_structures():
    """A float would eventually differ in its last bit between platforms."""
    with pytest.raises(TypeError):
        canonical_json({"confidence": 0.85})


# -- merkle ----------------------------------------------------------------


def test_root_changes_when_any_leaf_changes():
    leaves = _leaves()
    root = merkle_root(leaves)
    altered = list(leaves)
    altered[2] = leaf_hash({"rule_id": "R2", "verdict": "pass"})
    assert merkle_root(altered) != root, "flipping a verdict did not change the root"


def test_odd_node_is_promoted_not_duplicated():
    """Duplicating an odd node lets two different trees share a root.

    That is the CVE-2012-2459 shape. Promotion avoids it, and this test exists
    so nobody 'simplifies' the loop back into a duplication.
    """
    three = _leaves(3)
    four = [*three, three[-1]]
    assert merkle_root(three) != merkle_root(four)


def test_inclusion_proof_verifies_and_fails_on_substitution():
    leaves = _leaves(7)
    root = merkle_root(leaves)
    for index in range(len(leaves)):
        proof = merkle_proof(leaves, index)
        assert verify_proof(leaves[index], proof, root)
    forged = leaf_hash({"rule_id": "R3", "verdict": "pass"})
    assert not verify_proof(forged, merkle_proof(leaves, 3), root)


def test_an_empty_report_still_has_a_root():
    """A clean device is a real, signable audit result.

    Refusing to root it would mean the only reports that cannot be proven
    unaltered are the ones saying nothing was wrong.
    """
    assert merkle_root([])


# -- chain -----------------------------------------------------------------


def _populated(directory: Path, entries: int = 3):  # type: ignore[no-untyped-def]
    key = load_or_create_key(directory / "signing" / "ed25519.key")
    ledger = Ledger.open(directory / "ledger.jsonl")
    for index in range(entries):
        ledger.append(
            report_id=f"AUDIT-{index}",
            device_id=f"device-{index}",
            merkle_root=merkle_root(_leaves(index + 1)),
            rule_set_digest="digest",
            ir_schema_version="1.0.0",
            key=key,
        )
    return ledger, key


def test_a_fresh_ledger_links_to_genesis():
    directory = _tmp()
    ledger, _ = _populated(directory, entries=1)
    assert ledger.entries[0].prev_entry_hash == GENESIS


def test_intact_ledger_verifies():
    directory = _tmp()
    ledger, key = _populated(directory)
    ok, problems = ledger.verify(key.verifying_key())
    assert ok, problems


def test_altering_a_historical_entry_breaks_the_chain_and_the_signature():
    """The property the whole design exists for.

    One edit to entry 1 invalidates its signature *and* every link after it, so
    an attacker has to forge the issuing key to rewrite history rather than just
    edit a file.
    """
    directory = _tmp()
    ledger, key = _populated(directory)
    ledger.entries[0].merkle_root = "0" * 64

    ok, problems = ledger.verify(key.verifying_key())
    assert not ok
    assert any("signature" in p for p in problems)
    assert any("chain broken" in p for p in problems)


def test_a_ledger_reloaded_from_disk_still_verifies():
    """Verification must work from the file alone, years later.

    An air-gapped verifier has the report, the ledger and a public key. Nothing
    may depend on state held by the process that wrote it.
    """
    directory = _tmp()
    _, key = _populated(directory)
    reloaded = Ledger.open(directory / "ledger.jsonl")
    assert len(reloaded) == 3
    ok, problems = reloaded.verify(key.verifying_key())
    assert ok, problems


def test_a_foreign_key_does_not_verify():
    directory = _tmp()
    ledger, _ = _populated(directory)
    ok, problems = ledger.verify(SigningKey.generate().verifying_key())
    assert not ok
    assert all("signature" in p for p in problems)


def test_a_corrupt_ledger_file_is_refused_loudly():
    """A ledger that cannot be read is an error, never an empty ledger.

    Treating an unreadable ledger as empty would let deleting it look like a
    clean history.
    """
    directory = _tmp()
    (directory / "ledger.jsonl").write_text("not json at all\n", encoding="utf-8")
    with pytest.raises(LedgerError):
        Ledger.open(directory / "ledger.jsonl")


def test_entries_are_appended_not_rewritten():
    directory = _tmp()
    ledger, key = _populated(directory, entries=2)
    first_pass = (directory / "ledger.jsonl").read_text(encoding="utf-8")

    ledger.append(
        report_id="AUDIT-later",
        device_id="device-later",
        merkle_root=merkle_root(_leaves(2)),
        rule_set_digest="digest",
        ir_schema_version="1.0.0",
        key=key,
    )
    second_pass = (directory / "ledger.jsonl").read_text(encoding="utf-8")

    assert second_pass.startswith(first_pass), "an existing entry was rewritten"
    assert len(second_pass.splitlines()) == 3


def test_the_verification_hash_is_stable_and_short_enough_to_read():
    directory = _tmp()
    ledger, _ = _populated(directory, entries=1)
    entry = ledger.entries[0]
    assert entry.verification_hash == entry.entry_hash[:16]
    assert len(entry.verification_hash) == 16


def test_signing_key_file_is_not_world_readable():
    """Key material gets 0600 at creation, not afterwards."""
    import os
    import stat

    directory = _tmp()
    path = directory / "signing" / "ed25519.key"
    load_or_create_key(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    # Windows does not honour POSIX bits; assert only where it means something.
    if os.name == "posix":
        assert mode == 0o600, f"key file mode is {oct(mode)}"
    assert path.with_suffix(".pub").exists(), "public key was not written alongside"


def test_ledger_entries_are_valid_json_lines():
    directory = _tmp()
    _populated(directory, entries=2)
    for line in (directory / "ledger.jsonl").read_text(encoding="utf-8").splitlines():
        json.loads(line)
