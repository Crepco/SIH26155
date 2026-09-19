"""Ingestion, and the hostile shapes untrusted input arrives in.

Configuration files come from outside the trust boundary. An uploaded archive is
the most hostile shape they take, so the archive tests here are the ones that
matter: path traversal, absolute members and decompression bombs are refused
outright rather than sanitised, because a refusal is visible and a silently
rewritten filename is not.
"""

from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import pytest
from conftest import DEVICES

from crucible.common.errors import IngestError, UnsafeArchiveError
from crucible.ingest.bundle import load


def _tmp() -> Path:
    return Path(tempfile.mkdtemp())


# -- normal shapes ---------------------------------------------------------


def test_a_directory_of_device_directories_becomes_one_bundle_each():
    bundles = load(DEVICES)
    assert len(bundles) == 6
    assert {b.device_id for b in bundles} == {
        "cisco-ios-core-01",
        "arista-leaf-01",
        "fortios-fw-01",
        "junos-edge-01",
        "routeros-branch-01",
        "panos-fw-01",
    }


def test_show_output_is_classified_separately_from_configuration():
    """The serial number lives in show output, so it has to be identifiable.

    A tool that treats every file as a config cannot find a serial, and quietly
    ships a report with an empty identity field.
    """
    bundle = load(DEVICES / "cisco-ios-core-01")[0]
    assert len(bundle.configs) == 1
    assert len(bundle.show_outputs) == 1
    assert "show-version" in bundle.show_outputs[0].name


def test_loose_files_are_grouped_by_stem_into_one_device():
    """`core-01.cfg` and `core-01.show-version.txt` are one device, not two.

    Getting this wrong produces a device with no serial next to a phantom device
    that is nothing but a serial.
    """
    directory = _tmp()
    (directory / "core-01.cfg").write_text("hostname core-01\n", encoding="utf-8")
    (directory / "core-01.show-version.txt").write_text(
        "System serial number : ABC\n", encoding="utf-8"
    )
    (directory / "edge-02.cfg").write_text("hostname edge-02\n", encoding="utf-8")

    bundles = {b.device_id: b for b in load(directory)}
    assert set(bundles) == {"core-01", "edge-02"}
    assert len(bundles["core-01"].files) == 2
    assert len(bundles["core-01"].show_outputs) == 1


def test_a_single_file_becomes_a_single_bundle():
    directory = _tmp()
    path = directory / "one.cfg"
    path.write_text("hostname one\n", encoding="utf-8")
    bundles = load(path)
    assert len(bundles) == 1 and bundles[0].device_id == "one"


def test_line_counts_are_fixed_at_read_time():
    """Coverage denominators must not shift under the parser."""
    bundle = load(DEVICES / "cisco-ios-core-01")[0]
    assert bundle.total_lines == sum(f.line_count for f in bundle.files)
    assert bundle.total_lines > 100


# -- error paths -----------------------------------------------------------


def test_a_missing_path_is_an_error_not_an_empty_result():
    with pytest.raises(IngestError):
        load(_tmp() / "does-not-exist")


def test_a_directory_with_nothing_readable_is_an_error():
    """An empty result would be indistinguishable from a clean audit."""
    with pytest.raises(IngestError):
        load(_tmp())


# -- archives --------------------------------------------------------------


def test_a_normal_archive_extracts_and_loads():
    directory = _tmp()
    archive = directory / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("core-01/running-config.txt", "hostname core-01\nip ssh version 2\n")
        zf.writestr("core-01/show-version.txt", "System serial number : FDO1\n")

    bundles = load(archive, workdir=directory)
    assert len(bundles) == 1
    assert bundles[0].device_id == "core-01"
    assert len(bundles[0].show_outputs) == 1


def test_path_traversal_in_an_archive_is_refused():
    directory = _tmp()
    archive = directory / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0\n")

    with pytest.raises(UnsafeArchiveError):
        load(archive, workdir=directory)


def test_an_absolute_member_path_is_refused():
    directory = _tmp()
    archive = directory / "absolute.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("/etc/shadow", "nope\n")

    with pytest.raises(UnsafeArchiveError):
        load(archive, workdir=directory)


def test_a_decompression_bomb_is_refused():
    """A ratio far past anything a real configuration bundle produces.

    Text configs compress well, but not ten-thousand-to-one. Refusing keeps a
    bulk upload endpoint from being a memory exhaustion primitive.
    """
    directory = _tmp()
    archive = directory / "bomb.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.cfg", "A" * (8 * 1024 * 1024))

    with pytest.raises(UnsafeArchiveError):
        load(archive, workdir=directory)


def test_extracting_without_a_workdir_is_refused():
    """Never extract into a caller-unspecified location."""
    directory = _tmp()
    archive = directory / "b.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("d/c.cfg", "hostname d\n")

    with pytest.raises(IngestError):
        load(archive)


# -- encoding ---------------------------------------------------------------


def test_mixed_encodings_are_read_rather_than_refused():
    """Real device output is not always clean UTF-8.

    Losing a byte to a replacement character is acceptable; refusing the file is
    not, because the alternative is an auditor who cannot audit.
    """
    directory = _tmp()
    path = directory / "latin.cfg"
    path.write_bytes(b"hostname caf\xe9-rtr\nip ssh version 2\n")
    bundle = load(path)[0]
    assert bundle.files[0].line_count == 2
    assert "ssh" in bundle.files[0].text


def test_a_utf8_bom_does_not_corrupt_the_first_line():
    directory = _tmp()
    path = directory / "bom.cfg"
    path.write_bytes(b"\xef\xbb\xbfhostname bom-rtr\n")
    bundle = load(path)[0]
    assert bundle.files[0].lines[0] == "hostname bom-rtr"
