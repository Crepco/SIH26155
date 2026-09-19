"""Loading configuration bundles from files, directories and archives.

Archives get more scrutiny than anything else here, because an uploaded zip is
the most hostile shape untrusted input arrives in. Path traversal, absolute
members, symlinks and decompression bombs are all refused outright rather than
sanitised - a refusal is visible, and a silently sanitised name is not.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from crucible.common.errors import IngestError, UnsafeArchiveError

__all__ = ["DeviceBundle", "SourceFile", "load"]

#: Extensions we will read as text. Anything else in a bundle is ignored rather
#: than guessed at.
TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".config",
    ".txt",
    ".log",
    ".xml",
    ".json",
    ".rsc",
    ".boot",
    ".set",
    "",
}

#: Filename fragments that mark a file as command output rather than a running
#: configuration. This is how the serial number gets found.
SHOW_OUTPUT_MARKERS = (
    "show-version",
    "show_version",
    "showversion",
    "version",
    "inventory",
    "sysinfo",
)

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2000
MAX_EXPANSION_RATIO = 200


@dataclass(slots=True)
class SourceFile:
    """One text file, with its lines fixed at read time.

    ``lines`` is the denominator of the coverage figure, so it is captured once
    and never recomputed. Line numbers cited in a report refer to this list.
    """

    name: str
    text: str
    role: str = "config"

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)

    @property
    def is_show_output(self) -> bool:
        return self.role == "show_output"


@dataclass(slots=True)
class DeviceBundle:
    """Everything uploaded about one device."""

    device_id: str
    files: list[SourceFile] = field(default_factory=list)

    @property
    def configs(self) -> list[SourceFile]:
        return [f for f in self.files if f.role == "config"]

    @property
    def show_outputs(self) -> list[SourceFile]:
        return [f for f in self.files if f.role == "show_output"]

    @property
    def total_lines(self) -> int:
        return sum(f.line_count for f in self.files)

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "files": [{"name": f.name, "role": f.role, "lines": f.line_count} for f in self.files],
        }


def _classify(name: str) -> str:
    lowered = Path(name).name.lower()
    if any(marker in lowered for marker in SHOW_OUTPUT_MARKERS):
        return "show_output"
    return "config"


def _read_text(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise IngestError(f"{path.name} exceeds the {MAX_FILE_BYTES // (1024 * 1024)}MB limit")
    data = path.read_bytes()
    # Real device output is a mix of encodings and occasionally has a BOM or a
    # stray high byte. Losing a byte is acceptable; refusing the file is not,
    # because the alternative is an auditor who cannot audit.
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _is_texty(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def _safe_extract(archive: Path, destination: Path) -> None:
    """Extract a zip, refusing anything that tries to escape the destination."""
    with zipfile.ZipFile(archive) as zf:
        members = zf.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise UnsafeArchiveError(
                f"archive contains {len(members)} members, limit is {MAX_ARCHIVE_MEMBERS}"
            )
        compressed = sum(m.compress_size for m in members) or 1
        uncompressed = sum(m.file_size for m in members)
        if uncompressed / compressed > MAX_EXPANSION_RATIO:
            raise UnsafeArchiveError(
                f"expansion ratio {uncompressed // compressed}x looks like a decompression bomb"
            )

        for member in members:
            name = member.filename
            if name.startswith("/") or name.startswith("\\"):
                raise UnsafeArchiveError(f"absolute path in archive: {name}")
            if ".." in Path(name).parts:
                raise UnsafeArchiveError(f"path traversal in archive: {name}")
            # Unix mode is in the top 16 bits; 0xA000 is a symlink.
            if (member.external_attr >> 16) & 0xF000 == 0xA000:
                raise UnsafeArchiveError(f"symlink in archive: {name}")

        zf.extractall(destination)


def _bundle_from_directory(directory: Path, device_id: str) -> DeviceBundle:
    bundle = DeviceBundle(device_id=device_id)
    for path in sorted(directory.rglob("*")):
        if path.is_file() and _is_texty(path):
            relative = path.relative_to(directory.parent)
            bundle.files.append(
                SourceFile(
                    name=str(relative).replace("\\", "/"),
                    text=_read_text(path),
                    role=_classify(path.name),
                )
            )
    return bundle


def _group_loose_files(paths: Iterable[Path], root: Path) -> list[DeviceBundle]:
    """Group loose files by stem so ``core-01.cfg`` and ``core-01.show-version.txt``
    become one device rather than two.

    Getting this wrong is how a tool ends up reporting a device with no serial
    number next to a phantom device that is nothing but a serial number.
    """
    groups: dict[str, DeviceBundle] = {}
    for path in sorted(paths):
        stem = path.name.split(".")[0]
        bundle = groups.setdefault(stem, DeviceBundle(device_id=stem))
        try:
            name = str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            name = path.name
        bundle.files.append(SourceFile(name=name, text=_read_text(path), role=_classify(path.name)))
    return list(groups.values())


def load(target: str | Path, *, workdir: Path | None = None) -> list[DeviceBundle]:
    """Load one or many device bundles from a path.

    - A file becomes one bundle.
    - A directory of files groups them by filename stem.
    - A directory of subdirectories treats each subdirectory as one device.
    - A ``.zip`` is safely extracted and then treated as a directory.
    """
    path = Path(target)
    if not path.exists():
        raise IngestError(f"no such path: {path}")

    if path.is_file() and path.suffix.lower() == ".zip":
        if workdir is None:
            raise IngestError("extracting an archive requires a workdir")
        destination = workdir / (path.stem + "-extracted")
        destination.mkdir(parents=True, exist_ok=True)
        _safe_extract(path, destination)
        return load(destination)

    if path.is_file():
        if not _is_texty(path):
            raise IngestError(f"{path.name} is not a readable configuration file")
        stem = path.name.split(".")[0]
        return [
            DeviceBundle(
                device_id=stem,
                files=[
                    SourceFile(name=path.name, text=_read_text(path), role=_classify(path.name))
                ],
            )
        ]

    subdirectories = [p for p in sorted(path.iterdir()) if p.is_dir()]
    loose = [p for p in sorted(path.iterdir()) if p.is_file() and _is_texty(p)]

    bundles: list[DeviceBundle] = []
    for directory in subdirectories:
        bundle = _bundle_from_directory(directory, directory.name)
        if bundle.files:
            bundles.append(bundle)

    if loose:
        # A directory holding one configuration plus its command output is one
        # device's bundle, not several devices that happen to share a folder.
        # Splitting it by filename stem would file the show output as its own
        # device - which then has a serial number and no configuration, while
        # the real device has a configuration and no serial.
        config_count = sum(1 for p in loose if _classify(p.name) == "config")
        if config_count <= 1 and not subdirectories:
            bundle = DeviceBundle(device_id=path.name)
            for file_path in loose:
                bundle.files.append(
                    SourceFile(
                        name=f"{path.name}/{file_path.name}",
                        text=_read_text(file_path),
                        role=_classify(file_path.name),
                    )
                )
            bundles.append(bundle)
        else:
            bundles.extend(_group_loose_files(loose, path))

    if not bundles:
        raise IngestError(f"no readable configuration files under {path}")
    return bundles
