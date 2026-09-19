"""Zero-dependency test runner.

The suite is written as ordinary pytest functions and runs under pytest when it
is available. This runner exists so it *also* runs on a machine that has nothing
installed but the standard library - which is the machine this project is
actually built for.

    python tests/run_tests.py            # everything
    python tests/run_tests.py expr ir    # only matching modules

It supports the small slice of pytest the suite uses: test discovery, plain
asserts, and `pytest.raises`. Anything fancier belongs in a test that is honest
about needing pytest.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
import traceback
from pathlib import Path

TESTS_DIR = Path(__file__).parent
ROOT = TESTS_DIR.parent


class _Raises:
    """Minimal stand-in for ``pytest.raises`` as a context manager."""

    def __init__(self, expected: type[BaseException] | tuple[type[BaseException], ...]) -> None:
        self.expected = expected
        self.value: BaseException | None = None

    def __enter__(self) -> _Raises:
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:  # type: ignore[no-untyped-def]
        if exc_type is None:
            names = getattr(self.expected, "__name__", str(self.expected))
            raise AssertionError(f"expected {names} but nothing was raised")
        if not issubclass(exc_type, self.expected):  # type: ignore[arg-type]
            return False
        self.value = exc
        return True


def _install_pytest_shim() -> None:
    """Provide just enough ``pytest`` for the suite to import cleanly."""
    if "pytest" in sys.modules:
        return
    try:
        import pytest  # noqa: F401

        return
    except ImportError:
        pass

    import types

    shim = types.ModuleType("pytest")
    shim.raises = _Raises  # type: ignore[attr-defined]

    def _mark_stub(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        def decorator(fn):  # type: ignore[no-untyped-def]
            return fn

        return decorator

    marker = types.SimpleNamespace(
        integration=_mark_stub(), sandbox=_mark_stub(), model=_mark_stub()
    )
    shim.mark = marker  # type: ignore[attr-defined]
    sys.modules["pytest"] = shim


def _load(path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str]) -> int:
    sys.path.insert(0, str(ROOT))
    # conftest lives beside the tests and is imported by name, so the tests
    # directory has to be importable too - pytest does this for us.
    sys.path.insert(0, str(TESTS_DIR))
    _install_pytest_shim()

    filters = [a.lower() for a in argv]
    files = sorted(TESTS_DIR.rglob("test_*.py"))
    if filters:
        files = [f for f in files if any(term in f.stem.lower() for term in filters)]

    passed = 0
    failures: list[tuple[str, str]] = []

    for file in files:
        module = _load(file)
        tests = [
            (name, fn)
            for name, fn in sorted(vars(module).items())
            if name.startswith("test_") and inspect.isfunction(fn)
        ]
        for name, fn in tests:
            label = f"{file.stem}::{name}"
            try:
                fn()
            except Exception:
                failures.append((label, traceback.format_exc()))
                print(f"  FAIL  {label}")
            else:
                passed += 1
                print(f"  ok    {label}")

    print()
    if failures:
        for label, tb in failures:
            print("=" * 72)
            print(label)
            print(tb)
        print(f"{passed} passed, {len(failures)} FAILED")
        return 1

    print(f"{passed} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
