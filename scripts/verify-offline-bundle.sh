#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Install a bundle the way the customer will, and prove it needed no network.
#
#   scripts/verify-offline-bundle.sh dist/crucible-0.1.0-offline-20260920.tar.gz
#
# The build is not trusted; it is tested. Three things are checked, in the
# order they would fail for a real operator:
#
#   1. the manifest still describes the contents (nothing lost in transit)
#   2. pip installs with no package index configured at all
#   3. the suite and a full audit both pass with PIP_NO_INDEX set and every
#      proxy variable pointed at a black hole
#
# This does not simulate a severed NIC - that needs a container, and the CI
# job does it that way. What it does catch is the common failure: a package
# or an asset that is not actually in the bundle, so installation reaches out.
# ---------------------------------------------------------------------------
set -uo pipefail

tarball="${1:-}"
if [ -z "${tarball}" ] || [ ! -f "${tarball}" ]; then
  echo "usage: $0 <bundle.tar.gz>" >&2
  exit 2
fi

status=0
fail() { echo "  FAIL  $1"; status=1; }
pass() { echo "  ok    $1"; }

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo
echo "  verifying $(basename "${tarball}")"
echo

# 0. The archive's own digest, if it was delivered alongside.
if [ -f "${tarball}.sha256" ]; then
  if (cd "$(dirname "${tarball}")" && sha256sum -c "$(basename "${tarball}").sha256" >/dev/null 2>&1); then
    pass "archive digest matches"
  else
    fail "archive digest does NOT match - do not install this"
    exit 1
  fi
fi

# Extracted by name from its own directory: an absolute "C:/..." after -f is
# read by tar as host:path and fails as a remote copy.
( cd "$(dirname "${tarball}")" && tar -xzf "$(basename "${tarball}")" -C "${work}" )
root="$(find "${work}" -mindepth 1 -maxdepth 1 -type d | head -1)"

# 1. Every file still hashes to what the build recorded.
if (cd "${root}" && sha256sum -c MANIFEST.sha256 --quiet 2>/dev/null); then
  pass "manifest verifies ($(wc -l < "${root}/MANIFEST.sha256") files)"
else
  fail "the manifest does not match the contents"
fi

# 2. Install with no index. Any reach for a package fails here.
python -m venv "${work}/venv" >/dev/null 2>&1
venv_python="${work}/venv/bin/python"
[ -x "${venv_python}" ] || venv_python="${work}/venv/Scripts/python.exe"

if "${venv_python}" -m pip install --no-index --find-links "${root}/wheels" \
     -r "${root}/backend/requirements.txt" >"${work}/install.log" 2>&1; then
  pass "installed from vendored wheels with no package index"
else
  fail "installation reached for something that is not in the bundle:"
  tail -5 "${work}/install.log" | sed 's/^/          /'
  exit 1
fi

# 3. Run it, with every route to a proxy poisoned.
export PIP_NO_INDEX=1
export http_proxy="http://127.0.0.1:9" https_proxy="http://127.0.0.1:9"
export HTTP_PROXY="${http_proxy}" HTTPS_PROXY="${https_proxy}" no_proxy=""

if (cd "${root}/backend" && "${venv_python}" tests/run_tests.py >"${work}/tests.log" 2>&1); then
  pass "the suite passes from the installed bundle ($(grep -oE '[0-9]+ passed' "${work}/tests.log" | tail -1))"
else
  fail "the suite failed from the installed bundle:"
  tail -10 "${work}/tests.log" | sed 's/^/          /'
fi

(
  cd "${root}/backend" \
    && "${venv_python}" -m crucible.api.cli audit tests/fixtures/devices \
         --rules ../rules/cis --out "${work}/reports"
) >"${work}/audit.log" 2>&1
code=$?
# 0 is a clean fleet and 1 is findings; both mean the pipeline ran. Anything
# else is the audit itself failing.
if [ "${code}" -gt 1 ]; then
  fail "the audit exited ${code}"
  tail -10 "${work}/audit.log" | sed 's/^/          /'
fi
if [ -f "${work}/reports/ledger.jsonl" ]; then
  pass "a full audit ran and wrote a ledger"
  if (cd "${root}/backend" && "${venv_python}" -m crucible.api.cli verify \
        "${work}/reports/ledger.jsonl" >/dev/null 2>&1); then
    pass "the ledger verifies INTACT"
  else
    fail "the ledger did not verify"
  fi
else
  fail "the audit produced no ledger"
fi

echo
if [ "${status}" -eq 0 ]; then
  echo "  This bundle installs and runs with no package index and no proxy."
else
  echo "  Bundle verification FAILED. Do not ship it."
fi
echo
exit "${status}"
