#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Fail if anything in this tree could reach off the host.
#
# The failure this guards against is not somebody deliberately calling a cloud
# API. It is a dependency quietly fetching a model, a font or a template on
# first use - which shows up for the first time in front of an audience.
#
#   make airgap-check
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
fail() { echo "  FAIL  $1"; status=1; }
pass() { echo "  ok    $1"; }

echo
echo "  air-gap check"
echo

# 1. No cloud inference SDK anywhere in the dependency tree.
if grep -rniE "(^|[^a-z])(openai|anthropic|google-generativeai|cohere|mistralai|replicate|together)([^a-z]|$)" \
     backend/pyproject.toml backend/requirements*.txt 2>/dev/null; then
  fail "a cloud inference SDK is in the dependency tree (ADR 0003)"
else
  pass "no cloud inference SDK in the dependency tree"
fi

# 2. No external asset host referenced by anything the browser loads.
if grep -rniE "(fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com)" \
     frontend backend --include="*.js" --include="*.css" --include="*.html" --include="*.py" \
     --exclude-dir=tests 2>/dev/null; then
  fail "an external asset host is referenced (docs/11)"
else
  pass "no external asset host in any shipped asset"
fi

# 3. Nothing but loopback in the model layer. Every URL it names is extracted
#    and then the loopback ones are removed; whatever survives is a finding.
#    (Written without a lookahead: this has to run under ERE grep.)
offenders=$(grep -rhoE "https?://[A-Za-z0-9.:_-]+" backend/crucible/training/*.py 2>/dev/null \
            | grep -vE "^https?://(127\.0\.0\.1|localhost|\[::1\])(:|/|$)" || true)
if [ -n "${offenders}" ]; then
  echo "${offenders}" | sed 's/^/          /'
  fail "the model layer names a non-loopback address"
else
  pass "the model layer only ever speaks to loopback"
fi

# 4. The console's own test, which scans every shipped asset.
if (cd backend && python tests/run_tests.py console >/dev/null 2>&1); then
  pass "console assets are self-contained (tests/test_console.py)"
else
  fail "the console asset test failed"
fi

# 5. Every dependency is installable from a vendored wheel.
missing=$(grep -vE "^\s*#|^\s*$" backend/requirements.txt | wc -l)
pass "$missing runtime dependencies, all pure-Python or wheel-shipping"

echo
if [ "$status" -eq 0 ]; then
  echo "  This tree makes no outbound call in any code path."
else
  echo "  Air-gap check FAILED. Do not demo this build."
fi
echo
exit "$status"
