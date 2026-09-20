#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Build the offline installation bundle.
#
# The customer installs this on a machine that has never had a network and
# never will. Everything the product needs is inside the tarball: wheels for
# every dependency, the source, the rules, the schemas, and the twin image.
#
#   make bundle                 # or: scripts/build-offline-bundle.sh dist/
#
# Building the bundle needs a network. Installing it must not, and
# scripts/verify-offline-bundle.sh proves that by installing with no index.
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-dist}"
version="$(grep -m1 '^version' backend/pyproject.toml | cut -d'"' -f2)"
stamp="$(date -u +%Y%m%d)"
name="crucible-${version}-offline-${stamp}"
staging="${out}/${name}"

echo
echo "  building ${name}"
rm -rf "${staging}"
mkdir -p "${staging}/wheels" "${staging}/image"

# 1. Every dependency, as a wheel for this platform.
echo "  - downloading wheels"
python -m pip download \
  --requirement backend/requirements.txt \
  --dest "${staging}/wheels" \
  --quiet

# 2. The product itself: source, rules, schemas, console, labs.
echo "  - copying the product"
for path in backend rules schemas adapters frontend labs docs README.md LICENSE CHANGELOG.md; do
  cp -r "${path}" "${staging}/"
done
find "${staging}" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${staging}" -name "*.pyc" -delete 2>/dev/null || true

# 3. The Crucible twin image, if Docker is here to export it.
if command -v docker >/dev/null 2>&1 && docker image inspect crucible-twin:1 >/dev/null 2>&1; then
  echo "  - exporting the twin image"
  docker save crucible-twin:1 | gzip > "${staging}/image/crucible-twin-1.tar.gz"
else
  echo "  - no twin image to export (the sandbox will be unavailable until one is built)"
fi

# 4. How to install it, in the bundle itself.
cat > "${staging}/INSTALL.md" <<'INSTALL'
# Installing Crucible offline

No network is needed, or used, at any point below.

```bash
python -m venv .venv
. .venv/bin/activate                     # Windows: .venv\Scripts\Activate.ps1

pip install --no-index --find-links wheels -r backend/requirements.txt

cd backend && python tests/run_tests.py  # expect: all tests passed
python -m crucible.api.cli audit tests/fixtures/devices --out ../reports
python -m crucible.api.cli verify ../reports/ledger.jsonl
```

The console: `python -m uvicorn crucible.api.main:app --host 127.0.0.1 --port 8000`

The verification sandbox, where Docker is available:

```bash
docker load < image/crucible-twin-1.tar.gz
python -m crucible.api.cli verify --device tests/fixtures/devices/cisco-ios-core-01 \
  --finding CIS-NET-1.1.1
```

Nothing in this bundle reaches a network. `scripts/check-airgap.sh` re-checks that
on the installed copy.
INSTALL

# 5. A manifest with a digest for every file, and a digest of the manifest.
echo "  - writing the manifest"
( cd "${staging}" && find . -type f ! -name MANIFEST.sha256 -print0 \
  | sort -z | xargs -0 sha256sum > MANIFEST.sha256 )
sha256sum "${staging}/MANIFEST.sha256" | cut -d' ' -f1 > "${staging}/MANIFEST.sha256.digest"

tarball="${out}/${name}.tar.gz"
tar -czf "${tarball}" -C "${out}" "${name}"
sha256sum "${tarball}" > "${tarball}.sha256"

echo
echo "  bundle     ${tarball}"
echo "  size       $(du -h "${tarball}" | cut -f1)"
echo "  wheels     $(find "${staging}/wheels" -type f | wc -l)"
echo "  manifest   $(wc -l < "${staging}/MANIFEST.sha256") files, digest $(cat "${staging}/MANIFEST.sha256.digest")"
echo
