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

# 2. The product itself: source, rules, schemas, console, labs, and the label
#    files the validation harness reads.
#
#    Taken from git, not copied out of the working tree. A plain copy picks up
#    whatever happens to be lying around - a local virtualenv, a build
#    directory, a cache - and the bundle then carries paths deep enough that
#    extraction silently truncates them on Windows. What is committed ships.
echo "  - copying the product"
git archive --format=tar HEAD \
    backend rules schemas adapters frontend labs docs corpus scripts \
    README.md LICENSE CHANGELOG.md Makefile \
  | tar -x -C "${staging}"

# 3. The Crucible twin image, if Docker is here to export it.
#
#    Written straight to a tar: the whole staging directory is gzipped into the
#    archive below, and compressing it twice costs minutes for nothing.
#
#    Every docker call is bounded. A daemon that has wedged does not refuse the
#    connection, it simply never answers - so an unbounded `docker save` turns a
#    bundle build into a hang with no output, which is the worst way to fail.
docker_ok=0
if command -v docker >/dev/null 2>&1 \
   && timeout 20 docker image inspect crucible-twin:1 >/dev/null 2>&1; then
  docker_ok=1
fi

if [ "${docker_ok}" -eq 1 ]; then
  echo "  - exporting the twin image"
  if ! timeout 300 docker save crucible-twin:1 -o "${staging}/image/crucible-twin-1.tar"; then
    echo "    the daemon did not answer; the bundle will ship without the image"
    rm -f "${staging}/image/crucible-twin-1.tar"
  fi
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

The verification sandbox, where Docker is available and `image/` carries a twin
(without it, findings stay ASSERTED and the audit is otherwise unaffected):

```bash
docker load -i image/crucible-twin-1.tar
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
# Named relative to `out`, never as an absolute path: tar reads an argument to
# -f that contains a colon as host:path, so "C:/..." is a failed rsh to host C.
( cd "${out}" && tar -czf "${name}.tar.gz" "${name}" )
# Recorded with the bare filename, so `sha256sum -c` works from wherever the
# media is mounted rather than only from the directory that built it.
( cd "${out}" && sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256" )

echo
echo "  bundle     ${tarball}"
echo "  size       $(du -h "${tarball}" | cut -f1)"
echo "  wheels     $(find "${staging}/wheels" -type f | wc -l)"
echo "  manifest   $(wc -l < "${staging}/MANIFEST.sha256") files, digest $(cat "${staging}/MANIFEST.sha256.digest")"
echo
