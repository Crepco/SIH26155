#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Corpus progress against the Phase 0 target: 60+ configurations, 20 labelled.
#
#   make corpus
#
# Counts what is actually on disk. The manifest is a claim; this is the count.
# ---------------------------------------------------------------------------
set -uo pipefail
cd "$(dirname "$0")/.."

raw="corpus/raw"
labels="corpus/labels"

configs=$(find "${raw}" -type f ! -name ".gitkeep" 2>/dev/null | wc -l)
labelled=$(find "${labels}" -name "*.yaml" ! -name "_*" 2>/dev/null | wc -l)
fixtures=$(find backend/tests/fixtures/devices -mindepth 1 -maxdepth 1 -type d | wc -l)
fixture_labels=$(find "${labels}/fixtures" -name "*.yaml" 2>/dev/null | wc -l)

echo
echo "  corpus"
echo "    real configurations   ${configs} / 60"
echo "    label files           ${labelled} / 20"
echo
echo "  shipped fixtures (not the corpus, but audited and labelled in CI)"
echo "    devices               ${fixtures}"
echo "    labelled              ${fixture_labels}"
echo

if [ "${configs}" -eq 0 ]; then
  echo "  corpus/raw is empty: the accuracy number comes from the fixtures only,"
  echo "  and every report of it says so. See corpus/README.md."
  echo
fi

for vendor in cisco arista juniper fortinet mikrotik paloalto vyos sonic frr nokia; do
  count=$(find "${raw}" -iname "*${vendor}*" -type f 2>/dev/null | wc -l)
  [ "${count}" -gt 0 ] && printf "    %-12s %s\n" "${vendor}" "${count}"
done
echo
