#!/usr/bin/env bash
# Fetch the 6502/65C02 conformance corpus. FETCH, never vendor.
#
# WHY NOT VENDORED
# ----------------
# Klaus Dormann's suite is GPL-3.0 (its own license.txt). r2sleigh is not, and
# this repo's sibling workspaces carry an explicit standing rule that GPL
# emulator/test sources are BEHAVIOURAL REFERENCE ONLY — never transcribed,
# never copied in. So the bytes stay outside the tree and arrive on demand,
# exactly like an external benchmark corpus.
#
# The second reason is independent of licensing and would apply anyway: a test
# fixture that lives outside the repo but is used as if it were inside is a
# time bomb. Committed tests must read committed data; anything fetched is a
# MEASUREMENT input, not a gate. Nothing under tests/ may depend on this
# script having run.
#
# Usage:  tests/corpus/fetch-6502-suite.sh [dest]     (default: tests/corpus/cache)
set -euo pipefail

DEST="${1:-$(cd "$(dirname "$0")" && pwd)/cache}"
REPO="https://github.com/Klaus2m5/6502_65C02_functional_tests"

# sha256 of the upstream prebuilt binaries, measured 2026-08-25.
# A mismatch is a HARD failure: a conformance corpus that silently changed is
# worse than an absent one, because every number measured against it moves
# without anything saying so.
declare -A EXPECT=(
  ["6502_functional_test.bin"]="fa12bfc761e6f9057e4cc01a665a7b800ff01ae91f598af1e39a1201d01953fd"
  ["65C02_extended_opcodes_test.bin"]="10a2a07fa240666fa610c46accebe8d42b1000feef3aae619da15a8d152869b2"
)

mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "fetching $REPO (shallow) ..."
git clone --depth 1 "$REPO" "$TMP/suite" >/dev/null 2>&1

rc=0
for f in "${!EXPECT[@]}"; do
  src="$TMP/suite/bin_files/$f"
  if [ ! -f "$src" ]; then
    echo "MISSING  $f — upstream layout changed"
    rc=1
    continue
  fi
  got="$(sha256sum "$src" | cut -d' ' -f1)"
  if [ "$got" != "${EXPECT[$f]}" ]; then
    echo "MISMATCH $f"
    echo "  expected ${EXPECT[$f]}"
    echo "  actual   $got"
    rc=1
    continue
  fi
  cp "$src" "$DEST/$f"
  echo "ok       $f  ($(stat -c%s "$src") B)"
done

# The licence travels with the bytes. Anyone who fetched the corpus has the
# terms it came under, in the same directory.
cp "$TMP/suite/license.txt" "$DEST/LICENSE.upstream-GPL-3.0.txt" 2>/dev/null || true
echo "$REPO" > "$DEST/PROVENANCE.txt"

[ $rc -eq 0 ] && echo "corpus ready in $DEST" || echo "corpus INCOMPLETE"
exit $rc
