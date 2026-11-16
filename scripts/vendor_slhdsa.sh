#!/usr/bin/env bash
# Re-vendor or verify the slhdsa-c sources used by crates/qshield-slhdsa-sys.
#
#   scripts/vendor_slhdsa.sh <commit>   fetch upstream at <commit>, copy the library files,
#                                       print SHA-256 sums to paste into the crate README
#   scripts/vendor_slhdsa.sh --check    verify vendored files against the sums in the README
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DST="$ROOT/crates/qshield-slhdsa-sys/vendor/slhdsa-c"
README="$ROOT/crates/qshield-slhdsa-sys/README.md"
FILES=(LICENSE README.md cbmc.h plat_local.h sha2_256.c sha2_512.c sha2_api.h sha3_api.c sha3_api.h
       sha3_f1600.c slh_adrs.h slh_dsa.c slh_dsa.h slh_param.h slh_prehash.c slh_prehash.h
       slh_sha2.c slh_shake.c slh_sys.h slh_var.h)

if [[ "${1:-}" == "--check" ]]; then
  # Lines of the form "<64 hex>  <file>" inside the README code block.
  grep -E '^[0-9a-f]{64}  ' "$README" > /tmp/qshield-slhdsa.sums
  (cd "$DST" && sha256sum --check --strict /tmp/qshield-slhdsa.sums)
  extra=$(cd "$DST" && ls | grep -v -x -F -f <(printf '%s\n' "${FILES[@]}") || true)
  if [[ -n "$extra" ]]; then
    echo "unexpected files in vendor directory: $extra" >&2
    exit 1
  fi
  echo "vendored slhdsa-c matches README hashes"
  exit 0
fi

COMMIT="${1:?usage: $0 <commit>|--check}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
git clone --quiet https://github.com/pq-code-package/slhdsa-c.git "$WORK/slhdsa-c"
git -C "$WORK/slhdsa-c" checkout --quiet "$COMMIT"
rm -rf "$DST"
mkdir -p "$DST"
for f in "${FILES[@]}"; do
  cp "$WORK/slhdsa-c/$f" "$DST/$f"
done
(cd "$DST" && sha256sum "${FILES[@]}")
echo "vendored slhdsa-c @ $COMMIT; update the commit and sums in $README"
