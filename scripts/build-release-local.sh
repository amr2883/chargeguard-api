#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# build-release-local.sh
# Local variant of scripts/build-release.sh -- skips composer (vendor/ is
# already committed to git) and skips zip/unzip (compression happens
# afterwards via PowerShell). Staging/exclusion logic is now shared with
# build-release.sh via scripts/lib/stage-release.sh, so this can no
# longer drift out of sync with what actually gets excluded.
#
# Usage: ./scripts/build-release-local.sh <version>
# Example: ./scripts/build-release-local.sh 1.0.1
# ============================================================

if [ $# -lt 1 ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.0.1"
  exit 1
fi

VERSION="$1"
PLUGIN_DIR="woocommerce-chargeguard"
BUILD_DIR="build"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/stage-release.sh
source "${SCRIPT_DIR}/lib/stage-release.sh"

if [ ! -d "$PLUGIN_DIR" ]; then
  echo "Error: ${PLUGIN_DIR} directory not found. Run this from the repo root."
  exit 1
fi

echo "==> [1/3] Checking git status (warning only -- does not block the build)"
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  DIRTY=$(git status --porcelain -- "$PLUGIN_DIR" | grep -v "chargeguard-woocommerce.php" || true)
  if [ -n "$DIRTY" ]; then
    echo "Warning: uncommitted changes inside ${PLUGIN_DIR} (besides the version bump):"
    echo "$DIRTY"
    echo "The ZIP will be built from what's on disk (working tree), not HEAD."
  else
    echo "Clean (or the only change is the expected version bump)."
  fi
else
  echo "Warning: could not check git status -- continuing without it."
fi

echo "==> [2/3] Bumping version to ${VERSION} in ${PLUGIN_DIR}/chargeguard-woocommerce.php"
MAIN_FILE="${PLUGIN_DIR}/chargeguard-woocommerce.php"
if [ ! -f "$MAIN_FILE" ]; then
  echo "Error: main file ${MAIN_FILE} not found."
  exit 1
fi
sed -i.bak -E "s/^(\s*\*\s*Version:\s*)[0-9A-Za-z.\-]+/\1${VERSION}/" "$MAIN_FILE"
rm -f "${MAIN_FILE}.bak"
if ! grep -q "Version:.*${VERSION}" "$MAIN_FILE"; then
  echo "Error: version bump failed -- check the sed pattern against the actual header line."
  exit 1
fi
echo "Version confirmed: ${VERSION}"

echo "==> [3/3] Verifying vendor/ is complete (substitute for composer install)"
REQUIRED_VENDOR_FILES=(
  "vendor/autoload.php"
  "vendor/stripe/stripe-php/init.php"
  "vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php"
)
for f in "${REQUIRED_VENDOR_FILES[@]}"; do
  if [ ! -f "${PLUGIN_DIR}/${f}" ]; then
    echo "Error: missing vendor file: ${PLUGIN_DIR}/${f}"
    echo "vendor/ is incomplete -- needs to be fixed before building."
    exit 1
  fi
done
echo "All required vendor/ files are present."

# .distignore-driven staging + forbidden-file safety net -- the same
# check build-release.sh and build.ps1 run.
stage_release "$PLUGIN_DIR" "${BUILD_DIR}/${PLUGIN_DIR}"

echo ""
echo "==> Staging complete. Folder ready at: ${BUILD_DIR}/${PLUGIN_DIR}"
echo "    Zip it yourself (e.g. via PowerShell Compress-Archive) when ready."