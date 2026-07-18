#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/build-release.sh <version> [channel]
# Example: scripts/build-release.sh 1.2.0 stable

if [ $# -lt 1 ]; then
  echo "Usage: $0 <version> [channel]"
  echo "Example: $0 1.2.0 stable"
  exit 1
fi

VERSION=$1
CHANNEL=${2:-stable}
PLUGIN_DIR="woocommerce-chargeguard"
BUILD_DIR="build"
ZIP_NAME="chargeguard-woocommerce-${VERSION}.zip"

if [ ! -d "$PLUGIN_DIR" ]; then
  echo "Error: ${PLUGIN_DIR} directory not found. Run this from the repo root."
  exit 1
fi

echo "==> Bumping version to ${VERSION} in ${PLUGIN_DIR}/chargeguard-woocommerce.php"
# Matches the exact header line: "Version:     1.0.0" (any amount of
# whitespace after the colon, since the existing file uses aligned spacing).
sed -i.bak -E "s/^(\s*\*\s*Version:\s*)[0-9A-Za-z.\-]+/\1${VERSION}/" "${PLUGIN_DIR}/chargeguard-woocommerce.php"
rm -f "${PLUGIN_DIR}/chargeguard-woocommerce.php.bak"

echo "==> Verifying version bump"
if ! grep -q "Version:.*${VERSION}" "${PLUGIN_DIR}/chargeguard-woocommerce.php"; then
  echo "Error: version bump failed — check the sed pattern against the actual header line."
  exit 1
fi

echo "==> Installing production Composer dependencies (no dev deps in the shipped ZIP)"
(cd "$PLUGIN_DIR" && composer install --no-dev --optimize-autoloader)

echo "==> Packaging"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/woocommerce-chargeguard"
rsync -a \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='.DS_Store' \
  "$PLUGIN_DIR/" "$BUILD_DIR/woocommerce-chargeguard/"

(cd "$BUILD_DIR" && zip -r -X "../${ZIP_NAME}" woocommerce-chargeguard >/dev/null)

echo "==> Computing checksum"
CHECKSUM=$(shasum -a 256 "${ZIP_NAME}" | awk '{print $1}')

echo ""
echo "Build complete:"
echo "  File:     ${ZIP_NAME}"
echo "  SHA-256:  ${CHECKSUM}"
echo "  Channel:  ${CHANNEL}"
echo ""
echo "Next steps:"
echo "  1. aws s3 cp ${ZIP_NAME} s3://\$RELEASES_S3_BUCKET/releases/${ZIP_NAME}"
echo "  2. node scripts/publish-release.js ${VERSION} ${CHANNEL} ${CHECKSUM} releases/${ZIP_NAME}"