#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# build-release-local.sh
# نسخة محلية من scripts/build-release.sh، معدّلة عشان تشتغل من
# غير composer (vendor/ متسجل بالفعل في git) ومن غير الاعتماد
# على zip/unzip (الضغط والتحقق بيتعملوا بـ PowerShell بعد كده).
#
# الاستخدام: ./scripts/build-release-local.sh <version>
# مثال:      ./scripts/build-release-local.sh 1.0.1
# ============================================================

if [ $# -lt 1 ]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 1.0.1"
  exit 1
fi

VERSION="$1"
PLUGIN_DIR="woocommerce-chargeguard"
BUILD_DIR="build"

USE_RSYNC=1
if ! command -v rsync >/dev/null 2>&1; then
  USE_RSYNC=0
  echo "ملاحظة: rsync مش موجود — هيتم استخدام cp -r كبديل."
fi

if [ ! -d "$PLUGIN_DIR" ]; then
  echo "خطأ: مجلد ${PLUGIN_DIR} مش موجود. شغل السكريبت من جذر الريبو."
  exit 1
fi

echo "==> [1/4] فحص حالة git (تحذير فقط — مش رافض البناء)"
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  DIRTY=$(git status --porcelain -- "$PLUGIN_DIR" | grep -v "chargeguard-woocommerce.php" || true)
  if [ -n "$DIRTY" ]; then
    echo "تحذير: فيه تعديلات غير محفوظة (uncommitted) جوه ${PLUGIN_DIR} غير ملف الإصدار نفسه:"
    echo "$DIRTY"
    echo "الزيب هيتبني من الملفات الموجودة فعليًا على القرص (working tree)، مش من آخر commit."
  else
    echo "الحالة نظيفة (أو التعديل الوحيد هو رقم الإصدار المتوقع)."
  fi
else
  echo "تحذير: مش قادر أتحقق من git status — كمّلت من غير فحص."
fi

echo "==> [2/4] تحديث رقم الإصدار إلى ${VERSION} في ${PLUGIN_DIR}/chargeguard-woocommerce.php"
MAIN_FILE="${PLUGIN_DIR}/chargeguard-woocommerce.php"
if [ ! -f "$MAIN_FILE" ]; then
  echo "خطأ: الملف الرئيسي ${MAIN_FILE} مش موجود."
  exit 1
fi
sed -i.bak -E "s/^(\s*\*\s*Version:\s*)[0-9A-Za-z.\-]+/\1${VERSION}/" "$MAIN_FILE"
rm -f "${MAIN_FILE}.bak"

if ! grep -q "Version:.*${VERSION}" "$MAIN_FILE"; then
  echo "خطأ: فشل تحديث رقم الإصدار — راجع نمط الـ sed مقابل السطر الفعلي في الهيدر."
  exit 1
fi
echo "تم تأكيد رقم الإصدار: ${VERSION}"

echo "==> [3/4] التحقق من اكتمال vendor/ (بديل composer install)"
REQUIRED_VENDOR_FILES=(
  "vendor/autoload.php"
  "vendor/stripe/stripe-php/init.php"
  "vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php"
)
for f in "${REQUIRED_VENDOR_FILES[@]}"; do
  if [ ! -f "${PLUGIN_DIR}/${f}" ]; then
    echo "خطأ: ملف تبعية مفقود: ${PLUGIN_DIR}/${f}"
    echo "الـ vendor/ ناقص — لازم يتصلح قبل البناء."
    exit 1
  fi
done
echo "كل ملفات vendor/ الأساسية موجودة."

echo "==> [4/4] تجهيز مجلد البناء (staging) بالبنية الصحيحة"
rm -rf "$BUILD_DIR"
mkdir -p "${BUILD_DIR}/${PLUGIN_DIR}"

if [ "$USE_RSYNC" -eq 1 ]; then
  rsync -a \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='.DS_Store' \
    --exclude='tests' \
    --exclude='phpunit.xml' \
    "${PLUGIN_DIR}/" "${BUILD_DIR}/${PLUGIN_DIR}/"
else
  cp -r "${PLUGIN_DIR}/." "${BUILD_DIR}/${PLUGIN_DIR}/"
  rm -rf "${BUILD_DIR}/${PLUGIN_DIR}/.git"
  rm -rf "${BUILD_DIR}/${PLUGIN_DIR}/node_modules"
  rm -rf "${BUILD_DIR}/${PLUGIN_DIR}/tests"
  rm -f  "${BUILD_DIR}/${PLUGIN_DIR}/phpunit.xml"
  find "${BUILD_DIR}/${PLUGIN_DIR}" -name ".DS_Store" -delete
fi

echo ""
echo "==> التجهيز خلص. مجلد الـ staging جاهز في: ${BUILD_DIR}/${PLUGIN_DIR}"
echo "كمّل الآن بأوامر PowerShell للضغط والتحقق (Compress-Archive / Expand-Archive)."