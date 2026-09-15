#!/usr/bin/env bash
#
# scripts/lib/stage-release.sh
#
# Shared staging logic for BOTH build-release.sh (official/CI) and
# build-release-local.sh (local dev build). This is the single source of
# truth for "what gets excluded from the release ZIP" on the shell side,
# so the two build paths can never silently drift apart again.
#
# It reads exclusion / re-inclusion rules straight from
# woocommerce-chargeguard/.distignore — the same file build.ps1 uses on
# Windows — and then runs the same forbidden-file safety net build.ps1
# runs, so a mistake in .distignore is caught here too, not only on
# Windows.
#
# Portability note: uses only `cp` and `find`, not `rsync`, so it works
# the same way in Git Bash, WSL, and CI without an extra dependency.
#
# Usage: source this file, then call:
#   stage_release "<plugin_source_dir>" "<staging_dir>"

# Hard-coded safety net — mirrors build.ps1's $ForbiddenPatterns exactly.
# Kept here (not *only* in .distignore) on purpose: if .distignore is ever
# edited incorrectly, or a future file matches a pattern .distignore
# doesn't reach, the build must fail loudly rather than silently ship it.
# Do not remove entries just because they currently match nothing in the
# repo — that's the same reasoning as the CA-bundle check below, which
# also has nothing to verify until the day it matters.
FORBIDDEN_PATTERNS=(
    ".git" ".gitignore" ".gitattributes" ".github"
    ".env" "*.env"
    "*.bak" "*.orig" "*.log" "*.tmp"
    ".DS_Store" "Thumbs.db" "desktop.ini"
    "node_modules" ".idea" ".vscode"
    "phpunit.xml" "phpunit.xml.dist"
    "composer.lock"
    ".distignore" "build.ps1" "build.sh" "build-release.sh" "build-release-local.sh"
    "_deferred.*" "*.txt.js"
    "dev-notes"
)

stage_release() {
    local source_dir="$1"
    local staging_dir="$2"
    local distignore="${source_dir}/.distignore"

    if [ ! -f "$distignore" ]; then
        echo "Error: .distignore not found at ${distignore}" >&2
        return 1
    fi

    echo "==> Copying plugin source to staging: ${staging_dir}"
    rm -rf "$staging_dir"
    mkdir -p "$staging_dir"
    cp -r "${source_dir}/." "${staging_dir}/"

    echo "==> Applying .distignore exclusions"
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        [[ "$line" == !* ]] && continue  # re-includes are handled in the next pass

        find "$staging_dir" -name "$line" -exec rm -rf {} + 2>/dev/null || true
    done < "$distignore"

    echo "==> Restoring explicitly re-included paths"
    local restored_any=0
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [ -z "$line" ] && continue
        case "$line" in \#*) continue ;; esac
        [[ "$line" != !* ]] && continue

        local rel_path="${line#!}"
        local src="${source_dir}/${rel_path}"
        local dst="${staging_dir}/${rel_path}"

        if [ ! -e "$src" ]; then
            echo "  (skip) re-include path not found in source: ${rel_path}"
            continue
        fi

        mkdir -p "$(dirname "$dst")"
        rm -rf "$dst"
        cp -r "$src" "$dst"
        echo "  restored: ${rel_path}"
        restored_any=1
    done < "$distignore"
    [ "$restored_any" -eq 0 ] && echo "  (none)"

    echo "==> Verifying Stripe CA bundle is present"
    local ca_bundle="${staging_dir}/vendor/stripe/stripe-php/data/ca-certificates.crt"
    if [ ! -f "$ca_bundle" ]; then
        echo "Error: vendor/stripe/stripe-php/data/ca-certificates.crt is missing from staged output." >&2
        echo "Stripe HTTPS calls would fail at runtime. Check .distignore for an over-broad data exclusion." >&2
        return 1
    fi

    echo "==> Scanning staged output for forbidden files"
    local violations=()
    for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
        while IFS= read -r -d '' found; do
            violations+=("${found#"$staging_dir"/}")
        done < <(find "$staging_dir" -name "$pattern" -print0 2>/dev/null)
    done

    if [ "${#violations[@]}" -gt 0 ]; then
        echo "Forbidden files found in staged output:" >&2
        for v in "${violations[@]}"; do
            echo "  - $v" >&2
        done
        echo "Build aborted -- forbidden files present. Fix .distignore or remove these from source." >&2
        return 1
    fi

    echo "==> Removing Stripe SDK documentation files"
    local stripe_root="${staging_dir}/vendor/stripe/stripe-php"
    if [ -d "$stripe_root" ]; then
        for f in CHANGELOG.md README.md composer.json LICENSE OPENAPI_VERSION VERSION phpunit.xml.dist; do
            rm -f "${stripe_root}/${f}"
        done
    fi

    echo "==> Staging complete: ${staging_dir}"
}