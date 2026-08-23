#!/usr/bin/env bash
#
# Post-build smoke check: assert that `tauri build` actually emitted every
# installer this platform is configured to produce. A Tauri build can succeed
# while silently skipping a bundle target (missing tool, unsupported target
# triple), and an artifact set that is missing the one installer the reviewer
# wanted to smoke-test is worse than a red build.
#
# The expected sets below mirror the `bundle.targets` in the tauri configs:
#   tauri.linux.conf.json    -> deb, rpm, appimage
#   tauri.windows.conf.json  -> nsis only (deliberately no MSI)
#   tauri.conf.json          -> "all", which on macOS means app + dmg
# Keep them in sync when a target is added or dropped.
#
# Usage: verify-bundles.sh <bundle-root> <matrix-id>
#   bundle-root  e.g. src-tauri/target/release/bundle
#   matrix-id    linux-x64 | windows-x64 | macos-x64 | macos-arm64

set -euo pipefail

root="${1:?verify-bundles: bundle root argument is required}"
id="${2:?verify-bundles: matrix id argument is required}"

die() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

[ -d "$root" ] || die "verify-bundles: bundle root '$root' does not exist — tauri build produced nothing."

# "<human label>|<find -name pattern>"
case "$id" in
  linux-*)
    # The AppImage is also the updater target on Linux, so its .sig is checked
    # separately below: a missing signature means the updater artifacts were not
    # produced even though the installer was.
    expected=("AppImage|*.AppImage" "AppImage signature|*.AppImage.sig" \
      "Debian package|*.deb" "RPM package|*.rpm")
    ;;
  windows-*)
    expected=("NSIS installer|*-setup.exe" "NSIS signature|*-setup.exe.sig")
    ;;
  macos-*)
    # .app is a directory, not a file, so these checks deliberately do not
    # constrain -type. The .app.tar.gz is the updater artifact.
    expected=("disk image|*.dmg" "app bundle|*.app" \
      "updater tarball|*.app.tar.gz" "updater signature|*.app.tar.gz.sig")
    ;;
  *)
    die "verify-bundles: unknown matrix id '$id'."
    ;;
esac

missing=0
for entry in "${expected[@]}"; do
  label="${entry%%|*}"
  pattern="${entry#*|}"
  found="$(find "$root" -name "$pattern" 2>/dev/null || true)"
  if [ -z "$found" ]; then
    printf '::error::Missing %s for %s — no %s under %s\n' "$label" "$id" "$pattern" "$root" >&2
    missing=1
  else
    while IFS= read -r path; do
      printf 'ok  %-18s %s\n' "$label" "$path"
    done <<<"$found"
  fi
done

if [ "$missing" -ne 0 ]; then
  printf '\nContents of %s:\n' "$root" >&2
  find "$root" -maxdepth 2 >&2 || true
  die "verify-bundles: one or more expected bundles were not produced for $id."
fi

printf 'All expected bundles present for %s.\n' "$id"
