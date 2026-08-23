#!/bin/sh
# Pre-remove maintainer script for the deb / rpm packages. Drops the
# `/usr/bin/tervia` symlink that the post-install script created. Symlink
# removal is unconditional and idempotent — `rm -f` never errors if it's
# already gone (e.g., user manually deleted it, or this script runs again
# during reinstall).
#
# Only remove the symlink if it actually points to TerviaApp; never touch a
# user-authored `/usr/bin/tervia` that happens to share the name.

set -e

if [ -L /usr/bin/tervia ] && [ "$(readlink /usr/bin/tervia)" = "TerviaApp" ]; then
  rm -f /usr/bin/tervia
fi

# No update-desktop-database call here: this runs BEFORE the .desktop file is
# removed, so rebuilding the cache would just re-register the entry. Both
# dpkg and rpm ship a desktop-file-utils trigger on /usr/share/applications
# that rebuilds it after the removal lands.

exit 0
