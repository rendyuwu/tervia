#!/bin/sh
# Post-install maintainer script for the deb / rpm packages. Creates a
# `/usr/bin/tervia` symlink to the GUI binary so users can run `tervia` from any
# shell. Without this, `apt install tervia_*.deb` only exposes the binary as
# its renamed-via-mainBinaryName form (`TerviaApp`) — which is correct for the
# .desktop entry but surprises terminal users who expect lowercase `tervia`.
#
# The Windows installer (NSIS) ships a separate console-subsystem launcher
# at `tervia.exe`; on Linux the GUI binary inherits stdio natively from the
# spawning shell, so a simple symlink does the job.
#
# `dpkg` / `rpm` set $1 to "configure" (deb) or a numeric argument (rpm) on
# install / upgrade; either way we just want the link to exist. `ln -sf`
# silently replaces a stale link from a prior install — never errors and
# never accumulates stale entries.

set -e

if [ -x /usr/bin/TerviaApp ]; then
  ln -sf TerviaApp /usr/bin/tervia
fi

# Register the "Open With > Tervia" association. The MimeType line in
# `tervia.desktop` (inode/directory + text/plain) is inert until the desktop
# database is rebuilt, so a fresh install would ship the entry without file
# managers ever offering it. Best-effort: the tool lives in desktop-file-utils,
# which a headless/server install may not have, and a missing association is a
# smaller problem than a package that refuses to install.
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
fi

exit 0
