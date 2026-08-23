#!/usr/bin/env bash
#
# Install the Tauri Linux build dependencies, with a bound on how long apt is
# allowed to sulk.
#
# The GitHub runner images put azure.archive.ubuntu.com first in their apt
# sources. When that host stops answering, apt has no timeout of its own for the
# Packages fetch, so it blocks forever rather than failing over to the mirror
# after it. Falling back works for InRelease and then does not work for
# Packages, so this is not something a retry of the whole step fixes.
#
# Two defences, because either alone is a guess about which layer breaks:
#   1. Repoint every apt source away from the Azure mirror onto
#      archive.ubuntu.com, which is what apt had already failed over to on its
#      own.
#   2. Give apt real timeouts and retries, so a stall anywhere fails the step in
#      minutes instead of blocking it for hours.
#
# The rewrite walks every source file rather than assuming /etc/apt/apt-mirrors.txt
# exists. That indirection is an implementation detail of the runner image — on
# ubuntu-22.04 sources.list currently resolves through the mirrorlist, but that
# can move, and a sed against a path that stopped existing would silently do
# nothing and leave the hang in place.
#
# Usage: install-linux-deps.sh <package>...

set -euo pipefail

[ "$#" -gt 0 ] || {
  printf '::error::install-linux-deps: at least one package name is required.\n' >&2
  exit 1
}

rewrote=0
for f in /etc/apt/apt-mirrors.txt /etc/apt/sources.list \
  /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [ -f "$f" ] || continue
  grep -q 'azure\.archive\.ubuntu\.com' "$f" || continue
  sudo sed -i 's|azure\.archive\.ubuntu\.com|archive.ubuntu.com|g' "$f"
  printf 'Repointed the Azure mirror to archive.ubuntu.com in %s\n' "$f"
  rewrote=1
done

# Not an error. A future image may simply not use that mirror, in which case the
# apt timeouts below are the whole defence and the step should still run.
[ "$rewrote" -eq 1 ] || printf 'No apt source referenced azure.archive.ubuntu.com; nothing to repoint.\n'

sudo tee /etc/apt/apt.conf.d/99-ci-timeouts >/dev/null <<'CONF'
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::Retries "3";
CONF

sudo apt-get update
sudo apt-get install -y "$@"
