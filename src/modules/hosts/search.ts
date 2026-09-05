import { hasWordBoundaryMatch } from "@/lib/searchTiers";
import type { VaultIdentity } from "@/modules/vault/types";

import type { Host, HostGroup } from "./types";

// One ranking function, two mount points: the Hosts page search box and the
// header quick-connect both filter the same saved-host
// list and MUST agree on what the top match is - a user who sees one answer in
// the header and a different one on the page for the identical query has no
// way to tell which is "right". Building this once in `modules/hosts` and
// having both callers import it is what makes that impossible instead of
// merely unlikely.
//
// The ROW BUILDER lives here for the same reason, and it has to: sharing only
// `rankHosts` while each mount point assembled its own rows is what let them
// diverge once already. The header resolved a username inline and the page
// resolved it through the vault, so a host bound to an identity whose username
// is "deploy" matched on the page, matched nothing in the header, and the header
// then offered to CREATE it as a new host - a duplicate of a row the page could
// see. A shared helper is not enough when the assembly is what differs; the
// assembly itself has to be the shared thing. See `searchRows` below.
//
// This module is pure: no store read, no React, no Tauri. It resolves a vault
// binding when handed the identity map, which is a lookup over plain data, not a
// vault operation - `useVault()` gives both callers that map synchronously.

/** One searchable row: a host plus the two fields {@link matchTier} cannot work
 *  out from the host alone, because a vault-bound host's username lives on its
 *  identity and a group's name lives on the group. Build these with
 *  {@link searchRows}, never by hand. */
export type HostSearchRow = { host: Host; username?: string; groupName?: string };

/**
 * Just the map {@link searchRows} reads.
 *
 * Narrower than the Hosts page's full vault snapshot on purpose - resolving a
 * username is the only thing this module does with the vault, and asking for
 * `keys` as well would be claiming an interest it does not have. A full snapshot
 * is assignable to it, so a caller holding one passes it straight in.
 */
export type IdentityLookup = { identities: ReadonlyMap<string, VaultIdentity> };

/**
 * The strongest tier `row` qualifies for against a lowercased, non-empty
 * `query`, or `null` when it matches none. Checked strongest-first and returns
 * on the first hit, so a row that would satisfy several tiers is ranked by the
 * best one rather than summed across them.
 */
function matchTier(row: HostSearchRow, query: string): number | null {
  const name = row.host.name.toLowerCase();
  const host = row.host.host.toLowerCase();
  const username = row.username?.toLowerCase();
  const groupName = row.groupName?.toLowerCase();

  if (name === query) return 1;
  if (name.startsWith(query)) return 2;
  if (host.startsWith(query)) return 3;
  if (hasWordBoundaryMatch(name, query) || hasWordBoundaryMatch(host, query)) return 4;
  if (
    name.includes(query) ||
    host.includes(query) ||
    (username !== undefined && username.includes(query)) ||
    (groupName !== undefined && groupName.includes(query))
  ) {
    return 5;
  }
  return null;
}

/**
 * The shared tail of the ordering, used both to break ties between rows in
 * the same tier and, for an empty query, as the entire comparator - the same
 * order, from one comparator, not two: `lastConnectedAt` descending (absent
 * sorts last), then `name` case-insensitively, then `id`.
 *
 * The `id` tie-break is what makes the order total. Without it, two rows equal
 * on every other field would keep whatever relative order the input happened
 * to have, so the page and the header - fed the same rows in different
 * iteration order - could disagree on which one shows first.
 */
function compareRows(a: HostSearchRow, b: HostSearchRow): number {
  const at = a.host.lastConnectedAt;
  const bt = b.host.lastConnectedAt;
  if (at !== bt) {
    if (at === undefined) return 1;
    if (bt === undefined) return -1;
    return bt - at;
  }
  const byName = a.host.name.toLowerCase().localeCompare(b.host.name.toLowerCase());
  if (byName !== 0) return byName;
  return a.host.id.localeCompare(b.host.id);
}

/** Filter and rank, case-insensitively, over name, host, username and group name.
 *  An empty or whitespace-only query returns every row in its default order. */
export function rankHosts(rows: HostSearchRow[], query: string): HostSearchRow[] {
  const trimmed = query.trim().toLowerCase();
  if (trimmed.length === 0) {
    return [...rows].sort(compareRows);
  }

  const matched: Array<{ row: HostSearchRow; tier: number }> = [];
  for (const row of rows) {
    const tier = matchTier(row, trimmed);
    // Dropped, not sorted to the bottom: a non-match has no place in a ranked
    // list of results, and keeping it would make "how many hits" a manual
    // scan of the array instead of its length.
    if (tier !== null) matched.push({ row, tier });
  }

  matched.sort((a, b) => (a.tier !== b.tier ? a.tier - b.tier : compareRows(a.row, b.row)));
  return matched.map((m) => m.row);
}

/**
 * The username stored ON THE HOST: SSH's `credential.user`, RDP's
 * `credential.username`, `undefined` for a vault-bound binding.
 *
 * Not for building a search row - use {@link hostUsername}, which is this plus
 * the vault half. Feeding a row the inline half alone is exactly the divergence
 * described at the top of this file, and no caller does it any more: this is
 * exported so the three bindings can be pinned on their own, and because
 * `hostUsername` is only readable if the two halves are separate.
 */
export function inlineUsername(host: Host): string | undefined {
  if (host.protocol === "ssh") {
    return host.credential.kind === "inline" ? host.credential.user : undefined;
  }
  return host.credential.kind === "inline" ? host.credential.username : undefined;
}

/** The username a row logs in as, wherever it lives: on the host for an inline
 *  binding, on the identity for a vault one. Search needs both, or a query that
 *  is somebody's username silently stops matching once a host moves into the
 *  vault. `undefined` when the binding dangles - there is no username to report
 *  for an identity the vault does not have. */
export function hostUsername(
  host: Host,
  identities: IdentityLookup["identities"],
): string | undefined {
  const cred = host.credential;
  if (cred.kind === "inline") return inlineUsername(host);
  return identities.get(cred.identityId)?.username;
}

/**
 * Every host as a searchable row - THE row builder, for every mount point.
 *
 * Both surfaces call this rather than mapping the host list themselves, which is
 * the fix for the divergence at the top of this file. The two hand-written loops
 * it replaced disagreed on more than the username, too: one treated `groupId` as
 * falsy-or-set and the other as `undefined`-or-set, so an empty-string group id
 * resolved differently in each. One builder means a new searchable field, or a
 * new opinion about a blank id, lands on both surfaces or neither.
 */
export function searchRows(
  hosts: readonly Host[],
  groups: readonly HostGroup[],
  vault: IdentityLookup,
): HostSearchRow[] {
  const groupNames = new Map(groups.map((g) => [g.id, g.name]));
  return hosts.map((host) => ({
    host,
    username: hostUsername(host, vault.identities),
    groupName: host.groupId === undefined ? undefined : groupNames.get(host.groupId),
  }));
}

/** A quick-connect string that matches no saved host but parses as
 *  `user@host[:port]` opens the host editor prefilled. Returns null when it does
 *  not parse. */
export function parseAdHocTarget(
  query: string,
): { user?: string; host: string; port?: number } | null {
  const trimmed = query.trim();
  if (trimmed.length === 0 || /\s/.test(trimmed)) return null;

  // IPv6 needs the `[addr]:port` bracket convention to disambiguate the
  // address's own colons from the port separator. Parsing that correctly is
  // out of scope here, so a bracketed literal is refused rather than mangled
  // into a host string that silently drops the brackets or misreads the port.
  if (trimmed.includes("[") || trimmed.includes("]")) return null;

  const atCount = (trimmed.match(/@/g) ?? []).length;
  if (atCount > 1) return null;

  let user: string | undefined;
  let rest = trimmed;
  if (atCount === 1) {
    const atIndex = trimmed.indexOf("@");
    user = trimmed.slice(0, atIndex);
    rest = trimmed.slice(atIndex + 1);
    if (user.length === 0) return null; // "@host" names no one
  }

  // More than one colon is ambiguous without the bracket syntax above (and an
  // unbracketed IPv6 literal is exactly what produces this), so it is refused
  // for the same reason, not mangled by guessing which colon is the port.
  const colonCount = (rest.match(/:/g) ?? []).length;
  if (colonCount > 1) return null;

  let host = rest;
  let port: number | undefined;
  if (colonCount === 1) {
    const colonIndex = rest.indexOf(":");
    host = rest.slice(0, colonIndex);
    const portText = rest.slice(colonIndex + 1);
    if (!/^[0-9]+$/.test(portText)) return null;
    const parsedPort = Number(portText);
    if (parsedPort < 1 || parsedPort > 65535) return null;
    port = parsedPort;
  }
  if (host.length === 0) return null;

  // Built with `user` and `port` always assigned (possibly `undefined`) rather
  // than conditionally, so the key order is fixed: a caller that JSON-compares
  // the result does not have to know whether this took the with-user or the
  // no-port branch to get a stable shape.
  return { user, host, port };
}
