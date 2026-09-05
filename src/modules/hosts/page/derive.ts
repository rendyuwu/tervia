import { identityMissingSecret } from "@/modules/vault/refs";
import type {
  RdpInlineCredentials,
  SshInlineCredentials,
  VaultIdentity,
  VaultKey,
} from "@/modules/vault/types";

import { rankHosts, type HostSearchRow } from "../search";
import { isSshHost, type Host, type HostGroup } from "../types";

// Everything the Hosts page derives from its three inputs - the host list, the
// group list and a snapshot of the vault - as PURE FUNCTIONS over plain data.
//
// No React and no store access, which is the whole reason
// `scripts/hosts-page-verify.ts` can exist: the correctness in this file (which
// pip a row shows, which rows a filter keeps, what the group counts add up to)
// is the part worth checking, and it is checkable only while it is separable
// from the rendering.
//
// Nothing here reads a secret. Every "is a credential missing?" answer comes off
// the `has*` flags already on the record, which is what they are FOR: a page
// rendering a hundred rows must not issue three keychain reads per row, and the
// flags are maintained on write. A pip computed from a read-back
// would also be wrong more often, not less - it would report "fine" for a
// keychain that happens to be unlocked and "missing" for one that is not.
//
// Two of the page's derived values are NOT defined here. `hostUsername` and
// `searchRows` live in `../search`, next to `rankHosts`, because the header
// quick-connect needs the same two and reaching into `hosts/page/` from
// `modules/header/` would be worse - and because building rows twice is what let
// the two surfaces disagree about which hosts a query matches. They are
// re-exported so this file stays the single import site for everything the page
// derives; there is exactly one definition of each, in `../search`.
export { hostUsername, searchRows } from "../search";

/**
 * The vault as two maps, read synchronously.
 *
 * Named apart from `resolve.ts`'s `VaultLookup` on purpose: that one is the
 * async find-by-id pair the CONNECT path uses, this one is a snapshot a render
 * pass reads once per visible row without an await. Declared here rather than
 * imported from `modules/vault/useVault.ts` so this module stays React-free; the
 * two shapes are structurally identical, so the hook's result passes straight
 * in.
 */
export type VaultSnapshot = {
  identities: ReadonlyMap<string, VaultIdentity>;
  keys: ReadonlyMap<string, VaultKey>;
};

/**
 * What {@link identityName} reports for a binding naming an identity the vault
 * does not have.
 *
 * A named label rather than `undefined`, because `undefined` is already how this
 * function says "inline" - so a dangling reference would render as a host that
 * owns its own credential, which is the one thing it definitely is not.
 * {@link missingSecret} independently flags the same row, so the two agree.
 */
export const UNKNOWN_IDENTITY_LABEL = "Unknown identity";

export type GroupCounts = { total: number; ungrouped: number; byGroup: Record<string, number> };

export type ProtocolFilter = "all" | "ssh" | "rdp";

/** `"ungrouped"` is not a group id, so it gets its own arm rather than a magic
 *  string in `groupId`. */
export type GroupFilter =
  { kind: "all" } | { kind: "ungrouped" } | { kind: "group"; groupId: string };

/**
 * Does an SSH host's own credential name a secret the record says is absent?
 *
 * The `never` default is the same guarantee `resolve.ts` gives itself: a fourth
 * auth mode stops this compiling until it is handled, rather than falling off the
 * end and quietly reporting "nothing missing".
 */
function sshInlineMissing(cred: SshInlineCredentials): boolean {
  switch (cred.authMode) {
    case "agent":
      // Never missing, and not a shortcut: the local ssh-agent holds the key and
      // signs the handshake, so there is no secret for this record to be missing.
      // A warning pip here would be telling the user to enter something that
      // must not be entered.
      return false;
    case "password":
      return !cred.hasPassword;
    case "key":
      return !cred.hasPrivateKey;
    default: {
      const unhandled: never = cred.authMode;
      throw new Error(`hosts: unhandled auth mode ${String(unhandled)}`);
    }
  }
}

/** RDP asks about the password and nothing else. */
function rdpInlineMissing(cred: RdpInlineCredentials): boolean {
  return !cred.hasPassword;
}

/**
 * The record claims a credential it does not have.
 *
 * Branches on PROTOCOL first and the binding kind second, which is what keeps
 * this cast-free: narrowing `host` re-derives `host.credential` from the arm, so
 * testing the binding first and the protocol second would throw the binding's
 * narrowing away, and on a merged host list a narrowing cast becomes a runtime
 * read of a field that is not there.
 *
 * The RDP identity branch deliberately ignores `authMode`, matching
 * `resolveRdpAuth`: `hasPassword` is independent of the mode, so a key identity
 * holding a password is a legitimate row - it is the "one account, key over SSH
 * and password over RDP" case that sharing an identity exists for.
 */
export function missingSecret(host: Host, vault: VaultSnapshot): boolean {
  if (isSshHost(host)) {
    const cred = host.credential;
    if (cred.kind === "inline") return sshInlineMissing(cred);
    const identity = vault.identities.get(cred.identityId);
    // An id that resolves to nothing is its own missing state. It must not read
    // as fine: the row cannot connect at all, and `resolveSshAuth` throws
    // "identity … no longer exists" the moment it is tried.
    if (!identity) return true;
    return identityMissingSecret(identity, vault.keys);
  }
  const cred = host.credential;
  if (cred.kind === "inline") return rdpInlineMissing(cred);
  const identity = vault.identities.get(cred.identityId);
  if (!identity) return true;
  return !identity.hasPassword;
}

/** The bound identity's name, {@link UNKNOWN_IDENTITY_LABEL} when the binding
 *  dangles, `undefined` for a host that owns its credential. */
export function identityName(
  host: Host,
  identities: VaultSnapshot["identities"],
): string | undefined {
  const cred = host.credential;
  if (cred.kind === "inline") return undefined;
  const identity = identities.get(cred.identityId);
  return identity ? identity.name : UNKNOWN_IDENTITY_LABEL;
}

/**
 * The counts the group strip shows.
 *
 * A host whose `groupId` names a group that is not in `groups` counts as
 * UNGROUPED, and that is the case worth stating: it happens whenever a group is
 * deleted in another window between two renders here, and it is the difference
 * between the chips adding up and quietly not. The invariant is
 * `total === ungrouped + sum(byGroup)` - without the fallback a dangling row
 * lands in neither, so the chips sum to less than All and the row itself is
 * reachable from no chip at all.
 *
 * {@link matchesGroupFilter} makes the same call, so the count on a chip is
 * always the number of cards clicking it shows.
 */
export function groupCounts(hosts: readonly Host[], groups: readonly HostGroup[]): GroupCounts {
  const known = new Set(groups.map((g) => g.id));
  const byGroup: Record<string, number> = {};
  // Seeded so an empty group renders its own 0 rather than relying on a caller's
  // fallback for a key that was never written.
  for (const group of groups) byGroup[group.id] = 0;

  let ungrouped = 0;
  for (const host of hosts) {
    if (host.groupId !== undefined && known.has(host.groupId)) byGroup[host.groupId] += 1;
    else ungrouped += 1;
  }
  return { total: hosts.length, ungrouped, byGroup };
}

export function matchesGroupFilter(
  host: Host,
  filter: GroupFilter,
  knownGroupIds: ReadonlySet<string>,
): boolean {
  switch (filter.kind) {
    case "all":
      return true;
    case "ungrouped":
      return host.groupId === undefined || !knownGroupIds.has(host.groupId);
    case "group":
      return host.groupId === filter.groupId;
    default: {
      const unhandled: never = filter;
      throw new Error(`hosts: unhandled group filter ${JSON.stringify(unhandled)}`);
    }
  }
}

export type HostsViewInput = {
  rows: readonly HostSearchRow[];
  protocol: ProtocolFilter;
  group: GroupFilter;
  /** The ids in the CURRENT group list. Passed in rather than derived from the
   *  rows so {@link matchesGroupFilter} can tell "ungrouped" from "names a group
   *  that is gone" - the rows themselves cannot say which. */
  knownGroupIds: ReadonlySet<string>;
  query: string;
};

/**
 * The rows a render should draw: protocol, then group, then ranking.
 *
 * Ranking LAST is deliberate, but be precise about what it buys, because no
 * output today can tell the two orders apart: a predicate and a stable TOTAL
 * sort commute, so filtering a ranked list is order-identical to ranking a
 * filtered one, and `rankHosts` returns rows rather than tiers so the tiers
 * never reach a caller either. `scripts/hosts-page-verify.ts` says the same
 * thing where it checks this.
 *
 * What the order buys is that it stays correct when the output stops being the
 * whole list. The moment anything takes a top-N slice - a "best match" row, a
 * capped dropdown - rank-then-filter slices before the filters run and can hand
 * back fewer rows than N, or none, while matching rows sit below the cut. That
 * is the regression this order is proof against, and it is cheaper to write it
 * this way now than to notice later.
 */
export function filterAndRank(input: HostsViewInput): HostSearchRow[] {
  const byProtocol = input.rows.filter(
    (row) => input.protocol === "all" || row.host.protocol === input.protocol,
  );
  const byGroup = byProtocol.filter((row) =>
    matchesGroupFilter(row.host, input.group, input.knownGroupIds),
  );
  return rankHosts(byGroup, input.query);
}
