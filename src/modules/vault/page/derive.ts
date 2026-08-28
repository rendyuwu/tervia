import { hasWordBoundaryMatch } from "@/lib/searchTiers";
import type { Host } from "@/modules/hosts/types";

import { hostsUsingIdentity, identitiesUsingKey, identityMissingSecret } from "../refs";
import type { VaultIdentity, VaultKey } from "../types";

// Everything the Vault page derives from its three inputs - the identity list,
// the key list and the host list - as PURE FUNCTIONS over plain data.
//
// No React and no store access, which is the whole reason
// `scripts/vault-page-verify.ts` can exist: mirrors `modules/hosts/page/derive.ts`
// in shape and purpose. That file's `sshIdentityMissing`, and the ranking it built
// on top of `../search`, are the precedent this one follows for the vault's own
// two record types.
//
// The Vault page does not reuse `rankHosts`: that comparator is typed to
// `HostSearchRow`, and its tier 3 is `host.startsWith(query)` - a `Host` field
// neither a `VaultIdentity` nor a `VaultKey` has. Generalising it would mean
// refactoring a function two hand-tested surfaces (the Hosts page, the header
// quick-connect) depend on, for no behavioural gain. So: two comparators here,
// mirroring `rankHosts`' five-tier shape field-for-field, sharing only the
// word-boundary primitive in `@/lib/searchTiers` so the three cannot drift on
// what counts as a word boundary.
//
// `hostsUsingIdentity`, `identitiesUsingKey` and `identityMissingSecret` are NOT
// defined here. They live in `../refs`, because the delete guard that refuses to
// remove an identity or key a record still references needs the exact same
// answer this page shows, and building it twice is what let the Hosts page and
// the header quick-connect disagree about which hosts a query matched. They are
// re-exported so this file stays the single import site for everything the page
// derives; there is exactly one definition of each, in `../refs`.
export { hostsUsingIdentity, identitiesUsingKey, identityMissingSecret } from "../refs";

/** What {@link identityRows} reports for a `keyId` naming a key the vault does
 *  not have. A named label rather than `undefined`, because `undefined` already
 *  means "names no key at all" - so a dangling reference would render as an
 *  identity using a password, which is the one thing it is not. */
export const UNKNOWN_KEY_LABEL = "Unknown key";

export type IdentityRow = {
  identity: VaultIdentity;
  /** The bound key's NAME, {@link UNKNOWN_KEY_LABEL} when `keyId` names a key the
   *  vault does not have, `undefined` when the identity names no key at all. A
   *  named label rather than `undefined` for the dangling case, because
   *  `undefined` already means "names no key" - so a dangling reference would
   *  render as an identity that uses a password, which is the one thing it is not. */
  keyName?: string;
  /** How many hosts bind to this identity. A COUNT, not the array: a zustand v5
   *  selector that builds a fresh array re-subscribes forever and throws "Maximum
   *  update depth exceeded", and a count is a primitive. The array is available
   *  from `hostsUsingIdentity` for the delete refusal, which needs the names. */
  hostCount: number;
  missingSecret: boolean;
};

export type KeyRow = {
  key: VaultKey;
  /** How many identities name this key. Same reasoning as `hostCount`. */
  identityCount: number;
};

/**
 * One row per identity, everything the page shows precomputed.
 *
 * THE row builder, for every mount point that will ever list identities -
 * exactly as `searchRows` is the row builder every Hosts page mount point calls.
 * A future picker (wave 4's convert-to-vault, an identity combobox) must call
 * this rather than assembling its own rows: the header quick-connect and the
 * Hosts page both called one ranking function and still disagreed about which
 * hosts a query matched, because each built its own rows in its own loop - one
 * resolved a vault identity's username while the other did not, and the header
 * then offered to CREATE a host the page could already see. A shared pure
 * function guarantees nothing about callers that assemble its arguments
 * separately, so the assembly itself has to be the shared thing.
 */
export function identityRows(
  identities: readonly VaultIdentity[],
  keys: ReadonlyMap<string, VaultKey>,
  hosts: readonly Host[],
): IdentityRow[] {
  return identities.map((identity) => {
    let keyName: string | undefined;
    if (identity.keyId) {
      const key = keys.get(identity.keyId);
      keyName = key ? key.name : UNKNOWN_KEY_LABEL;
    }
    return {
      identity,
      keyName,
      hostCount: hostsUsingIdentity(hosts, identity.id).length,
      missingSecret: identityMissingSecret(identity, keys),
    };
  });
}

/** One row per key, everything the page shows precomputed. Same reasoning as
 *  {@link identityRows}. */
export function keyRows(keys: readonly VaultKey[], identities: readonly VaultIdentity[]): KeyRow[] {
  return keys.map((key) => ({
    key,
    identityCount: identitiesUsingKey(identities, key.id).length,
  }));
}

/**
 * The shared tail of the ordering for both row types: `name` case-insensitively,
 * then `id`.
 *
 * Vault records have no `lastConnectedAt` - there is no recency term here, unlike
 * `compareRows` in `modules/hosts/search.ts`, and its absence is a deliberate
 * difference rather than an oversight.
 *
 * The `id` tie-break is what makes the order TOTAL. Without it, two rows equal on
 * name would keep whatever relative order the input happened to have, so two
 * surfaces fed the same records in different iteration order could disagree
 * about which one shows first.
 */
function byNameThenId(aName: string, aId: string, bName: string, bId: string): number {
  const byName = aName.toLowerCase().localeCompare(bName.toLowerCase());
  if (byName !== 0) return byName;
  return aId.localeCompare(bId);
}

function compareIdentityRows(a: IdentityRow, b: IdentityRow): number {
  return byNameThenId(a.identity.name, a.identity.id, b.identity.name, b.identity.id);
}

function compareKeyRows(a: KeyRow, b: KeyRow): number {
  return byNameThenId(a.key.name, a.key.id, b.key.name, b.key.id);
}

/**
 * The strongest tier `row` qualifies for against a lowercased, non-empty
 * `query`, or `null` when it matches none. Checked strongest-first and returns
 * on the first hit, mirroring `rankHosts`' `matchTier` with `host` replaced by
 * `username` - the field that plays the same role for an identity.
 *
 * `keyName` is in tier 5 for the reason the header's missing username
 * resolution was a defect: a user searching for the key they know an identity
 * uses should find it.
 */
function identityMatchTier(row: IdentityRow, query: string): number | null {
  const name = row.identity.name.toLowerCase();
  const username = row.identity.username.toLowerCase();
  const domain = row.identity.domain?.toLowerCase();
  const keyName = row.keyName?.toLowerCase();

  if (name === query) return 1;
  if (name.startsWith(query)) return 2;
  if (username.startsWith(query)) return 3;
  if (hasWordBoundaryMatch(name, query) || hasWordBoundaryMatch(username, query)) return 4;
  if (
    name.includes(query) ||
    username.includes(query) ||
    (domain !== undefined && domain.includes(query)) ||
    (keyName !== undefined && keyName.includes(query))
  ) {
    return 5;
  }
  return null;
}

/**
 * Filter and rank identities, case-insensitively, over name, username, domain
 * and key name. An empty or whitespace-only query returns every row in its
 * default order (name, then id). Rows matching no tier are DROPPED, not sorted
 * to the bottom - a non-match has no place in a ranked list of results, and
 * keeping it would make "how many hits" a manual scan instead of the array's
 * length.
 */
export function rankIdentities(rows: readonly IdentityRow[], query: string): IdentityRow[] {
  const trimmed = query.trim().toLowerCase();
  if (trimmed.length === 0) {
    return [...rows].sort(compareIdentityRows);
  }

  const matched: Array<{ row: IdentityRow; tier: number }> = [];
  for (const row of rows) {
    const tier = identityMatchTier(row, trimmed);
    if (tier !== null) matched.push({ row, tier });
  }

  matched.sort((a, b) => (a.tier !== b.tier ? a.tier - b.tier : compareIdentityRows(a.row, b.row)));
  return matched.map((m) => m.row);
}

/**
 * The strongest tier `row` qualifies for against a lowercased, non-empty
 * `query`, or `null` when it matches none.
 *
 * Everything is lowercased before comparison, including the fingerprint - which
 * is base64 and therefore case-significant, so a lowercased substring test can
 * in principle match a differently-cased string. This is search, not
 * verification: the fingerprint shown next to the row is what a user compares
 * against, and nothing authenticates off a search result.
 *
 * `keyType` (`VaultKeyType`, `src/modules/vault/types.ts:113`) is already a short
 * lowercase token, so a `.includes` on it needs no folding of its own.
 */
function keyMatchTier(row: KeyRow, query: string): number | null {
  const name = row.key.name.toLowerCase();
  const fingerprint = row.key.fingerprint?.toLowerCase();
  const keyType = row.key.keyType;

  if (name === query) return 1;
  if (name.startsWith(query)) return 2;
  if (fingerprint !== undefined) {
    // A leading "sha256:" is the fingerprint's own prefix, folded along with
    // everything else - so a query for the raw digest matches without the
    // caller having to know the prefix is there.
    const afterPrefix = fingerprint.startsWith("sha256:") ? fingerprint.slice(7) : fingerprint;
    if (fingerprint.startsWith(query) || afterPrefix.startsWith(query)) return 3;
  }
  if (hasWordBoundaryMatch(name, query)) return 4;
  if (
    name.includes(query) ||
    (keyType !== undefined && keyType.includes(query)) ||
    (fingerprint !== undefined && fingerprint.includes(query))
  ) {
    return 5;
  }
  return null;
}

/**
 * Filter and rank keys, case-insensitively, over name, fingerprint and key
 * type. Same default-order and drop-non-matches rules as {@link rankIdentities}.
 */
export function rankKeys(rows: readonly KeyRow[], query: string): KeyRow[] {
  const trimmed = query.trim().toLowerCase();
  if (trimmed.length === 0) {
    return [...rows].sort(compareKeyRows);
  }

  const matched: Array<{ row: KeyRow; tier: number }> = [];
  for (const row of rows) {
    const tier = keyMatchTier(row, trimmed);
    if (tier !== null) matched.push({ row, tier });
  }

  matched.sort((a, b) => (a.tier !== b.tier ? a.tier - b.tier : compareKeyRows(a.row, b.row)));
  return matched.map((m) => m.row);
}
