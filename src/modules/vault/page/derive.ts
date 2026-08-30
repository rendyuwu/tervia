import { hasWordBoundaryMatch } from "@/lib/searchTiers";
import type { Host } from "@/modules/hosts/types";

import {
  hostsUsingIdentity,
  identitiesUsingKey,
  identityMissingSecret,
  keyMissingSecret,
} from "../refs";
import type { VaultIdentity, VaultKey } from "../types";
import { VaultInUseError } from "../types";

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
export {
  hostsUsingIdentity,
  identitiesUsingKey,
  identityMissingSecret,
  keyMissingSecret,
} from "../refs";

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
  /** `keyId` names a key the vault does not have.
   *
   *  Separate from `keyName` because the label cannot carry this: a dangling
   *  reference renders as {@link UNKNOWN_KEY_LABEL}, and a key the user
   *  actually named "Unknown key" renders identically. Separate from
   *  `missingSecret` because the two are not the same fact - `keyId` is
   *  independent of `authMode` (`src/modules/vault/types.ts:107-108`), so an
   *  identity on `password` auth with a stale `keyId` has a dangling reference
   *  AND a working credential. A renderer must be able to warn about the chip
   *  without calling the row broken. */
  keyDangling: boolean;
  /** How many hosts bind to this identity. A COUNT, not the array: a zustand v5
   *  selector that builds a fresh array re-subscribes forever and throws "Maximum
   *  update depth exceeded", and a count is a primitive. The array is available
   *  from `hostsUsingIdentity` for the delete refusal, which needs the names.
   *
   *  This field being a primitive does NOT make {@link identityRows} itself safe
   *  to call from inside a selector - see that function's own doc. */
  hostCount: number;
  missingSecret: boolean;
};

export type KeyRow = {
  key: VaultKey;
  /** How many identities name this key. Same reasoning as `hostCount`. */
  identityCount: number;
  /** The record claims a private key the keychain does not hold. From the
   *  shared {@link keyMissingSecret}, so this pip and the pip on every identity
   *  row that names this key are one answer rather than two. */
  missingPrivateKey: boolean;
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
 *
 * Returns a FRESH array on every call, the same as any function ending in
 * `.map` does - this is a plain function, not a memoized selector. A caller
 * MUST wrap the call in `useMemo` keyed on its three arguments, and must never
 * call it directly inside a zustand selector: a fresh array read as "changed"
 * on every store broadcast re-renders forever (v5 throws "Maximum update
 * depth exceeded" outright). `hostCount` being a primitive (see its own doc)
 * fixes the LEAF, not this - the array this function returns is a new
 * reference every call regardless of what its elements are made of.
 * `useVault()` and `useHosts()` hand back stable references between
 * broadcasts (they return the store's own state, not something derived from
 * it), so a memo keyed on those plus `identities`/`keys` is safe; calling this
 * function with no memo at all is not.
 */
export function identityRows(
  identities: readonly VaultIdentity[],
  keys: ReadonlyMap<string, VaultKey>,
  hosts: readonly Host[],
): IdentityRow[] {
  return identities.map((identity) => {
    let keyName: string | undefined;
    let keyDangling = false;
    if (identity.keyId) {
      const key = keys.get(identity.keyId);
      keyName = key ? key.name : UNKNOWN_KEY_LABEL;
      keyDangling = key === undefined;
    }
    return {
      identity,
      keyName,
      keyDangling,
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
    missingPrivateKey: keyMissingSecret(key),
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
 * That residual holds only because nothing today asks this function a
 * verification question. `VaultKey.fingerprint`'s own doc
 * (`src/modules/vault/types.ts:122`) says the field is for "display, and
 * duplicate detection at import" - and `rankKeys`/`keyMatchTier` must NEVER be
 * the implementation of that second half. The moment an import path asks "does
 * the vault already have this fingerprint?" through this search layer, a
 * case-folded false positive stops being a ranking nicety and becomes a wrong
 * answer about whether a secret is a duplicate. Duplicate detection needs its
 * own case-sensitive equality over the full digest, not this function.
 *
 * `keyType` (`VaultKeyType`, `src/modules/vault/types.ts:113`) is already a short
 * lowercase token, so a `.includes` on it needs no folding of its own.
 *
 * Tier 3 and tier 5 compare DIGEST to digest, never the un-stripped
 * `"sha256:<digest>"` string. Every fingerprint this app produces shares the
 * literal "sha256:" lead (`src-tauri/src/modules/ssh/mod.rs:309`), so testing
 * the un-stripped form against the query made any prefix of that constant
 * string - "s", "sh", ..., all the way to "sha256:" itself - a tier-3 hit
 * against EVERY fingerprinted key, independent of the actual digest. That was
 * the bug: rows that should have been dropped for a one-letter query instead
 * flooded tier 3, and the tier order stopped meaning anything once every key
 * cleared it. Stripping the constant prefix from both sides before comparing
 * closes that off, including the degenerate case where the query strips down
 * to an empty digest (the query WAS just "sha256:"): `hasDigestQuery` refuses
 * to treat an empty digest as a match-everything wildcard.
 */
function keyMatchTier(row: KeyRow, query: string): number | null {
  const name = row.key.name.toLowerCase();
  const fingerprint = row.key.fingerprint?.toLowerCase();
  const keyType = row.key.keyType;

  if (name === query) return 1;
  if (name.startsWith(query)) return 2;

  // `digest` is the fingerprint with its constant "sha256:" lead stripped, or
  // `undefined` when the row has no fingerprint at all. `queryDigest` strips
  // the SAME optional prefix from the query, so a query for the bare digest
  // (no prefix typed) still matches - but an empty result after stripping
  // (`hasDigestQuery` false) means the query carried no actual digest, so it
  // must not match by virtue of the constant prefix alone.
  const digest = fingerprint?.startsWith("sha256:") ? fingerprint.slice(7) : fingerprint;
  const queryDigest = query.startsWith("sha256:") ? query.slice(7) : query;
  const hasDigestQuery = queryDigest.length > 0;

  if (digest !== undefined && hasDigestQuery && digest.startsWith(queryDigest)) return 3;
  if (hasWordBoundaryMatch(name, query)) return 4;
  if (
    name.includes(query) ||
    (keyType !== undefined && keyType.includes(query)) ||
    (digest !== undefined && hasDigestQuery && digest.includes(queryDigest))
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

/**
 * A refused vault delete, said in terms of what the user has to go and fix.
 *
 * Page COPY rather than a derivation, and it lives here anyway so the page has
 * one import site for everything it needs from this layer - the same argument
 * that put the three reference lookups' re-export at the top of this file.
 *
 * `VaultInUseError` already carries a serviceable message
 * (`src/modules/vault/types.ts:249-260`: `cannot delete X: still used by 2
 * hosts (a, b)`), and it is not the one to show, for the reason
 * `deleteRefusalText` in `HostsPage.tsx:119-128` exists: "still used by" reads
 * as a tidiness complaint, and this is not one. The holders are records that
 * would stop being able to connect, so the copy names them AND names the edit
 * that clears the way.
 *
 * `holderKind` comes from the caller rather than from the error because the
 * error does not carry it - the noun is baked into its message string only. The
 * caller always knows: an identity is held by hosts, a key is held by
 * identities, and nothing else holds either.
 *
 * Anything that is not a refusal falls through to its own message unchanged. A
 * keychain that refused a delete has something to say and this must not eat it.
 */
export function deleteRefusalText(
  subject: string,
  holderKind: "host" | "identity",
  e: unknown,
): string {
  if (!(e instanceof VaultInUseError)) return e instanceof Error ? e.message : String(e);
  const names = e.holders.map((h) => h.name || h.id).join(", ");
  const one = e.holders.length === 1;
  const noun = one ? holderKind : holderKind === "host" ? "hosts" : "identities";
  const target = holderKind === "host" ? "another credential" : "another key";
  return (
    `Cannot delete ${subject}: ${e.holders.length} ${noun} still ` +
    `${one ? "uses" : "use"} it (${names}). Point ${one ? "it" : "each of them"} at ${target} first.`
  );
}
