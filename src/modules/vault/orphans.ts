import type { StoreFileState } from "@/lib/storeRecovery";
import { HOST_RDP_SECRET_FIELDS, HOST_SSH_SECRET_FIELDS, type Host } from "@/modules/hosts/types";

import type { SecretEntry, SecretsIo } from "./adapters";
import {
  HOST_KEYRING_SERVICE,
  VAULT_IDENTITY_SECRET_FIELDS,
  VAULT_KEY_SECRET_FIELDS,
  VAULT_KEYRING_SERVICE,
  vaultAccount,
  type VaultIdentity,
  type VaultKey,
} from "./types";

// Which stored secrets no record accounts for, and nothing else.
//
// The policy half of the orphan sweep, with no Tauri in it: `secrets_list` is
// the only thing that can answer "what is in there", and this subtracts what the
// app's own records claim from what it answers. Injected `list` and `delete`, so
// `scripts/orphan-secrets-verify.ts` drives the whole decision without a
// keychain.
//
// REPORTS AND ASKS, NEVER DELETES ON ITS OWN. `purgeLegacySecrets` in
// `modules/hosts/legacyPurge.ts` may run unattended because it derives its
// accounts from ids read out of a specific file and skips entirely when that file
// will not read. This derives its targets from the ABSENCE of a record, where
// the same failure would delete everything - which is what {@link usable} is for
// and why the caller confirms.

/**
 * The two services nothing can name any more. Every account under either is an
 * orphan by construction: the modules that wrote them are deleted, so the known
 * set is empty.
 *
 * Copied, not imported, for the reason `modules/hosts/legacyPurge.ts`'s header
 * gives: this must keep working after the old store FILES that pass reads are
 * gone, and enumeration is what makes it independent of them.
 *
 * The SYNC service is deliberately absent, and a reader who adds it would be
 * making a mistake rather than a fix: `SYNC_KEYRING_SERVICE` in
 * `modules/sync/types.ts` holds fixed account names rather than `<id>::<field>`,
 * so there is no id to subtract and a configured passphrase would be reported as
 * an orphan.
 */
const LEGACY_SERVICES = ["tervia-ssh", "tervia-rdp"] as const;

/** Both host field lists, unioned. A merged row carries both protocols, so a
 *  protocol flip must not manufacture an orphan. */
const HOST_SECRET_FIELDS = [...HOST_SSH_SECRET_FIELDS, ...HOST_RDP_SECRET_FIELDS];

/** How a store file looked, which is the only thing that decides whether its ids
 *  are knowable. */
export type StoreFileVerdict = { found: StoreFileState; recovered: boolean };

/** What the sweep needs: the listing, and the delete. `list` is the free
 *  function `listSecrets` from `./adapters`, not a port method - see its doc for
 *  why it is not on {@link SecretsIo}. */
export type OrphanSecretsIo = Pick<SecretsIo, "delete"> & {
  list(service: string): Promise<string[]>;
};

export type OrphanScan =
  /** Not checked, and why. Nothing was listed and nothing may be deleted. */
  { kind: "off"; reason: string } | { kind: "ok"; orphans: SecretEntry[]; failed: string[] };

/**
 * The store file states in which the ids this app knows ARE knowable.
 *
 * `missing` belongs here: the contents are known - there are none - and it is
 * the exact state a rolled-back restore leaves behind, which is the case the
 * sweep exists for. `empty`, `nul`, `unparseable`, `toolarge`, `unreadable` and
 * `unreachable` all mean the ids cannot be enumerated, and a sweep over an empty
 * known set would call every stored secret an orphan.
 */
function usable(file: StoreFileVerdict): boolean {
  return file.recovered || file.found === "ok" || file.found === "missing";
}

/**
 * Every `service -> account` set the app's records account for.
 *
 * Built from the id list and the FULL field list, never from the `has*` presence
 * flags. A record claiming no password while an account holds one is a stale
 * flag, not an orphan - `KNOWN-LIMITS.md`'s restore entry is about exactly that
 * - and deleting on a flag mismatch would destroy a secret the record can still
 * be corrected to use.
 *
 * The two legacy services map to an EMPTY set rather than being left out, so the
 * caller's one loop lists them too and everything under them comes back as an
 * orphan.
 */
export function knownAccounts(input: {
  hosts: Host[];
  identities: VaultIdentity[];
  keys: VaultKey[];
}): Map<string, Set<string>> {
  const known = new Map<string, Set<string>>();
  known.set(
    HOST_KEYRING_SERVICE,
    new Set(input.hosts.flatMap((h) => HOST_SECRET_FIELDS.map((f) => vaultAccount(h.id, f)))),
  );
  known.set(
    VAULT_KEYRING_SERVICE,
    new Set([
      ...input.identities.flatMap((i) =>
        VAULT_IDENTITY_SECRET_FIELDS.map((f) => vaultAccount(i.id, f)),
      ),
      ...input.keys.flatMap((k) => VAULT_KEY_SECRET_FIELDS.map((f) => vaultAccount(k.id, f))),
    ]),
  );
  for (const service of LEGACY_SERVICES) known.set(service, new Set());
  return known;
}

/**
 * Enumerate the four services this app writes and subtract every account its
 * records account for. Never rejects: a service that would not list lands in
 * `failed` and the others are still reported.
 */
export async function scanOrphanSecrets(input: {
  hosts: { rows: Host[]; file: StoreFileVerdict };
  vault: { identities: VaultIdentity[]; keys: VaultKey[]; file: StoreFileVerdict };
  io: OrphanSecretsIo;
}): Promise<OrphanScan> {
  // Before any `list` call, not after: a scan whose known set is incomplete must
  // not even look, because the answer it would produce is "delete everything".
  if (!usable(input.hosts.file)) {
    return { kind: "off", reason: `the saved machines file reads as ${input.hosts.file.found}` };
  }
  if (!usable(input.vault.file)) {
    return { kind: "off", reason: `the vault file reads as ${input.vault.file.found}` };
  }

  const known = knownAccounts({
    hosts: input.hosts.rows,
    identities: input.vault.identities,
    keys: input.vault.keys,
  });
  const orphans: SecretEntry[] = [];
  const failed: string[] = [];
  for (const [service, accounts] of known) {
    let stored: string[];
    try {
      stored = await input.io.list(service);
    } catch (e) {
      failed.push(`${service}: ${e instanceof Error ? e.message : String(e)}`);
      continue;
    }
    for (const account of stored) {
      if (!accounts.has(account)) orphans.push({ service, account });
    }
  }
  return { kind: "ok", orphans, failed };
}

/**
 * Delete the named accounts. Sequential, not `Promise.all`: one refusal must not
 * abandon the accounts behind it, which is the same reason `deleteHost` in
 * `modules/hosts/store.ts` fans its deletes out one at a time.
 */
export async function deleteOrphanSecrets(
  orphans: readonly SecretEntry[],
  io: OrphanSecretsIo,
): Promise<{ cleared: string[]; failed: string[] }> {
  const cleared: string[] = [];
  const failed: string[] = [];
  for (const { service, account } of orphans) {
    try {
      await io.delete(service, account);
      cleared.push(`${service}::${account}`);
    } catch (e) {
      failed.push(`${service}::${account}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { cleared, failed };
}
