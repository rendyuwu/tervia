/**
 * The Tauri-dependent half of importing an `ssh_config`/PuTTY `.reg` file:
 * resolves what the pure parsers in `sshConfigImport.ts`/`puttyRegImport.ts`
 * could not (an `IdentityFile` path, a `ProxyJump` against saved hosts), then
 * writes the result.
 *
 * SPLIT IN TWO, `preview*` then `applyForeignImport`, matching the review
 * dialog's own contract: nothing is written until the user confirms what
 * `preview*` built. `applyForeignImport` is shared by both sources - once a
 * source has produced `SshHost`/`VaultIdentity`/`VaultKey` rows, writing them
 * does not care where they came from.
 *
 * NOT `applyV3` (`apply.ts`), and deliberately so. `applyV3` decrypts a sealed
 * blob this app produced and never lets a credential's plaintext reach JS -
 * that is the whole point of `backup_open_payload`/`backup_apply_secrets`. An
 * `IdentityFile`'s bytes are read directly by THIS import (the same
 * `fs_read_file` call the key editor's own picker makes), so the private key
 * is already plaintext in memory here, exactly the state the key editor's own
 * save is in - `upsertKey(record, { privateKey })` is the same call
 * `KeyEditorDialog.tsx` makes on save. The MERGE machinery (jump clearing,
 * ordering, protocol-conflict refusal) is reused unchanged from `file.ts`;
 * only the write step differs, because the trust boundary differs.
 */
import { invoke } from "@tauri-apps/api/core";
import { dirname, homeDir, join } from "@tauri-apps/api/path";

import type { FsReadResult } from "@/lib/ipc";
import { listHosts, upsertHost } from "@/modules/hosts/store";
import type { SshHost } from "@/modules/hosts/types";
import { inspectSshKey } from "@/modules/ssh/bridge";
import { vaultKeyFactsFrom, type VaultKeyFacts } from "@/modules/vault/keyInspect";
import {
  listIdentities,
  listKeys,
  newIdentityId,
  newKeyId,
  upsertIdentity,
  upsertKey,
} from "@/modules/vault/store";
import type { SshCredentialBinding, VaultIdentity, VaultKey } from "@/modules/vault/types";

import type { ImportCounts, ImportIdentityCounts, ImportKeyCounts } from "./apply";
import { clearDanglingJumps, orderHostWrites, refuseProtocolConflicts, sanitizeKey } from "./file";
import type { PuttyParseResult, PuttyRefusalReason } from "./puttyRegImport";
import {
  resolveProxyJumpChain,
  type ParsedForeignHost,
  type SshConfigParseResult,
  type SshConfigRefusalReason,
} from "./sshConfigImport";

/** Every reason a row can be refused across both sources, plus the two that
 *  only exist once a saved store is in the picture (`chainUnresolved`,
 *  `keyUnreadable` - the pure parsers cannot know either without `listHosts`/
 *  a file read) and `protocolConflicts` (see `refuseProtocolConflicts` in
 *  `file.ts` - reused for the same reason `KNOWN-LIMITS.md`'s re-import entry
 *  gives: always zero today given freshly minted ids, kept rather than
 *  special-cased out because the row-checking machinery is shared, not
 *  duplicated). */
export type ForeignRefusalReason =
  | SshConfigRefusalReason
  | PuttyRefusalReason
  | "chainUnresolved"
  | "keyUnreadable"
  | "protocolConflicts";

export type ForeignImportPreview = {
  hosts: SshHost[];
  identities: VaultIdentity[];
  keys: { record: VaultKey; privateKey: string }[];
  refused: Partial<Record<ForeignRefusalReason, number>>;
  skipped: number;
};

export type ForeignImportResult = {
  hosts: ImportCounts;
  identities: ImportIdentityCounts;
  keys: ImportKeyCounts;
  refused: Partial<Record<ForeignRefusalReason, number>>;
  skipped: number;
  problems: string[];
};

function bump(
  refused: Partial<Record<ForeignRefusalReason, number>>,
  reasonKey: ForeignRefusalReason,
): void {
  refused[reasonKey] = (refused[reasonKey] ?? 0) + 1;
}

/** POSIX `/...`, a Windows drive (`C:\`/`C:/`) or a UNC path (`\\server\...`).
 *  No library needed for one predicate this narrow. */
function isAbsolutePath(p: string): boolean {
  return p.startsWith("/") || /^[a-zA-Z]:[\\/]/.test(p) || p.startsWith("\\\\");
}

/** `~`, `~/rest`, a path relative to the config file's own directory, or
 *  already absolute - see decision 7 in the plan for why each form is
 *  resolved the way it is. */
async function resolveIdentityFilePath(raw: string, configDir: string): Promise<string> {
  const p = raw.trim();
  if (p === "~") return homeDir();
  if (p.startsWith("~/") || p.startsWith("~\\")) return join(await homeDir(), p.slice(2));
  if (isAbsolutePath(p)) return p;
  return join(configDir, p);
}

/** Read and inspect one `IdentityFile`, building the `VaultKey` `sanitizeKey`
 *  would accept. `null` for anything unreadable or unparseable - a picker-
 *  style `fs_read_file` failure, a non-text result, or `inspectSshKey`
 *  rejecting the content (a public key pasted by mistake, DSA, a SEC1 `EC
 *  PRIVATE KEY`). An encrypted key with no stored passphrase is NOT this
 *  case: `inspectSshKey` answers `parsed:false` rather than rejecting, and
 *  the key still imports - see `vaultKeyFactsFrom`. */
async function buildVaultKeyFromFile(
  path: string,
): Promise<{ record: VaultKey; privateKey: string } | null> {
  let result: FsReadResult;
  try {
    result = await invoke<FsReadResult>("fs_read_file", { path });
  } catch {
    return null;
  }
  if (result.kind !== "text" || !result.content.trim()) return null;

  let facts: VaultKeyFacts;
  try {
    facts = vaultKeyFactsFrom(await inspectSshKey(result.content));
  } catch {
    return null;
  }

  const name = path.split(/[\\/]/).pop() || path;
  const record = sanitizeKey({ id: newKeyId(), name, ...facts });
  return record ? { record, privateKey: result.content } : null;
}

/**
 * Preview an `ssh_config` parse: resolve every `ProxyJump` (against the
 * file's own aliases, then `await listHosts()`), read and dedupe every
 * `IdentityFile` into a vault key + a per-host identity, then run the
 * result through `refuseProtocolConflicts` / `clearDanglingJumps` /
 * `orderHostWrites` unchanged. Writes nothing.
 */
export async function previewSshConfigImport(
  parsed: SshConfigParseResult,
  configPath: string,
): Promise<ForeignImportPreview> {
  const existingHosts = await listHosts();
  const existingByAlias = new Map(existingHosts.map((h) => [h.name, h]));

  // First occurrence wins for a literal alias claimed by two Host lines
  // (decision 3).
  const aliasIndex = new Map<string, string>();
  for (const h of parsed.hosts) if (!aliasIndex.has(h.alias)) aliasIndex.set(h.alias, h.id);

  const lookupSaved = (token: string): { id: string; proxyJumpId?: string } | undefined => {
    const saved = existingByAlias.get(token);
    return saved && saved.protocol === "ssh"
      ? { id: saved.id, proxyJumpId: saved.proxyJumpId }
      : undefined;
  };

  // Pass 1: every host's OWN single-hop ProxyJump, needed below as the
  // consistency check for a chain that jumps through another file-local host.
  const singleHop = new Map<string, string | undefined>();
  for (const h of parsed.hosts) {
    if (h.proxyJumpTokens?.length !== 1) continue;
    const lookup1 = (token: string) => {
      const fid = aliasIndex.get(token);
      return fid ? { id: fid } : lookupSaved(token);
    };
    singleHop.set(h.id, resolveProxyJumpChain(h.proxyJumpTokens, lookup1).proxyJumpId);
  }

  const refused: Partial<Record<ForeignRefusalReason, number>> = { ...parsed.refused };
  let skipped = parsed.skipped;

  const proxyJumpByHostId = new Map<string, string>();
  for (const h of parsed.hosts) {
    if (!h.proxyJumpTokens || h.proxyJumpTokens.length === 0) continue;
    if (h.proxyJumpTokens.length === 1) {
      const id = singleHop.get(h.id);
      if (id) proxyJumpByHostId.set(h.id, id);
      continue;
    }
    const lookup2 = (token: string) => {
      const fid = aliasIndex.get(token);
      return fid ? { id: fid, proxyJumpId: singleHop.get(fid) } : lookupSaved(token);
    };
    const resolved = resolveProxyJumpChain(h.proxyJumpTokens, lookup2);
    if (resolved.chainUnresolved) bump(refused, "chainUnresolved");
    else if (resolved.proxyJumpId) proxyJumpByHostId.set(h.id, resolved.proxyJumpId);
  }

  // IdentityFile: resolve, read, inspect, dedupe by resolved path - one key
  // and one read no matter how many stanzas name the same file.
  const configDir = await dirname(configPath);
  const keyIdByPath = new Map<string, string>();
  const keys: { record: VaultKey; privateKey: string }[] = [];
  const identities: VaultIdentity[] = [];
  const identityIdByHostId = new Map<string, string>();

  for (const h of parsed.hosts) {
    if (!h.identityFilePath) continue;
    let resolvedPath: string;
    try {
      resolvedPath = await resolveIdentityFilePath(h.identityFilePath, configDir);
    } catch {
      bump(refused, "keyUnreadable");
      continue;
    }
    let keyId = keyIdByPath.get(resolvedPath);
    if (keyId === undefined) {
      const built = await buildVaultKeyFromFile(resolvedPath);
      keyId = built ? built.record.id : "";
      keyIdByPath.set(resolvedPath, keyId);
      if (built) keys.push(built);
      else bump(refused, "keyUnreadable");
    }
    if (!keyId) continue;
    const identityId = newIdentityId();
    identities.push({
      id: identityId,
      name: h.user ? `${h.user} @ ${h.alias}` : h.alias,
      username: h.user,
      authMode: "key",
      hasPassword: false,
      keyId,
    });
    identityIdByHostId.set(h.id, identityId);
  }

  const hosts: SshHost[] = parsed.hosts.map((h) =>
    hostRecordFrom(h, proxyJumpByHostId.get(h.id), identityIdByHostId.get(h.id)),
  );

  const conflicts = refuseProtocolConflicts(hosts, existingHosts);
  if (conflicts.conflicts > 0) refused.protocolConflicts = conflicts.conflicts;
  const ordered = orderHostWrites(
    clearDanglingJumps(conflicts.hosts, existingHosts),
    existingHosts,
  );

  return { hosts: ordered, identities, keys, refused, skipped };
}

/**
 * Preview a PuTTY `.reg` parse. No `ProxyJump`/`IdentityFile` concept in this
 * scope, so every session arrives with a blank inline SSH credential - the
 * same fallback an `ssh_config` host with no `IdentityFile` gets. Writes
 * nothing.
 */
export async function previewPuttyImport(parsed: PuttyParseResult): Promise<ForeignImportPreview> {
  const existingHosts = await listHosts();
  const hosts = parsed.hosts.map((h) => hostRecordFrom(h, undefined, undefined));
  const conflicts = refuseProtocolConflicts(hosts, existingHosts);
  const refused: Partial<Record<ForeignRefusalReason, number>> = { ...parsed.refused };
  if (conflicts.conflicts > 0) refused.protocolConflicts = conflicts.conflicts;
  // No proxyJumpId is ever set for a PuTTY session, so clearDanglingJumps is a
  // no-op here - run anyway, matching decision 11's reasoning for
  // refuseProtocolConflicts: the row-checking machinery is shared, not
  // special-cased out per source.
  const ordered = orderHostWrites(
    clearDanglingJumps(conflicts.hosts, existingHosts),
    existingHosts,
  );
  return { hosts: ordered, identities: [], keys: [], refused, skipped: parsed.skipped };
}

function hostRecordFrom(
  h: ParsedForeignHost,
  proxyJumpId: string | undefined,
  identityId: string | undefined,
): SshHost {
  const credential: SshCredentialBinding = identityId
    ? { kind: "identity", identityId }
    : {
        kind: "inline",
        hostId: h.id,
        user: h.user,
        authMode: "password",
        hasPassword: false,
        hasPrivateKey: false,
        hasKeyPassphrase: false,
      };
  return {
    id: h.id,
    name: h.alias,
    host: h.host,
    port: h.port,
    protocol: "ssh",
    credential,
    ...(proxyJumpId ? { proxyJumpId } : {}),
  };
}

function reason(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Write a previewed import: keys, then identities (their `keyId`s already
 * name a key from THIS SAME preview, so no `normaliseIdentityKeys`-style
 * reconciliation is needed - decision 7), then hosts - the same order
 * `applyV3` writes in and for the same reason, so a host's identity binding
 * always names a record already on disk. Each record is tried independently
 * and a failure is counted and reported without abandoning the rest, matching
 * `applyV3`'s own containment.
 */
export async function applyForeignImport(
  preview: ForeignImportPreview,
): Promise<ForeignImportResult> {
  const [existingHosts, existingIdentities, existingKeys] = await Promise.all([
    listHosts(),
    listIdentities(),
    listKeys(),
  ]);
  const existingHostIds = new Set(existingHosts.map((h) => h.id));
  const existingIdentityIds = new Set(existingIdentities.map((i) => i.id));
  const existingKeyIds = new Set(existingKeys.map((k) => k.id));

  const keys: ImportKeyCounts = { added: 0, replaced: 0, withoutSecrets: 0, failed: 0 };
  const identities: ImportIdentityCounts = {
    added: 0,
    replaced: 0,
    withoutSecrets: 0,
    withoutKeys: 0,
    keysDropped: 0,
    failed: 0,
  };
  const hosts: ImportCounts = { added: 0, replaced: 0, withoutSecrets: 0, failed: 0 };
  const problems: string[] = [];

  for (const { record, privateKey } of preview.keys) {
    try {
      await upsertKey(record, { privateKey });
      if (existingKeyIds.has(record.id)) keys.replaced++;
      else keys.added++;
    } catch (e) {
      keys.failed++;
      problems.push(`key "${record.name}" could not be saved: ${reason(e)}`);
    }
  }

  for (const identity of preview.identities) {
    try {
      await upsertIdentity(identity, {});
      if (existingIdentityIds.has(identity.id)) identities.replaced++;
      else identities.added++;
    } catch (e) {
      identities.failed++;
      problems.push(`identity "${identity.name}" could not be saved: ${reason(e)}`);
    }
  }

  for (const host of preview.hosts) {
    try {
      await upsertHost(host, {});
      if (existingHostIds.has(host.id)) hosts.replaced++;
      else hosts.added++;
    } catch (e) {
      hosts.failed++;
      problems.push(`"${host.name}" could not be saved: ${reason(e)}`);
    }
  }

  return { hosts, identities, keys, refused: preview.refused, skipped: preview.skipped, problems };
}
