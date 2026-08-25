import type { StoreFileIo, StoreFileRead } from "@/lib/storeRecovery";
import type { SecretsIo } from "@/modules/vault/adapters";

import type { HostsStoreIo } from "./adapters";
import { LEGACY_PURGE_KEY } from "./types";

// A one-shot sweep of the secrets the two old connection modules leave behind.
//
// Decision 3 accepts losing the RECORDS: `tervia-ssh-connections.json` and
// `tervia-rdp-connections.json` are simply not read after this sub-phase (§9.1),
// and the saved hosts get re-entered once. Nobody accepted leaving the SECRETS.
// The moment those modules are deleted, `tervia-ssh :: <id>::{password,
// privateKey, keyPassphrase}` and `tervia-rdp :: <id>::password` become
// UNENUMERABLE: the IPC surface is `secrets_get`, `secrets_get_all`, `secrets_set`
// and `secrets_delete`, with no `secrets_list` (§9.7), so nothing left in the
// macOS keychain, the Windows `secrets.bin` or the Linux mode-0600 JSON could ever
// be named from inside the app again. Private keys, permanently, with no delete
// button anywhere.
//
// So this module must OUTLIVE what it cleans up. It reads the two old store files
// DIRECTLY, through `storeRecovery`'s existing file port, and imports nothing from
// `modules/ssh` or `modules/rdp` - not the store paths, not the service names, not
// the field lists. Copies of four short strings are the price of a purge that
// still works after those files are gone, and duplicating them is the whole point
// rather than an oversight.
//
// It never reads a secret's VALUE. `SecretsIo.delete` takes a service and an
// account name, and that is the only method touched here.

/** Both old modules stored their rows under this key. */
const LEGACY_ROWS_KEY = "connections";

/**
 * The two old store files, each with the keychain service and field list that
 * belonged to it: `SSH_SECRET_FIELDS` from `ssh/connections.ts`,
 * `RDP_SECRET_FIELDS` from `rdp/connections.ts`.
 *
 * Copied rather than imported, deliberately - see the module header. These are the
 * OLD services' names, which is the whole point: nothing else can name those
 * accounts once the modules that wrote them are deleted.
 */
const LEGACY_STORES: readonly {
  path: string;
  service: string;
  fields: readonly string[];
}[] = [
  {
    path: "tervia-ssh-connections.json",
    service: "tervia-ssh",
    fields: ["password", "privateKey", "keyPassphrase"],
  },
  { path: "tervia-rdp-connections.json", service: "tervia-rdp", fields: ["password"] },
];

/**
 * What one purge did.
 *
 * `failed` is why there is no single boolean: a `secrets_delete` that fails is a
 * REAL failure on every platform (`vault/adapters.ts` explains why - an absent
 * account already reports success), so it must not be folded into "done".
 */
export type LegacyPurgeResult = {
  /** Nothing was read or deleted: a previous run finished and left the marker. */
  skipped: boolean;
  /** Accounts `secrets_delete` accepted, as `service::account`. Never a value. */
  cleared: string[];
  /** Accounts that could not be cleared, each with its reason. The marker is NOT
   *  written when this is non-empty, so the next launch tries again. */
  failed: string[];
  /** Set when the marker itself could not be written, which only costs a repeat
   *  pass - every delete here is idempotent. */
  note?: string;
};

export type LegacyPurgeIo = {
  /** The HOSTS store, because that is where the marker lives and because its
   *  queue is the one that must not be raced. */
  store: HostsStoreIo;
  secrets: SecretsIo;
  files: StoreFileIo;
};

function reason(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * The ids one old store file names, or NONE for anything that cannot be read as
 * one.
 *
 * Total on purpose. A missing file (never installed, or already cleaned), an empty
 * file, a file torn to nul bytes by a power cut (plugins-workspace#3085) and a
 * file whose JSON does not parse are all "nothing to do" rather than errors:
 * running on every launch means every one of those is an ordinary Tuesday, and a
 * throw here would take the app's startup with it. A file too large for
 * `fs_read_file` reads as nothing to do as well - the alternative is pretending to
 * have purged it.
 */
function idsIn(read: StoreFileRead): string[] {
  if (read.kind !== "text") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(read.content);
  } catch {
    return [];
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return [];
  const rows = (parsed as Record<string, unknown>)[LEGACY_ROWS_KEY];
  if (!Array.isArray(rows)) return [];
  const ids: string[] = [];
  for (const row of rows) {
    if (row === null || typeof row !== "object") continue;
    const id = (row as Record<string, unknown>).id;
    if (typeof id === "string" && id) ids.push(id);
  }
  return ids;
}

/** `appDataDir()` carries no trailing separator today; normalise anyway. Forward
 *  slashes are fine on Windows - Rust's `PathBuf` accepts either. The join is
 *  duplicated from `storeRecovery`, which keeps it private. */
function pathIn(dir: string, fileName: string): string {
  return `${dir.replace(/[\\/]+$/, "")}/${fileName}`;
}

/**
 * Delete every keychain account the two old connection stores could have owned,
 * once, and remember that it happened.
 *
 * Safe to call on every launch: the marker skips the file reads, and without it
 * every delete is still idempotent - `secrets_delete` reports an absent account as
 * success on all three platforms.
 *
 * The old store FILES are deliberately left in place. They cost nothing, this
 * phase writes no migration (decision 3), and a user who wants their old host list
 * back for reference still has it sitting there to read.
 *
 * Never rejects. The worst outcome it reports is a partial purge, which is the one
 * thing the caller might want to say out loud.
 */
export async function purgeLegacySecrets(io: LegacyPurgeIo): Promise<LegacyPurgeResult> {
  const cleared: string[] = [];
  const failed: string[] = [];

  try {
    if ((await io.store.get<boolean>(LEGACY_PURGE_KEY)) === true) {
      return { skipped: true, cleared, failed };
    }
  } catch (e) {
    // The marker is unreadable, so run the purge rather than skip it: repeating
    // idempotent deletes is free, and skipping them is permanent.
    failed.push(`${LEGACY_PURGE_KEY} could not be read: ${reason(e)}`);
    return { skipped: false, cleared, failed };
  }

  let dir: string;
  try {
    dir = await io.files.dir();
  } catch (e) {
    // No data directory means no files to read and no way to know whether there
    // ever were any. Not a purge, and not a success.
    return { skipped: false, cleared, failed: [`the data directory is unreachable: ${reason(e)}`] };
  }

  for (const legacy of LEGACY_STORES) {
    let ids: string[];
    try {
      ids = idsIn(await io.files.read(pathIn(dir, legacy.path)));
    } catch (e) {
      // `tauriStoreFileIo.read` swallows its own errors, but the port allows one.
      failed.push(`${legacy.path} could not be read: ${reason(e)}`);
      continue;
    }
    for (const id of ids) {
      for (const field of legacy.fields) {
        const account = `${id}::${field}`;
        try {
          // Sequential, not `Promise.all`: one refusal must not abandon the
          // accounts behind it, and there are a handful of them, not thousands.
          await io.secrets.delete(legacy.service, account);
          cleared.push(`${legacy.service}::${account}`);
        } catch (e) {
          failed.push(`${legacy.service}::${account}: ${reason(e)}`);
        }
      }
    }
  }

  // Only a clean pass earns the marker. Anything left behind is unreachable once
  // the old modules are gone, so the next launch has to get another attempt.
  if (failed.length > 0) return { skipped: false, cleared, failed };

  try {
    await io.store.enqueueWrite(async () => {
      await io.store.set(LEGACY_PURGE_KEY, true);
      await io.store.commit();
    });
  } catch (e) {
    return {
      skipped: false,
      cleared,
      failed,
      note: `${LEGACY_PURGE_KEY} could not be recorded, so this will run again: ${reason(e)}`,
    };
  }
  return { skipped: false, cleared, failed };
}
