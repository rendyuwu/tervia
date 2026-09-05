/**
 * Self-check for the one-shot legacy secret purge.
 * Run: `npx tsx scripts/legacy-purge-verify.ts`.
 *
 * `purgeLegacySecrets` is the only thing that can ever name the keychain accounts
 * the two OLD connection stores left behind. The IPC surface is `secrets_get`,
 * `secrets_get_all`, `secrets_set` and `secrets_delete` with no `secrets_list`,
 * so the moment `modules/ssh/connections.ts` and `modules/rdp/connections.ts`
 * were deleted, `tervia-ssh :: <id>::privateKey` became unreachable from inside
 * the app. A pass that SKIPS is therefore not a cheap mistake, it is a private
 * key nobody can delete again.
 *
 * Which is why the happy path is not what this file is for. The whole suite in
 * `hosts-store-verify.ts` drives the purge through the real store, and it covers
 * the sweep, the marker, the torn and unparseable files, and a partial failure.
 * What it cannot reach from there is the branch where the MARKER ITSELF is
 * unreadable, because that needs a store port whose `get` rejects. This file
 * hands one in.
 */
import type { StoreFileIo, StoreFileRead, StoreRecovery } from "../src/lib/storeRecovery";
import type { HostsStoreIo } from "../src/modules/hosts/adapters";
import { purgeLegacySecrets } from "../src/modules/hosts/legacyPurge";
import { LEGACY_PURGE_KEY } from "../src/modules/hosts/types";
import type { SecretsIo } from "../src/modules/vault/adapters";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}

const DATA_DIR = "/data/dev.rendy.tervia";
const SSH_FILE = `${DATA_DIR}/tervia-ssh-connections.json`;
const RDP_FILE = `${DATA_DIR}/tervia-rdp-connections.json`;

/** One old store file's bytes, in the shape both old modules wrote. */
function rows(ids: string[]): StoreFileRead {
  return { kind: "text", content: JSON.stringify({ connections: ids.map((id) => ({ id })) }) };
}

type Harness = {
  io: HostsStoreIo & { data: Record<string, unknown> };
  files: StoreFileIo;
  secrets: SecretsIo;
  /** Every `secrets_delete` this run issued, as `service::account`. */
  deleted: string[];
};

/**
 * A store port, a file port and a secrets port, each doing the least a purge
 * needs. `getThrows` is the whole reason this file exists: the real port only
 * rejects when the store file is unreadable at the OS level, which cannot be
 * staged through the store layer above it.
 */
function harness(opts: { getThrows?: boolean; setThrows?: boolean } = {}): Harness {
  const data: Record<string, unknown> = {};
  const deleted: string[] = [];
  const notice: StoreRecovery | null = null;

  const io = {
    data,
    get: async <T>(key: string): Promise<T | null> => {
      if (opts.getThrows) throw new Error("store file is unreadable");
      return (data[key] as T | undefined) ?? null;
    },
    set: async (key: string, value: unknown): Promise<void> => {
      if (opts.setThrows) throw new Error("disk is full");
      data[key] = value;
    },
    commit: async (): Promise<void> => {},
    enqueueWrite: <T>(op: () => Promise<T>): Promise<T> => op(),
    onChanged: async (): Promise<() => void> => () => {},
    ensureLoaded: async (): Promise<StoreRecovery | null> => notice,
    takeRecoveryNotice: (): StoreRecovery | null => notice,
  };

  const files: StoreFileIo = {
    dir: async () => DATA_DIR,
    read: async (path) =>
      path === SSH_FILE ? rows(["c-1"]) : path === RDP_FILE ? rows(["r-1"]) : { kind: "missing" },
    write: async () => {},
  };

  const secrets: SecretsIo = {
    getAll: async () => [],
    set: async () => {},
    delete: async (service, account) => {
      deleted.push(`${service}::${account}`);
    },
    // The purge deletes by ACCOUNT NAME and never learns a value, so a copy
    // reaching here is a defect rather than a case to model. It throws for the
    // same reason `files.write` would: a fake that answered `false` would let a
    // future purge start moving secrets around and still pass every check below.
    copy: async () => {
      throw new Error("legacy-purge-verify: the purge must never copy a secret");
    },
  };

  return { io, files, secrets, deleted };
}

console.log("[marker] an unreadable marker must PURGE, not skip");
// The branch this file exists for. Skipping here is permanent: nothing else can
// name those accounts once the two old modules are gone, so a store read that
// failed for any reason - a torn file, a locked file, a plugin error - must fall
// through into a sweep whose every delete is idempotent anyway.
const unreadable = harness({ getThrows: true });
const blind = await purgeLegacySecrets({
  store: unreadable.io,
  secrets: unreadable.secrets,
  files: unreadable.files,
});
// Spelled out rather than compared against the spy, which would agree with
// itself when both are empty - the exact state the bug produced.
const EVERY_LEGACY_ACCOUNT = [
  "tervia-ssh::c-1::password",
  "tervia-ssh::c-1::privateKey",
  "tervia-ssh::c-1::keyPassphrase",
  "tervia-rdp::r-1::password",
];
check("the purge ran rather than reporting a skip", blind.skipped, false);
check("every legacy account was still swept", unreadable.deleted, EVERY_LEGACY_ACCOUNT);
check("and the same accounts are reported cleared", blind.cleared, EVERY_LEGACY_ACCOUNT);
// The read failure stays on the record, which is what stops this run earning the
// marker: a pass that could not tell whether it had already run must not claim it
// has, or the next launch skips a sweep that may never have happened.
check("the read failure is reported", blind.failed, [
  `${LEGACY_PURGE_KEY} could not be read: store file is unreadable`,
]);
check("and the marker is NOT written, so the next launch retries", unreadable.io.data, {});

console.log("\n[marker] a readable marker still short-circuits the whole pass");
const done = harness();
done.io.data[LEGACY_PURGE_KEY] = true;
const skipped = await purgeLegacySecrets({
  store: done.io,
  secrets: done.secrets,
  files: done.files,
});
check("a finished purge skips", [skipped.skipped, skipped.cleared, skipped.failed], [true, [], []]);
check("and reads nothing", done.deleted, []);

console.log("\n[marker] a clean pass records itself");
const fresh = harness();
const swept = await purgeLegacySecrets({
  store: fresh.io,
  secrets: fresh.secrets,
  files: fresh.files,
});
check("nothing failed", swept.failed, []);
check("the marker is written", fresh.io.data[LEGACY_PURGE_KEY], true);
// A marker that cannot be written costs a repeat pass and nothing else, so it is
// a `note` rather than a failure: every delete above is idempotent.
const unwritable = harness({ setThrows: true });
const noted = await purgeLegacySecrets({
  store: unwritable.io,
  secrets: unwritable.secrets,
  files: unwritable.files,
});
check("an unwritable marker is a note, not a failure", [noted.failed, !!noted.note], [[], true]);

console.log(failed === 0 ? "\nAll legacy-purge checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
