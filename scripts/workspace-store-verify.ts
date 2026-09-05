/**
 * Self-check: hydrating the workspace store must never blank a file it could
 * not read. Run: `npx tsx scripts/workspace-store-verify.ts`.
 *
 * This exists because the conversion of `tervia-workspaces.json` onto
 * `createRecoveredStore` could have introduced a data-loss regression and
 * nothing else would have caught it. The old `hydrate` retried a `get` three
 * times and set `readFailed` when it THREW; that flag is what stopped an empty
 * default being persisted over a file the app had merely failed to read. The
 * recovered-store port does not throw for a file it cannot use - `StoreFileIo`
 * reports `missing` instead - so a naive conversion leaves `readFailed`
 * permanently false, a transient unreadable file seeds "Workspace 1", and the
 * first `persist()` writes it over everything the user had saved.
 *
 * So the property here is one sentence: A SEEDED DEFAULT IS WRITTEN ONLY WHEN
 * THERE WAS NOTHING TO LOSE. Everything below is a state of the two files on
 * disk, and what the store does about it.
 *
 * Driven against a stand-in for the Tauri IPC bridge (the idiom
 * `rdp-tunnel-verify.ts` uses) rather than an injected port, because the store
 * is a zustand singleton that builds its own port at module scope - which is the
 * shape the app ships, and the shape the regression would live in. Each scenario
 * re-imports the module under a distinct specifier so it gets a fresh settle
 * pass; the recovery pass runs once per store instance, and that is exactly the
 * thing being varied.
 */
export {};

// ---------------------------------------------------------------------------
// Stand-in for the Tauri IPC bridge.
// ---------------------------------------------------------------------------

const APP_DATA_DIR = "/verify-app-data";
const PRIMARY = `${APP_DATA_DIR}/tervia-workspaces.json`;
const SNAPSHOT = `${PRIMARY}.bak`;

type Read =
  | { kind: "text"; content: string }
  | { kind: "binary" }
  | { kind: "toolarge" }
  /** There IS a file and the command would not open it. Distinct from absent,
   *  and the distinction is the point of the `[unreadable]` group below. */
  | { kind: "unreadable" };

/** The two files, as this run wants them found. Absent = the command errors
 *  with ENOENT, which is a genuine first run and NOT a failed read. */
let files: Record<string, Read> = {};
/** Every `fs_write_file`, in order. */
let writes: { path: string; content: string }[] = [];
/** When set, `appDataDir()` fails - the `unreachable` case. */
let dirFails = false;

const callbacks = new Map<number, (payload: unknown) => void>();
let nextId = 1;

async function handleInvoke(cmd: string, args: Record<string, unknown>): Promise<unknown> {
  switch (cmd) {
    case "plugin:path|resolve_directory":
      if (dirFails) throw new Error("app data dir unavailable");
      return APP_DATA_DIR;
    case "fs_read_file": {
      const path = args.path as string;
      const held = files[path];
      // Both of these are REJECTIONS from the real command, and the wording is
      // what tells them apart: `tauriStoreFileIo.read` sorts on the `(os error N)`
      // suffix Rust appends, so ENOENT becomes `missing` and everything else
      // becomes `unreadable`.
      if (!held) throw new Error(`No such file or directory (os error 2): ${path}`);
      if (held.kind === "unreadable") {
        throw new Error(`Permission denied (os error 13): ${path}`);
      }
      if (held.kind === "text") return { kind: "text", content: held.content, size: 1 };
      return held.kind === "toolarge"
        ? { kind: "toolarge", size: 1, limit: 1 }
        : { kind: "binary", size: 1 };
    }
    case "fs_write_file": {
      const path = args.path as string;
      const content = args.content as string;
      writes.push({ path, content });
      files[path] = { kind: "text", content };
      return undefined;
    }
    case "plugin:event|emit":
      return undefined;
    case "plugin:event|listen":
      return nextId++;
    case "plugin:event|unlisten":
      return undefined;
    default:
      throw new Error(`unexpected command in this harness: ${cmd}`);
  }
}

(globalThis as { window?: unknown }).window = {
  __TAURI_INTERNALS__: {
    transformCallback: (cb: (payload: unknown) => void) => {
      const id = nextId++;
      callbacks.set(id, cb);
      return id;
    },
    unregisterCallback: (id: number) => callbacks.delete(id),
    invoke: (cmd: string, args: Record<string, unknown>) => handleInvoke(cmd, args ?? {}),
  },
};

// ---------------------------------------------------------------------------

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}
function assert(cond: boolean, msg: string): void {
  if (cond) console.log(`  ok: ${msg}`);
  else {
    console.error(`  FAIL: ${msg}`);
    failed++;
  }
}

type Store = typeof import("../src/modules/workspaces/store");

/**
 * A fresh store instance over a fresh pair of files.
 *
 * The query string is a cache key, not a path: the module builds its port and
 * caches its settle pass at import, so a second scenario against the same import
 * would be answered by the first one's recovery verdict.
 */
let caseId = 0;
async function world(seed: { files?: Record<string, Read>; dirFails?: boolean }): Promise<Store> {
  files = { ...(seed.files ?? {}) };
  writes = [];
  dirFails = seed.dirFails ?? false;
  caseId++;
  return (await import(`../src/modules/workspaces/store.ts?case=${caseId}`)) as Store;
}

const text = (content: string): Read => ({ kind: "text", content });
const saved = (names: string[], activeIndex = 0): string =>
  JSON.stringify({
    workspaces: names.map((name, i) => ({
      id: `ws-${i}`,
      name,
      tabs: [{ kind: "pane", paneTree: { kind: "leaf", leafKind: "board" }, activeLeafIndex: 0 }],
      activeTabIndex: 0,
    })),
    activeId: `ws-${activeIndex}`,
  });
const primaryWrites = (): { path: string; content: string }[] =>
  writes.filter((w) => w.path === PRIMARY);

// ---------------------------------------------------------------------------
console.log("[read] a file that is there comes back");
{
  const mod = await world({ files: { [PRIMARY]: text(saved(["Left", "Right"], 1)) } });
  await mod.useWorkspacesStore.getState().hydrate();
  const s = mod.useWorkspacesStore.getState();
  check(
    "both workspaces are restored",
    s.workspaces.map((w) => w.name),
    ["Left", "Right"],
  );
  check("with the saved one active", s.activeId, "ws-1");
  check("and hydrated is true", s.hydrated, true);
  check("nothing was written over the file", primaryWrites().length, 0);
  assert(!!files[SNAPSHOT], "but a snapshot was taken beside it");
}

// ---------------------------------------------------------------------------
console.log("\n[first run] nothing on disk, so the seeded default is written");
{
  const mod = await world({});
  await mod.useWorkspacesStore.getState().hydrate();
  const s = mod.useWorkspacesStore.getState();
  check(
    "one workspace is seeded",
    s.workspaces.map((w) => w.name),
    ["Workspace 1"],
  );
  check("it is active", s.activeId, s.workspaces[0]?.id);
  check("hydrated is true", s.hydrated, true);
  // A genuine first run is the ONE case where writing the default is right: the
  // file does not exist, so there is nothing it could be written over.
  check("and the default reaches the file", primaryWrites().length, 1);
  const written = JSON.parse(primaryWrites()[0].content) as Record<string, unknown>;
  check(
    // Both keys in ONE write. That is the whole reason this store joined the
    // recovered family: an active id naming a workspace that is not in the list
    // is a state the file must never be able to hold.
    "carrying both keys, in one write",
    Object.keys(written).sort(),
    ["activeId", "workspaces"],
  );
}

// ---------------------------------------------------------------------------
console.log("\n[torn] a primary its snapshot cannot replace is NOT written over");
{
  // The regression this file exists for. The store comes up empty because the
  // file is unreadable, not because the user has no workspaces - and the empty
  // default must stay in memory.
  const mod = await world({
    files: { [PRIMARY]: text(""), [SNAPSHOT]: { kind: "binary" } },
  });
  await mod.useWorkspacesStore.getState().hydrate();
  const s = mod.useWorkspacesStore.getState();
  check(
    "a default is seeded so the app can boot",
    s.workspaces.map((w) => w.name),
    ["Workspace 1"],
  );
  check("hydrated is true, so the CLI drain is not stranded", s.hydrated, true);
  check("and NOTHING was written over the torn file", primaryWrites().length, 0);
  check("which is therefore still exactly as it was found", files[PRIMARY], text(""));
}
{
  // Same shape, different corruption: nul-filled, which `fs_read_file` reports
  // as binary rather than handing the bytes over.
  const mod = await world({ files: { [PRIMARY]: { kind: "binary" } } });
  await mod.useWorkspacesStore.getState().hydrate();
  check("a nul-filled primary with no snapshot writes nothing either", primaryWrites().length, 0);
  check("and still hydrates", mod.useWorkspacesStore.getState().hydrated, true);
}
{
  // A file too large for `fs_read_file` is real data, not corruption. Writing a
  // default over it would destroy the largest saved layout in the app.
  const mod = await world({ files: { [PRIMARY]: { kind: "toolarge" } } });
  await mod.useWorkspacesStore.getState().hydrate();
  check("a too-large primary is left alone", primaryWrites().length, 0);
  check("and still hydrates", mod.useWorkspacesStore.getState().hydrated, true);
}
{
  const mod = await world({ dirFails: true });
  await mod.useWorkspacesStore.getState().hydrate();
  check("an unreachable data directory writes nothing", primaryWrites().length, 0);
  check("and still hydrates", mod.useWorkspacesStore.getState().hydrated, true);
}

// ---------------------------------------------------------------------------
console.log("\n[unreadable] a file that is THERE and will not open is not a first run");
{
  // The distinction the whole guard rests on. `fs_read_file` rejects for BOTH
  // "no such file" and "there is a file and it would not open" - a lock during
  // an auto-update handoff, a Windows sharing violation, EACCES, a descriptor
  // limit. Folding the second into the first is what makes the default look
  // safe to write, and the file it would be written over is the one that was
  // never read.
  const mod = await world({ files: { [PRIMARY]: { kind: "unreadable" } } });
  await mod.useWorkspacesStore.getState().hydrate();
  const s = mod.useWorkspacesStore.getState();
  check("a default is seeded so the app can boot", s.workspaces.length, 1);
  check("hydrated is true", s.hydrated, true);
  check("and NOTHING is written over the file that would not open", primaryWrites().length, 0);
}
{
  // And the same read on the snapshot must not license a restore over a primary
  // that is merely torn: the snapshot's bytes are unknown, so they are not a
  // better copy of anything.
  const mod = await world({
    files: { [PRIMARY]: text(""), [SNAPSHOT]: { kind: "unreadable" } },
  });
  await mod.useWorkspacesStore.getState().hydrate();
  check("an unreadable snapshot restores nothing", primaryWrites().length, 0);
  check("and still hydrates", mod.useWorkspacesStore.getState().hydrated, true);
}

// ---------------------------------------------------------------------------
console.log("\n[restored] a snapshot that CAN replace it is used, and believed");
{
  const mod = await world({
    files: { [PRIMARY]: text('{"workspaces":['), [SNAPSHOT]: text(saved(["From the backup"])) },
  });
  await mod.useWorkspacesStore.getState().hydrate();
  const s = mod.useWorkspacesStore.getState();
  check(
    "the snapshot's workspaces are what load",
    s.workspaces.map((w) => w.name),
    ["From the backup"],
  );
  check("so no default is seeded", s.workspaces.length, 1);
  check("hydrated is true", s.hydrated, true);
}

// ---------------------------------------------------------------------------
console.log("\n[persist] a change writes both keys once");
{
  const mod = await world({ files: { [PRIMARY]: text(saved(["Only"])) } });
  const store = mod.useWorkspacesStore;
  await store.getState().hydrate();
  const before = primaryWrites().length;

  store.getState().renameWorkspace("ws-0", "Renamed");
  await store.getState().flush();

  const after = primaryWrites();
  assert(after.length > before, "a rename reaches the file");
  const last = JSON.parse(after[after.length - 1].content) as {
    workspaces: { name: string }[];
    activeId: string;
  };
  check(
    "with the new name",
    last.workspaces.map((w) => w.name),
    ["Renamed"],
  );
  check("and the active id in the same write", last.activeId, "ws-0");
}

if (failed > 0) throw new Error(`workspace-store-verify: ${failed} FAILED`);
console.log("\nworkspace-store-verify: OK\n");
