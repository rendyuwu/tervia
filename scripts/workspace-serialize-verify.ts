/**
 * Workspace serialization audit. Eight properties, all silent when broken:
 *
 * 1. A remote (SFTP) editor leaf must never round-trip through its SESSION.
 *    `sshSessionId` is a live russh number: dead after a restart, and since the
 *    counter restarts at 1, liable to name a different host. Restoring a leaf
 *    that keeps it is wrong; restoring one WITHOUT anything remote is worse,
 *    because `useDocument` then reads - and on the next save writes - the
 *    remote path against the LOCAL disk.
 * 2. A leaf carrying a saved `sshConnectionId` must round-trip, since that id
 *    survives a restart and the pane re-resolves it to a live session. An
 *    AD-HOC one (no profile) has nothing to come back as and is still pruned;
 *    its siblings, the split shape, and the active-leaf index have to survive
 *    that prune.
 * 3. `savedActiveTabIndex` must count exactly the tabs `serializeTabs` emits.
 *    Any drift silently focuses the wrong tab on restore.
 * 4. A tab renamed from its right-click menu must round-trip. The serializer
 *    whitelists leaf fields one by one, so a new one is dropped unless it is
 *    added in BOTH directions - and the failure is a name that quietly reverts
 *    to the folder basename on the next launch. Clearing a name must remove the
 *    key rather than persist `""`, which would restore as a blank tab.
 * 5. An RDP leaf must round-trip its connection id AND its size mode, and must
 *    restore with NO session identity of any kind. The id is the only thing
 *    that can find the host, the credentials and the desktop size again, and a
 *    leaf that loses it comes back as a pane that can never connect; the size
 *    mode is persisted from day one purely so adding `"fit"` later needs no
 *    migration, which is worthless if the serializer drops it. Together these
 *    are property 4's whitelist problem on a kind where the symptom is a dead
 *    pane rather than a wrong name.
 * 6. A page leaf must round-trip its `page` value and rename, inside a split
 *    exactly like any other kind, and an unrecognised `page` value (a newer
 *    build's page, or hand-edited state) must restore as Hosts rather than crash
 *    or drop the leaf. Hosts is the only page that may BE a leaf since DCR-1; a
 *    saved `vault`/`forwards` leaf is dropped on restore, which is
 *    `scripts/rail-views-verify.ts`.
 * 7. Switching to (or creating) a workspace with no saved tabs must land on
 *    the Hosts page, matching the startup fallback (decision 9) instead of
 *    reverting to a local shell; a workspace that does have saved tabs must
 *    still restore them untouched. And the fallback tab must itself survive a
 *    restart, since it is snapshotted like any other tab.
 * 8. Closing a leaf must be refused only when it is the last thing ON SCREEN,
 *    never when it is merely the last TERMINAL. Since the default tab became a
 *    Hosts page a workspace can hold zero terminals and still be full, so the
 *    old proxy both resurrected a terminal the user had just exited and made
 *    Ctrl+Shift+X a silent no-op.
 *
 * Run: `npx tsx scripts/workspace-serialize-verify.ts`.
 *
 * serialize.ts and tabs/lib/entries.ts pull in panes.ts (type-only imports) and
 * the zustand title store, so this runs under plain node with hand-built pane
 * trees.
 */
import {
  defaultHostsTab,
  serializeTabs,
  savedActiveTabIndex,
  savedToTab,
  tabsForWorkspaceEntry,
} from "../src/modules/workspaces/serialize";
import { countTabEntries, isLastEntryInWorkspace } from "../src/modules/tabs/lib/entries";
import {
  foldSshBinding,
  type SshConnectionBinding,
  type SshStatus,
} from "../src/modules/ssh/status";
import type { SavedPaneNode, SavedTab } from "../src/modules/workspaces/store";
import {
  editorPaneSession,
  type PaneNode,
  type TabPageKind,
} from "../src/modules/terminal/lib/panes";
import type { Tab } from "../src/modules/tabs";

let nextId = 1;
const id = () => nextId++;

/**
 * `savedToTab` returns null for a tab that does not survive restore - DCR-1's
 * dropped Vault/Port-Forwarding leaves. Every case below restores a tab that is
 * supposed to come back, so a null here is the check failing, not a branch to
 * handle. The rail-view cases assert on `savedToTab` / `restoreSavedTabs`
 * directly.
 */
function restoreOne(saved: SavedTab, allocId: () => number): Tab {
  const tab = savedToTab(saved, allocId);
  if (tab === null) throw new Error("expected the saved tab to survive restore");
  return tab;
}

function term(leafId: number, cwd = "/w"): PaneNode {
  return { kind: "leaf", id: leafId, leafKind: "terminal", cwd };
}
function editor(leafId: number, path: string): PaneNode {
  return { kind: "leaf", id: leafId, leafKind: "editor", path, dirty: false, preview: false };
}
/** Ad-hoc remote file: opened over a session with no saved profile behind it,
 *  so there is nothing stable to restore and the leaf must be pruned. */
function adHocRemoteEditor(leafId: number, path: string): PaneNode {
  return {
    kind: "leaf",
    id: leafId,
    leafKind: "editor",
    path,
    dirty: false,
    preview: false,
    sshSessionId: 7,
    sshHostLabel: "u@h:22",
  };
}
/** Remote file opened through a SAVED connection: carries both the live session
 *  and the profile id, and must round-trip on the profile alone. */
function savedRemoteEditor(leafId: number, path: string): PaneNode {
  return {
    kind: "leaf",
    id: leafId,
    leafKind: "editor",
    path,
    dirty: false,
    preview: false,
    sshConnectionId: "c-prod",
    sshSessionId: 7,
    sshHostLabel: "u@h:22",
  };
}
/** An RDP leaf: a reference to a saved connection and how it sizes itself.
 *  Nothing else - no host, no credential, no session. */
function rdp(leafId: number, rdpConnectionId: string): PaneNode {
  return { kind: "leaf", id: leafId, leafKind: "rdp", rdpConnectionId, sizeMode: "preset" };
}
/** A page leaf: nothing but which page it is. `TabPageKind`, so a Vault or
 *  Port-Forwarding leaf cannot be built here either - since DCR-1 that is a
 *  type error, not a fixture. See `scripts/rail-views-verify.ts`. */
function page(leafId: number, p: TabPageKind): PaneNode {
  return { kind: "leaf", id: leafId, leafKind: "page", page: p };
}
function split(dir: "row" | "col", children: PaneNode[], sizes?: number[]): PaneNode {
  return { kind: "split", id: id(), dir, children, ...(sizes ? { sizes } : {}) };
}
function tab(paneTree: PaneNode, activeLeafId: number, tabId = id()): Tab {
  return { id: tabId, kind: "pane", title: "t", paneTree, activeLeafId };
}

/** Narrow to the pane variant. `SavedTab` still carries the legacy `preview`
 *  kind, which `serializeTabs` never emits. */
function pane(t: SavedTab): { paneTree: SavedPaneNode; activeLeafIndex: number } {
  if (t.kind !== "pane") throw new Error(`expected a saved pane tab, got "${t.kind}"`);
  return t;
}

/** Leaf kinds of a saved tree, in order. `split(...)` for a split node. */
function shape(t: SavedTab): string {
  const walk = (n: SavedPaneNode): string =>
    n.kind === "leaf" ? n.leafKind : `split(${n.children.map(walk).join(",")})`;
  return walk(pane(t).paneTree);
}

/** Persisted divider ratios, or null when the root is a leaf / carries none. */
function sizes(t: SavedTab): number[] | null {
  const n = pane(t).paneTree;
  return n.kind === "split" ? (n.sizes ?? null) : null;
}

const activeIdx = (t: SavedTab): number => pane(t).activeLeafIndex;

let failures = 0;
function check(label: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a === e) {
    console.log(`  ok    ${label}`);
  } else {
    console.log(`  FAIL  ${label}\n          expected ${e}\n          actual   ${a}`);
    failures++;
  }
}

console.log("\n[prune] a remote editor leaf must not round-trip");

// Nothing to prune: the ordinary case must come through unchanged.
{
  const s = serializeTabs([tab(split("row", [term(101), editor(102, "/w/a.ts")], [30, 70]), 102)]);
  check("local editor + terminal: both saved", shape(s[0]), "split(terminal,editor)");
  check("local editor + terminal: divider ratios preserved", sizes(s[0]), [30, 70]);
  check("local editor + terminal: active index", activeIdx(s[0]), 1);
}

// The defect: the remote leaf is dropped and the split collapses to its sibling.
{
  const s = serializeTabs([
    tab(split("row", [term(201), adHocRemoteEditor(202, "/srv/a.ts")], [30, 70]), 201),
  ]);
  check("remote editor pruned, sibling kept", shape(s[0]), "terminal");
  check("collapsed split drops stale sizes", sizes(s[0]), null);
  check("surviving terminal is still the active leaf", activeIdx(s[0]), 0);
}

// The active leaf itself was pruned: fall back to the first survivor, never -1.
{
  const s = serializeTabs([
    tab(split("row", [term(301), adHocRemoteEditor(302, "/srv/a.ts")]), 302),
  ]);
  check("pruned active leaf falls back to index 0", activeIdx(s[0]), 0);
}

// A pruned leaf BEFORE the active one used to shift every later index.
{
  const s = serializeTabs([
    tab(
      split("row", [adHocRemoteEditor(401, "/srv/a.ts"), term(402), term(403)], [20, 40, 40]),
      403,
    ),
  ]);
  check("index is taken over SAVED leaves, not live ones", activeIdx(s[0]), 1);
  check("both terminals survive", shape(s[0]), "split(terminal,terminal)");
  check("sizes dropped after a prune", sizes(s[0]), null);
}

// Nested: the inner split loses a child, collapses, and flattens into the outer.
{
  const inner = split("col", [adHocRemoteEditor(501, "/srv/a.ts"), term(502)]);
  const s = serializeTabs([tab(split("row", [inner, term(503)]), 503)]);
  check("nested collapse flattens", shape(s[0]), "split(terminal,terminal)");
}

// Nothing left to save: the whole tab goes.
{
  const s = serializeTabs([tab(adHocRemoteEditor(601, "/srv/a.ts"), 601)]);
  check("remote-editor-only tab is dropped", s.length, 0);
}
{
  const s = serializeTabs([
    tab(split("row", [adHocRemoteEditor(701, "/a"), adHocRemoteEditor(702, "/b")]), 701),
  ]);
  check("all-remote split tab is dropped", s.length, 0);
}

console.log("\n[rebind] a profile-bound remote editor must round-trip, minus its session");

/** The single saved leaf of a one-leaf tab. */
function onlyLeaf(t: SavedTab): Extract<SavedPaneNode, { kind: "leaf" }> {
  const n = pane(t).paneTree;
  if (n.kind !== "leaf") throw new Error("expected a single-leaf saved tab");
  return n;
}

// The whole point of the feature: the tab survives a restart.
{
  const s = serializeTabs([tab(savedRemoteEditor(1101, "/srv/a.ts"), 1101)]);
  check("profile-bound remote editor tab is kept", s.length, 1);
  const leaf = onlyLeaf(s[0]);
  check("saved as an editor leaf", leaf.leafKind, "editor");
  check("remote path is preserved", leaf.leafKind === "editor" && leaf.path, "/srv/a.ts");
  check(
    "the reconnectable profile is persisted",
    leaf.leafKind === "editor" && leaf.sshConnectionId,
    "c-prod",
  );
  check(
    "the host label rides along for the waiting pane",
    leaf.leafKind === "editor" && leaf.sshHostLabel,
    "u@h:22",
  );
  // The one thing that must NEVER be written: a live session number is dead on
  // the next launch and the counter restarts, so it can name a different host.
  check(
    "the live session id is NOT persisted",
    "sshSessionId" in leaf ? (leaf as { sshSessionId?: number }).sshSessionId : undefined,
    undefined,
  );
}

// Restore: the leaf comes back remote-but-unbound, never as a local file.
{
  const s = serializeTabs([tab(savedRemoteEditor(1201, "/srv/a.ts"), 1201)]);
  let next = 1;
  const restored = restoreOne(s[0], () => next++);
  if (restored.kind !== "pane" || restored.paneTree.kind !== "leaf") {
    throw new Error("expected a restored single-leaf pane tab");
  }
  const leaf = restored.paneTree;
  check(
    "restored leaf keeps the profile",
    leaf.leafKind === "editor" && leaf.sshConnectionId,
    "c-prod",
  );
  check(
    "restored leaf has no session to read through yet",
    leaf.leafKind === "editor" && leaf.sshSessionId,
    undefined,
  );
  check(
    "restored leaf still knows its host",
    leaf.leafKind === "editor" && leaf.sshHostLabel,
    "u@h:22",
  );
}

// A local editor is untouched by any of this: no remote fields appear.
{
  const s = serializeTabs([tab(editor(1301, "/w/a.ts"), 1301)]);
  const leaf = onlyLeaf(s[0]);
  check(
    "local editor gains no connection id",
    leaf.leafKind === "editor" && leaf.sshConnectionId,
    undefined,
  );
}

// Mixed split: the profile-bound leaf is no longer pruned, so ratios survive.
{
  const s = serializeTabs([
    tab(split("row", [term(1401), savedRemoteEditor(1402, "/srv/a.ts")], [30, 70]), 1402),
  ]);
  check("nothing is pruned", shape(s[0]), "split(terminal,editor)");
  check("divider ratios survive", sizes(s[0]), [30, 70]);
  check("the remote editor is still the active leaf", activeIdx(s[0]), 1);
}

// Ad-hoc and profile-bound leaves in one tab: only the ad-hoc one goes.
{
  const s = serializeTabs([
    tab(
      split("row", [adHocRemoteEditor(1501, "/srv/a.ts"), savedRemoteEditor(1502, "/srv/b.ts")]),
      1502,
    ),
  ]);
  check("only the ad-hoc leaf is pruned", shape(s[0]), "editor");
  check("the surviving leaf is the active one", activeIdx(s[0]), 0);
  check(
    "and it is the profile-bound file",
    onlyLeaf(s[0]).leafKind === "editor" && (onlyLeaf(s[0]) as { path: string }).path,
    "/srv/b.ts",
  );
}

console.log("\n[bind] a restored leaf must resolve its host across every terminal for it");

// How the per-leaf statuses collapse into the one binding a remote editor pane
// reads. Getting this wrong either strands a restored file behind a Reconnect
// button that never clears, or flashes that button on every launch.
{
  const connected = (sessionId: number): SshStatus => ({
    kind: "connected",
    fingerprint: "fp",
    since: 0,
    sessionId,
  });
  const fold = (...statuses: (SshStatus | undefined)[]) =>
    statuses.reduce<SshConnectionBinding | undefined>(
      (acc, s) => foldSshBinding(acc, s),
      undefined,
    );

  check("a connected leaf binds its session", fold(connected(3)), {
    sessionId: 3,
    connecting: false,
  });
  check("no status yet reads as connecting, not as failed", fold(undefined), { connecting: true });
  check("a handshaking leaf reads as connecting", fold({ kind: "connecting", attempt: 1 }), {
    connecting: true,
  });
  check(
    "a failed leaf leaves the connection promptable",
    fold({ kind: "error", message: "x", canRetry: true }),
    { connecting: false },
  );
  check(
    "a disconnected leaf leaves the connection promptable",
    fold({ kind: "disconnected", reason: "x", canRetry: true }),
    { connecting: false },
  );
  // Order independence: whichever leaf is walked first, a live session wins and
  // is never displaced by a dead sibling on the same host.
  check("connected wins over a later failure", fold(connected(4), { kind: "idle" }), {
    sessionId: 4,
    connecting: false,
  });
  check(
    "connected wins over an earlier failure",
    fold({ kind: "error", message: "x", canRetry: true }, connected(5)),
    { sessionId: 5, connecting: false },
  );
  check("two dead leaves stay promptable", fold({ kind: "idle" }, { kind: "idle" }), {
    connecting: true,
  });
}

console.log("\n[mount] a remote pane must never open an editor without a session");

// The invariant that keeps a restored remote file off the local disk. If this
// ever returns a session (or undefined, which means "local") for an unbound
// remote leaf, the pane mounts an editor that reads and then WRITES the remote
// path against this machine.
{
  const leaf = (n: PaneNode) => n as Parameters<typeof editorPaneSession>[0];
  const local = leaf(editor(1601, "/w/a.ts"));
  const remote = leaf(savedRemoteEditor(1602, "/srv/a.ts"));
  const adHoc = leaf(adHocRemoteEditor(1603, "/srv/a.ts"));

  check(
    "a local file reads the local disk",
    editorPaneSession(local, undefined, undefined),
    undefined,
  );
  check("a local file ignores a stray session", editorPaneSession(local, 5, 5), undefined);
  check("a bound remote file reads its session", editorPaneSession(remote, 5, undefined), 5);
  check(
    "an UNBOUND remote file is blocked",
    editorPaneSession(remote, undefined, undefined),
    "blocked",
  );
  check(
    "an unbound ad-hoc remote file is blocked too",
    editorPaneSession(adHoc, undefined, undefined),
    "blocked",
  );
  // Losing the session keeps the editor (and its unsaved buffer) on the dead one.
  check("a dropped session keeps the last binding", editorPaneSession(remote, undefined, 5), 5);
  // A reconnect mints a new session; the pane must follow it, not the old one.
  check("a reconnect adopts the fresh session", editorPaneSession(remote, 9, 5), 9);
}

console.log("\n[active index] savedActiveTabIndex must match what serializeTabs emits");

// The drift this pins: a dropped remote-editor-only tab was counted but never
// emitted, so the saved active index pointed one tab too far.
{
  const remoteTab = tab(adHocRemoteEditor(901, "/srv/a.ts"), 901);
  const paneTab = tab(term(902), 902);
  const tabs = [remoteTab, paneTab];
  check("only the pane tab is emitted", serializeTabs(tabs).length, 1);
  check("index skips the dropped remote-editor tab", savedActiveTabIndex(tabs, paneTab.id), 0);
}

// Non-pane tab kinds were always skipped, including kinds that no longer exist
// (`scm` shipped up to v0.4.22). Guard against a regression, and against an
// unknown kind from a future or older build slipping into the saved layout.
{
  const legacyTab = { id: id(), kind: "scm", title: "scm" } as unknown as Tab;
  const paneTab = tab(term(1002), 1002);
  const tabs = [legacyTab, paneTab];
  check("an unknown tab kind is not emitted", serializeTabs(tabs).length, 1);
  check("index skips the unknown tab", savedActiveTabIndex(tabs, paneTab.id), 0);
}

// 4. A tab renamed from its right-click menu must survive a restart, on every
//    leaf kind that is serialised at all, and clearing it must actually clear -
//    an empty string persisted as a name would restore as a blank tab.
{
  const named = (n: PaneNode, name: string): PaneNode =>
    ({ ...(n as object), customTitle: name }) as PaneNode;
  const t = tab(
    split("row", [
      named(term(1200, "/w/api"), "backend"),
      named(editor(1201, "/w/api/main.rs"), "entrypoint"),
      // `browser` is a saved-only, legacy leaf kind (removed as a live pane in
      // v0.4.22+) - it can never occur in a real `PaneNode`, so the cast, not a
      // widened type, is what's honest here. Same shape as the `scm` legacy-tab
      // cast below: a defunct kind, simulated to prove the serializer still
      // whitelists its `customTitle` rather than dropping it.
      named(
        {
          kind: "leaf",
          id: 1202,
          leafKind: "browser",
          url: "https://x.dev",
        } as unknown as PaneNode,
        "docs",
      ),
    ]),
    1200,
  );
  const savedTree = pane(serializeTabs([t])[0]).paneTree;
  const savedNames =
    savedTree.kind === "split"
      ? savedTree.children.map((c) => (c.kind === "leaf" ? c.customTitle : undefined))
      : [];
  check("a rename persists on terminal, editor and browser leaves", savedNames, [
    "backend",
    "entrypoint",
    "docs",
  ]);

  const restored = restoreOne(serializeTabs([t])[0], () => id());
  const liveNames =
    restored.paneTree.kind === "split"
      ? restored.paneTree.children.map((c) => (c.kind === "leaf" ? c.customTitle : undefined))
      : [];
  check("and comes back on restore", liveNames, ["backend", "entrypoint", "docs"]);

  // An un-renamed leaf must carry no key at all, so older saved state and a
  // reset name are the same thing on disk rather than an empty string.
  const plain = pane(serializeTabs([tab(term(1203, "/w"), 1203)])[0]).paneTree;
  check(
    "an un-renamed leaf persists no name key",
    plain.kind === "leaf" && "customTitle" in plain,
    false,
  );
}

console.log("\n[rdp] an rdp leaf must round-trip its connection id and size mode");

// 5. The whole of an RDP leaf's restorable identity is `rdpConnectionId` +
//    `sizeMode`. Dropping either is silent: the layout still restores, and the
//    pane is simply one that cannot connect (or one that will size itself wrong
//    once a second size mode exists).
{
  const t = tab(split("row", [term(1300), rdp(1301, "r-win-build")]), 1301);
  const s = serializeTabs([t]);
  check("an rdp leaf is saved beside its sibling", shape(s[0]), "split(terminal,rdp)");
  check("the rdp leaf is the active one", activeIdx(s[0]), 1);

  const savedLeaf = (() => {
    const tree = pane(s[0]).paneTree;
    if (tree.kind !== "split") throw new Error("expected a split");
    return tree.children[1];
  })();
  check(
    "the connection id is persisted",
    savedLeaf.kind === "leaf" && savedLeaf.leafKind === "rdp" && savedLeaf.rdpConnectionId,
    "r-win-build",
  );
  check(
    "the size mode is persisted",
    savedLeaf.kind === "leaf" && savedLeaf.leafKind === "rdp" && savedLeaf.sizeMode,
    "preset",
  );
  // An RDP session cannot be reattached, so there must be nothing here that
  // looks like one: a persisted session number would be dead on the next launch
  // and, since the counter restarts at 1, liable to name a different host - the
  // exact failure `sshSessionId` was pruned for in property 1.
  check(
    "and nothing session-shaped is persisted with it",
    savedLeaf.kind === "leaf" && Object.keys(savedLeaf).sort(),
    ["kind", "leafKind", "rdpConnectionId", "sizeMode"],
  );

  const restored = restoreOne(s[0], () => id());
  const liveLeaf =
    restored.paneTree.kind === "split" ? restored.paneTree.children[1] : restored.paneTree;
  check(
    "and both come back on restore",
    liveLeaf.kind === "leaf" && liveLeaf.leafKind === "rdp"
      ? [liveLeaf.rdpConnectionId, liveLeaf.sizeMode]
      : null,
    ["r-win-build", "preset"],
  );

  // A rename has to survive on this kind too, same whitelist, same symptom.
  const named = tab(
    { ...(rdp(1302, "r-dc-01") as object), customTitle: "domain controller" } as PaneNode,
    1302,
  );
  const savedNamed = pane(serializeTabs([named])[0]).paneTree;
  check(
    "a renamed rdp leaf keeps its name",
    savedNamed.kind === "leaf" && savedNamed.customTitle,
    "domain controller",
  );
}

console.log("\n[page] a page leaf round-trips its page value, name and tree shape");

// 6. A page leaf's whole restorable identity is which page it is.
//
// `hosts` throughout, not `vault`: since DCR-1 the only page that may be a tab
// leaf is Hosts, and a saved `vault`/`forwards` leaf is DROPPED on restore rather
// than round-tripped. That migration is `scripts/rail-views-verify.ts`; what is
// checked here is that the surviving kind is unaffected by it.
{
  const t = tab(page(1400, "hosts"), 1400);
  const s = serializeTabs([t]);
  const leaf = onlyLeaf(s[0]);
  check("saved as a page leaf", leaf.leafKind, "page");
  check("the page value is persisted", leaf.leafKind === "page" && leaf.page, "hosts");

  const restored = restoreOne(s[0], () => id());
  const liveLeaf = restored.paneTree;
  check(
    "and comes back on restore",
    liveLeaf.kind === "leaf" && liveLeaf.leafKind === "page" ? liveLeaf.page : null,
    "hosts",
  );
}

// A rename has to survive on this kind too, same whitelist, same symptom.
{
  const named = tab(
    { ...(page(1401, "hosts") as object), customTitle: "tunnels" } as PaneNode,
    1401,
  );
  const savedNamed = onlyLeaf(serializeTabs([named])[0]);
  check(
    "a renamed page leaf keeps its name",
    savedNamed.leafKind === "page" && savedNamed.customTitle,
    "tunnels",
  );
}

// Clearing a name must delete the key, not persist `""` - a blank string would
// restore as a nameless tab. Tested on `page` and not only on `terminal`
// because each kind spells its own `customTitle` spread, so the guard is
// per-kind rather than shared.
{
  const cleared = tab({ ...(page(1404, "hosts") as object), customTitle: "" } as PaneNode, 1404);
  const savedCleared = onlyLeaf(serializeTabs([cleared])[0]);
  check("a cleared page name persists no key", "customTitle" in savedCleared, false);
}

// Inside a split: the tree shape and divider ratios survive around a page
// leaf exactly as they do around any other kind - BOTH directions, since a
// column split is a separate code path in the pane tree.
{
  const t = tab(split("col", [page(1405, "hosts"), term(1406)], [35, 65]), 1405);
  const s = serializeTabs([t]);
  check("a page leaf is saved in a column split", shape(s[0]), "split(page,terminal)");
  check("the column's divider ratios survive", sizes(s[0]), [35, 65]);
  check("the page leaf is the active one", activeIdx(s[0]), 0);

  const restored = restoreOne(s[0], () => id());
  const tree = restored.paneTree;
  check(
    "and the column direction survives restore",
    tree.kind === "split" ? [tree.dir, tree.children.length] : null,
    ["col", 2],
  );
}

{
  const t = tab(split("row", [term(1402), page(1403, "hosts")], [40, 60]), 1403);
  const s = serializeTabs([t]);
  check("a page leaf is saved beside its sibling", shape(s[0]), "split(terminal,page)");
  check("divider ratios survive", sizes(s[0]), [40, 60]);
  check("the page leaf is still the active one", activeIdx(s[0]), 1);

  const restored = restoreOne(s[0], () => id());
  const tree = restored.paneTree;
  check(
    "and the split shape survives restore",
    tree.kind === "split"
      ? tree.children.map((c) => (c.kind === "leaf" ? c.leafKind : "split"))
      : null,
    ["terminal", "page"],
  );
}

// An unrecognised `page` value (a newer build's page, or hand-edited state) must
// not crash restore, and is DROPPED - the same treatment a `vault`/`forwards`
// leaf gets, by the same predicate (`isUnrestorablePageLeaf` asks
// `!isTabPageKind`, so there is no list of known-bad pages to keep in step).
//
// This used to default to Hosts, on the reasoning that `page` is a leaf kind
// this build recognises with a value it does not - the shape of RDP's
// `sizeMode ?? "preset"`. That reasoning does not survive the page leaf becoming
// PERMANENT (`tabs/lib/closable.ts` invariant 1): the fallback minted a SECOND
// Hosts tab, and neither of the two could then be closed. A page leaf holds
// nothing but which page it is, so dropping it loses no state - unlike an RDP
// leaf, where the fallback is the difference between a dialable host and nothing.
// The migration itself is `scripts/rail-views-verify.ts`.
{
  const corrupt = { kind: "leaf", leafKind: "page", page: "snippets" } as unknown as SavedPaneNode;
  check(
    "a tab holding only an unknown page value is dropped, not rewritten to Hosts",
    savedToTab({ kind: "pane", paneTree: corrupt, activeLeafIndex: 0 }, () => id()),
    null,
  );
  // Beside a sibling: the leaf goes, the tab stays, and the split collapses.
  const savedTerm: SavedPaneNode = { kind: "leaf", leafKind: "terminal", cwd: "/w" };
  const withSibling = restoreOne(
    {
      kind: "pane",
      paneTree: { kind: "split", dir: "row", children: [savedTerm, corrupt] },
      activeLeafIndex: 1,
    },
    () => id(),
  );
  check(
    "beside a terminal, only the unknown page leaf is dropped",
    withSibling.paneTree.kind === "leaf" ? withSibling.paneTree.leafKind : "split",
    "terminal",
  );
}

console.log(
  "\n[switch] switching to (or creating) an empty workspace opens Hosts, not a shell; a saved one restores untouched",
);

// `tabsForWorkspaceEntry` is decision 9's runtime counterpart to
// `useWorkspacePersistence`'s startup fallback, and the single resolver both
// `switchToWorkspace` and `closeWorkspace` go through. It lives in serialize.ts
// (not beside those callers in `useWorkspaceSwitching`, whose module pulls in
// `@xterm/xterm` and so cannot be imported outside a bundler) precisely so it
// can be exercised here for real, rather than pinned by grepping the hook's
// source - a test that reddens on a pure refactor and stays green on a
// regression in the function itself.
{
  let n = 1;
  const allocId = () => n++;

  const empty = tabsForWorkspaceEntry({ tabs: [] }, allocId);
  check("an empty workspace's fallback is a single tab", empty.length, 1);
  const emptyLeaf = empty[0].paneTree;
  check(
    "and it is a Hosts page leaf, not a terminal",
    emptyLeaf.kind === "leaf" && emptyLeaf.leafKind === "page" ? emptyLeaf.page : null,
    "hosts",
  );

  const saved = serializeTabs([tab(term(1701), 1701), tab(page(1702, "hosts"), 1702)]);
  const restored = tabsForWorkspaceEntry({ tabs: saved }, allocId);
  check(
    "a workspace with saved tabs restores the same leaf kinds untouched",
    restored.map((t) => (t.paneTree.kind === "leaf" ? t.paneTree.leafKind : "split")),
    ["terminal", "page"],
  );
  check("and the fallback is not prepended to them", restored.length, 2);
}

// The fallback tab has to survive a restart like any other tab: it is
// snapshotted on the first save, so a page leaf that failed to round-trip would
// turn a fresh profile's only tab into an empty terminal on the next launch -
// silently reintroducing exactly the shell that decision 9 replaced.
{
  let n = 1;
  const allocId = () => n++;
  const s = serializeTabs([defaultHostsTab(allocId)]);
  check("the fallback tab is persisted", s.length, 1);
  const back = restoreOne(s[0], allocId);
  const backLeaf = back.paneTree;
  check(
    "and comes back as the same Hosts page",
    backLeaf.kind === "leaf" && backLeaf.leafKind === "page" ? backLeaf.page : null,
    "hosts",
  );
  check("with its title intact", back.title, "Hosts");
}

console.log(
  "\n[close] a leaf is unclosable only when it is the last thing on screen, not the last terminal",
);

// 8. The proxy that broke in 6c. `isLastEntryInWorkspace` is what both close
// paths ask: `handleLeafExit` respawns exactly here (and closes everywhere
// else), and it is the one close `closePaneByLeaf` refuses. Answering "is this
// the last TERMINAL" instead resurrected a shell the user had just `exit`ed
// whenever a Hosts tab was the other thing on screen.
{
  const hostsTab = tab(page(1801, "hosts"), 1801);
  const termTab = tab(term(1802), 1802);

  check("a lone leaf is the last thing on screen", isLastEntryInWorkspace([termTab], 1802), true);
  // The regression: one terminal, one Hosts page. Zero OTHER terminals, so the
  // old guard respawned; but the window keeps the Hosts page, so it must close.
  check(
    "the only terminal is closable when a page tab is also open",
    isLastEntryInWorkspace([hostsTab, termTab], 1802),
    false,
  );
  check(
    "and the page leaf beside it is closable too",
    isLastEntryInWorkspace([hostsTab, termTab], 1801),
    false,
  );
  // A lone page tab is the last thing on screen just as a lone terminal is:
  // "last entry" is about the window emptying, not about which kind it holds.
  check(
    "a lone page leaf is the last thing on screen too",
    isLastEntryInWorkspace([hostsTab], 1801),
    true,
  );
  // Two panes in ONE tab: the tab list is length 1, so a tabs-only count would
  // wrongly refuse this close.
  const splitTab = tab(split("row", [term(1803), page(1804, "hosts")]), 1803);
  check(
    "a pane in a split is never the last thing on screen",
    isLastEntryInWorkspace([splitTab], 1803),
    false,
  );
  // A leaf that is not on screen at all must not be mistaken for the last one,
  // or a stale exit event would respawn a shell into a workspace it left.
  check(
    "an unknown leaf id is not the last thing on screen",
    isLastEntryInWorkspace([termTab], 9999),
    false,
  );
  // The oracle underneath, and the count the broken guard should have used: a
  // Hosts tab plus a terminal is TWO things on screen, not one.
  check("a page tab and a terminal tab are two entries", countTabEntries([hostsTab, termTab]), 2);
  check("a two-pane split is two entries", countTabEntries([splitTab]), 2);
}

// `throw` (not process.exit) for a non-zero exit, matching the other verify scripts.
if (failures > 0) throw new Error(`workspace-serialize-verify: ${failures} FAILED`);
console.log("\nworkspace-serialize-verify: OK\n");
