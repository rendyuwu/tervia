import type { HostGroup } from "./types";

// The read-time shape of the group list as a forest, and the one place that
// walk lives - `GroupStrip.tsx`'s tree render, `page/derive.ts`'s
// descendant-aware filter and counts, `store.ts`'s write-time cycle check, and
// `modules/backup/file.ts`'s import write order all build on this rather than
// each walking `parentId` on its own.
//
// Sync can deliver a `parentId` two devices never agreed on: naming a group
// this device deleted, naming itself, or - two devices reparenting the same
// pair in opposite directions - a cycle. `effectiveParents` is the read-time
// tolerance for all three: the offending group resolves to root instead of
// vanishing or hanging a walk. `store.ts`'s `upsertGroup` is what REFUSES
// writing one of those in the first place, checking the candidate write
// against this same resolution rather than a second, stricter walk.

/** One node in the forest {@link buildGroupTree} returns. */
export type GroupNode = {
  group: HostGroup;
  children: GroupNode[];
};

/** Ordered groups first (by `order`, ascending), then unordered ones by name -
 *  the rule `GroupStrip.tsx`'s old flat list used, applied at every depth here
 *  so sibling order stays stable regardless of the array's incoming order. */
function byOrderThenName(a: HostGroup, b: HostGroup): number {
  if (a.order !== undefined && b.order !== undefined) return a.order - b.order;
  if (a.order !== undefined) return -1;
  if (b.order !== undefined) return 1;
  return a.name.localeCompare(b.name);
}

/**
 * This group's resolved parent id, or `undefined` (root) when `parentId` is
 * absent, names no group in `byId`, or `id` itself sits on the cycle reached
 * by walking up from its own parent.
 *
 * Only `id`'s OWN parent is checked for existing; a group further up an
 * otherwise-valid chain that happens to be missing does not pull THIS
 * group to root too - it keeps its raw `parentId`, so a bad ancestor does
 * not flatten every descendant beneath it. Likewise, only a group ON the
 * cycle (the walk from its own parent comes back to `id`) resolves to
 * root; a group that merely HANGS OFF a cycle member keeps that member as
 * its parent, the same way it would keep any other valid parent.
 */
function effectiveParentId(id: string, byId: ReadonlyMap<string, HostGroup>): string | undefined {
  const raw = byId.get(id)?.parentId;
  if (raw === undefined || !byId.has(raw)) return undefined;
  const seen = new Set<string>();
  for (
    let cursor: string | undefined = raw;
    cursor !== undefined && !seen.has(cursor);
    cursor = byId.get(cursor)?.parentId
  ) {
    if (cursor === id) return undefined;
    seen.add(cursor);
  }
  return raw;
}

/**
 * Every group's own immediate parent, resolved by {@link effectiveParentId}.
 * The map form {@link buildGroupTree} groups children by, and what
 * `modules/backup/file.ts`'s `orderGroupWrites` walks to decide which of an
 * import's rows has to be WRITTEN first - `upsertGroup` checks a `parentId`
 * against whatever is already on disk, so a parent that is itself new in the
 * same file must land before the child naming it. The cross-device merge
 * caveat this resolves at read time is recorded in `KNOWN-LIMITS.md`.
 */
export function effectiveParents(
  groups: readonly HostGroup[],
): ReadonlyMap<string, string | undefined> {
  const byId = new Map(groups.map((g) => [g.id, g]));
  return new Map(groups.map((g) => [g.id, effectiveParentId(g.id, byId)]));
}

/**
 * The group list as a forest, children ordered under each parent by
 * {@link byOrderThenName}. `GroupStrip.tsx` renders this directly;
 * `page/derive.ts`'s `groupCounts` sums it bottom-up. `KNOWN-LIMITS.md`
 * carries the same cross-device merge caveat {@link effectiveParents} does.
 */
export function buildGroupTree(groups: readonly HostGroup[]): GroupNode[] {
  const parents = effectiveParents(groups);
  const childrenOf = new Map<string | undefined, HostGroup[]>();
  for (const group of groups) {
    const parentId = parents.get(group.id);
    const list = childrenOf.get(parentId);
    if (list) list.push(group);
    else childrenOf.set(parentId, [group]);
  }
  function build(parentId: string | undefined): GroupNode[] {
    return (childrenOf.get(parentId) ?? [])
      .sort(byOrderThenName)
      .map((group) => ({ group, children: build(group.id) }));
  }
  return build(undefined);
}

/** `node`'s own id plus every id in its subtree, collected into `into`.
 *  Exported for `GroupStrip.tsx`'s "Move to…" picker, which already has the
 *  node in hand from the tree it renders and so has no reason to re-find it
 *  through {@link descendantIds}. */
export function collectIds(node: GroupNode, into: Set<string>): void {
  into.add(node.group.id);
  for (const child of node.children) collectIds(child, into);
}

function findNode(nodes: readonly GroupNode[], id: string): GroupNode | undefined {
  for (const node of nodes) {
    if (node.group.id === id) return node;
    const found = findNode(node.children, id);
    if (found) return found;
  }
  return undefined;
}

/**
 * `groupId` itself plus every id in its subtree, by {@link buildGroupTree}'s
 * effective-parent resolution. Used by `page/derive.ts`'s
 * `matchesGroupFilter` - selecting a group means "this group and its
 * descendants". Empty when `groupId` names no group in `groups`.
 */
export function descendantIds(groupId: string, groups: readonly HostGroup[]): ReadonlySet<string> {
  const node = findNode(buildGroupTree(groups), groupId);
  const ids = new Set<string>();
  if (node) collectIds(node, ids);
  return ids;
}
