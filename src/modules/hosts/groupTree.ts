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
// vanishing or hanging a walk. `groupChain`, by contrast, is what
// `upsertGroup` uses to REFUSE writing one of those in the first place, on the
// pattern `jumps.ts`'s `jumpChain` already set for a jump-host chain.

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
 * absent, names no group in `byId`, or the chain followed from here repeats an
 * id before it reaches a group with none.
 *
 * Self-reference and a two-group cycle are both a repeat, of length one and
 * two. A group hanging off a cycle it is not itself part of also lands at
 * root here: nothing walking outward from it can give it a finite depth
 * either, so treating only the cycle's own members as root would leave this
 * one's ancestor walk looping forever the first time something tries to read
 * it.
 */
function effectiveParentId(id: string, byId: ReadonlyMap<string, HostGroup>): string | undefined {
  const raw = byId.get(id)?.parentId;
  if (raw === undefined) return undefined;
  const seen = new Set<string>([id]);
  let cursor: string | undefined = raw;
  while (cursor !== undefined) {
    if (seen.has(cursor)) return undefined;
    const target = byId.get(cursor);
    if (!target) return undefined;
    seen.add(cursor);
    cursor = target.parentId;
  }
  return raw;
}

/**
 * Every group's own immediate parent, resolved by {@link effectiveParentId}.
 * The map form {@link buildGroupTree} groups children by, and what
 * `modules/backup/file.ts`'s `orderGroupWrites` walks to decide which of an
 * import's rows has to be WRITTEN first - `upsertGroup` checks a `parentId`
 * against whatever is already on disk, so a parent that is itself new in the
 * same file must land before the child naming it.
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
 * `page/derive.ts`'s `groupCounts` sums it bottom-up.
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

function collectIds(node: GroupNode, into: Set<string>): void {
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
 * effective-parent resolution. Two callers: `page/derive.ts`'s
 * `matchesGroupFilter` - selecting a group means "this group and its
 * descendants" - and `GroupStrip.tsx`'s "Move to…" picker, which must exclude
 * a group's own descendants or `groupChain` would refuse the move as a cycle
 * anyway. Empty when `groupId` names no group in `groups`.
 */
export function descendantIds(groupId: string, groups: readonly HostGroup[]): ReadonlySet<string> {
  const node = findNode(buildGroupTree(groups), groupId);
  const ids = new Set<string>();
  if (node) collectIds(node, ids);
  return ids;
}

/**
 * The chain from `startParentId` outward, collected `[nearest, ..., root]`.
 * Cycle detection is seeded with `selfId`, so a group reparented into a cycle
 * that runs back through itself throws instead of looping - `upsertGroup`'s
 * refusal, on the SAME pattern `jumps.ts`'s `jumpChain` already set for a
 * jump-host chain, including the one thing a same-record immediate check
 * cannot: A -> B -> A, which would otherwise save on both sides and only fail
 * once something tries to render it.
 */
export function groupChain(
  startParentId: string | undefined,
  selfId: string | undefined,
  groups: readonly HostGroup[],
): HostGroup[] {
  if (!startParentId) return [];
  const byId = new Map(groups.map((g) => [g.id, g]));
  const visited = new Set<string>();
  if (selfId) visited.add(selfId);
  const chain: HostGroup[] = [];
  let cursor: string | undefined = startParentId;
  while (cursor) {
    if (visited.has(cursor)) throw new Error("hosts: group parent chain has a cycle");
    visited.add(cursor);
    const hop = byId.get(cursor);
    if (!hop) throw new Error("hosts: a parent group in the chain no longer exists");
    chain.push(hop);
    cursor = hop.parentId;
  }
  return chain;
}
