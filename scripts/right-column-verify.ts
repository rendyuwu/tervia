/**
 * Self-check for the stacked right column.
 * Run: `npx tsx scripts/right-column-verify.ts`.
 *
 * Two invariants, both of which used to be enforced by the fact that the column
 * could only ever hold ONE thing:
 *
 *  1. The right-column store is a SET of open sections. Opening a second one
 *     must not evict the first (that was the whole point of the change), opening
 *     the same one twice must not duplicate it, and closing one must leave its
 *     neighbours alone.
 *  2. The persisted drag order is reconciled, not trusted: sections come and go
 *     (a section is docked from the other side, a panel is closed), so a stale
 *     key must be dropped and an unknown one appended without disturbing the
 *     arrangement the user dragged into place.
 */
import { isMovableSection, useSidebarPlacementStore } from "../src/modules/rightPanel/placement";
import { isRightSectionOpen, useRightColumnStore } from "../src/modules/rightPanel/store";
import { reconcileSectionOrder } from "../src/app/lib/sectionOrder";

let failed = 0;
function check(name: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${name}`);
    return;
  }
  console.error(`  FAIL: ${name}`, detail === undefined ? "" : JSON.stringify(detail));
  failed++;
}

const store = useRightColumnStore;
const ids = () => store.getState().open;

console.log("[store] several sections share the column");
store.getState().openSection("files");
store.getState().openSection("workspaces");
check("opening a second section keeps the first", ids().length === 2, ids());
check("order is open-order", ids().join(",") === "files,workspaces", ids());
store.getState().openSection("files");
check("opening an already-open section is a no-op", ids().length === 2, ids());
check("isRightSectionOpen finds a member", isRightSectionOpen(ids(), "workspaces"));

console.log("\n[store] closing is per-section");
store.getState().closeSection("files");
check("the named section closes", !isRightSectionOpen(ids(), "files"));
check("its neighbour survives", isRightSectionOpen(ids(), "workspaces"), ids());
store.getState().closeSection("files");
check("closing an already-closed section is a no-op", ids().length === 1, ids());

console.log("\n[store] toggle round-trips");
store.getState().toggleSection("files");
check("toggle opens", isRightSectionOpen(ids(), "files"));
store.getState().toggleSection("files");
check("toggle closes", !isRightSectionOpen(ids(), "files"));
check("and only that one", ids().join(",") === "workspaces", ids());

console.log("\n[order] a persisted arrangement survives sections coming and going");
check(
  "persisted order wins over the caller's order",
  reconcileSectionOrder(["ssh", "files"], ["files", "ssh"]).join(",") === "ssh,files",
);
check(
  "a key that no longer exists is dropped, not rendered as a hole",
  reconcileSectionOrder(["ssh", "gone", "files"], ["files", "ssh"]).join(",") === "ssh,files",
);
check(
  "a new key is APPENDED, so opening a panel never reshuffles the rest",
  reconcileSectionOrder(["ssh", "files"], ["files", "ssh", "workspaces"]).join(",") ===
    "ssh,files,workspaces",
);
check(
  "no persisted order yet -> the caller's order verbatim",
  reconcileSectionOrder([], ["workspaces", "ssh"]).join(",") === "workspaces,ssh",
);
check(
  // A repeat would be a duplicate React key, two dnd-kit items on one id, and
  // two resizable panels on one id.
  "a repeated key in a corrupt persisted value renders once",
  reconcileSectionOrder(["ssh", "ssh"], ["ssh", "files"]).join(",") === "ssh,files",
  reconcileSectionOrder(["ssh", "ssh"], ["ssh", "files"]),
);

console.log("\n[placement] a section docks right and comes back");
for (const key of ["files", "workspaces"] as const) {
  const placement = useSidebarPlacementStore;
  placement.getState().moveRight(key);
  check(`${key}: moveRight marks it right`, placement.getState().placement[key] === "right");
  check(`${key}: docking starts it open`, placement.getState().rightOpen[key] === true);
  // The drag back is keyed by the same section id the dock used - miss this and
  // the section drags left-to-right but not back.
  check(`${key}: is recognised as movable`, isMovableSection(key));
  placement.getState().moveLeft(key);
  check(`${key}: moveLeft marks it left`, placement.getState().placement[key] === "left");
}
check("a key that is not a movable section is rejected", !isMovableSection("ssh"));

if (failed > 0) throw new Error(`${failed} check(s) FAILED`);
console.log("\nALL PASS");
