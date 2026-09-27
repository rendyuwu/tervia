import { IS_WINDOWS } from "@/lib/platform";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useEffect } from "react";
import { findLeafIdFromPoint, writeToLeaf } from "./useTerminalSession";

// Two drop pathways into terminal PTYs, both ending in `writeToLeaf`:
//
//   1. OS-level file drops from outside the WebView (file manager, etc).
//      Captured by Tauri (`dragDropEnabled: true` by default) and emitted
//      as `tauri://drag-drop`. Handled by `useTerminalFileDrop` below
//      with screen-coordinate hit-testing via `findLeafIdFromPoint`.
//   2. Internal drops from a Tervia file explorer row → terminal pane.
//      Synthesized from raw mouse events by `ensureFsDragListener`
//      (HTML5 drag-drop is unreliable inside the WebView because the
//      Tauri intercept consumes drag events before HTML sees them).
//
// `quoteForShell` is shared by both paths and the only OS-specific bit
// in this file. PowerShell + cmd accept double-quoted paths on Windows;
// POSIX shells use single quotes with the `'\''` close-escape-open trick.

export function quoteForShell(path: string): string {
  if (IS_WINDOWS) {
    // PowerShell and cmd both accept double-quoted paths; embedded `"` is escaped as `""`.
    if (!/[\s"&^%!()<>|,;=]/.test(path)) return path;
    return `"${path.replace(/"/g, '""')}"`;
  }
  // POSIX: single-quote, escape embedded single quotes via `'\''`.
  if (!/[\s"'\\$`!*?(){}[\];<>|&#~]/.test(path)) return path;
  return `'${path.replace(/'/g, `'\\''`)}'`;
}

// Module-scope guards.
let fsDragBridgeAttached = false;
let dragStyleInjected = false;

/**
 * Synthetic mouse-based "drag" for internal fs-path drops into terminal.
 *
 * Why mouse events instead of HTML5 drag-drop? Tauri 2's default
 * `dragDropEnabled: true` installs an OS-level drag-drop target on the
 * WebView (so it can emit `tauri://drag-drop` for external file drops).
 * The native intercept consumes drag events before the WebView's HTML
 * engine sees them, so HTML5 `dragstart`/`dragover`/`drop` either don't
 * fire reliably or show the "not allowed" cursor because the WebView
 * can't preventDefault on events it never received.
 *
 * Mouse events (`mousedown` / `mousemove` / `mouseup`) aren't part of
 * the drag-drop intercept surface; they fire normally regardless of
 * Tauri's setting. We synthesize a drag gesture:
 *
 *   - `mousedown` on `data-fs-path="<abs path>"` arms the source.
 *   - `mousemove` past a 5 px threshold activates drag mode (cursor +
 *     drop-target outline via `tervia-fs-dragging`).
 *   - `mouseup` over `data-terminal-leaf-id` writes the shell-quoted
 *     path into that PTY.
 *   - A Remote (`data-sftp-tree`) row released over another row of its tree
 *     or its empty body dispatches `FS_ROW_DROP_EVENT` (a move), and over a
 *     local Files (`data-fs-tree`) row or empty body the same event (a
 *     download). A local Files row released over a Remote row or empty body
 *     dispatches it too (an upload). The SSH explorer handles all three.
 *   - `mouseup` elsewhere, back on the source row, or `Escape` cancels.
 *
 * Tradeoff: no native ghost preview under the cursor (browser only
 * draws ghosts for HTML5 drags). We compensate with a body-level
 * `cursor: copy` and an outline on the drop target under the cursor.
 * A drag out to the OS file manager is not supported (see the SFTP
 * entry in `KNOWN-LIMITS.md`).
 *
 * The OS-level file drop path is unchanged. `useTerminalFileDrop`
 * still handles `tauri://drag-drop` for files dragged from outside.
 */
const DRAG_ACTIVATION_PX = 5;

/** Bubbles from a Remote tree body when a row is dropped on a move, download
 *  or upload target. `upload` is set at mousedown (a local Files source), so a
 *  Remote row re-rendered mid-drag still routes as a move or download. */
export const FS_ROW_DROP_EVENT = "tervia:fs-row-drop";
export type FsRowDropDetail = { from: string; target: HTMLElement; upload: boolean };

type SyntheticDragState = {
  path: string;
  startX: number;
  startY: number;
  active: boolean;
  currentTarget: HTMLElement | null;
  /** The row the drag started on. */
  source: HTMLElement;
  /** The Remote tree body the source row sits in, null for any other row. */
  tree: HTMLElement | null;
};

/** The drop target under a point: a terminal pane for any source; for a Remote
 *  source also a row or the body of its own tree (move) or of the local Files
 *  tree (download); for a local source also a row or the body of a Remote tree
 *  (upload). A local row over its own tree has no target. */
function dropTargetAt(x: number, y: number, d: SyntheticDragState): HTMLElement | null {
  const under = document.elementFromPoint(x, y);
  if (!under) return null;
  const leaf = under.closest<HTMLElement>("[data-terminal-leaf-id]");
  if (leaf) return leaf;
  const tree = d.tree?.contains(under)
    ? d.tree
    : under.closest<HTMLElement>(d.tree ? "[data-fs-tree]" : "[data-sftp-tree]");
  if (!tree) return null;
  const row = under.closest<HTMLElement>("[data-fs-path]");
  return row === d.source ? null : (row ?? tree);
}

function injectFsDragStyle(): void {
  if (dragStyleInjected) return;
  if (typeof document === "undefined") return;
  // Belt-and-suspenders for Vite HMR: module-scope guards reset on
  // hot reload but the previously-injected `<style>` survives in the
  // DOM. A DOM check prevents accumulating duplicate tags during dev.
  if (document.querySelector('style[data-tervia-fs-drag="1"]')) {
    dragStyleInjected = true;
    return;
  }
  dragStyleInjected = true;
  const style = document.createElement("style");
  style.setAttribute("data-tervia-fs-drag", "1");
  style.textContent = `
body.tervia-fs-dragging,
body.tervia-fs-dragging * {
  cursor: copy !important;
  user-select: none !important;
}
body.tervia-fs-dragging .tervia-fs-drop-target {
  outline: 2px solid var(--ring, #3b82f6);
  outline-offset: -2px;
  transition: outline-color 80ms;
}
`;
  document.head.appendChild(style);
}

export function ensureFsDragListener(): void {
  if (fsDragBridgeAttached) return;
  if (typeof document === "undefined") return;
  fsDragBridgeAttached = true;
  injectFsDragStyle();

  let drag: SyntheticDragState | null = null;

  const clearDropTarget = (): void => {
    if (drag?.currentTarget) {
      drag.currentTarget.classList.remove("tervia-fs-drop-target");
      drag.currentTarget = null;
    }
  };

  const reset = (): void => {
    clearDropTarget();
    drag = null;
    document.body.classList.remove("tervia-fs-dragging");
  };

  document.addEventListener(
    "mousedown",
    (e: MouseEvent) => {
      if (e.button !== 0) return; // left-button only
      // Defensive: clear any stale drag state from a previous gesture
      // whose `mouseup` was missed (e.g. user released the button
      // outside the window on some platforms). Without this the body
      // class could stay stuck and a fresh click would inherit weird
      // visual state.
      if (drag) reset();
      const target = e.target as HTMLElement | null;
      const el = target?.closest?.<HTMLElement>("[data-fs-path]");
      if (!el) return;
      const path = el.getAttribute("data-fs-path");
      if (!path) return;
      drag = {
        path,
        startX: e.clientX,
        startY: e.clientY,
        active: false,
        currentTarget: null,
        source: el,
        tree: el.closest<HTMLElement>("[data-sftp-tree]"),
      };
    },
    true,
  );

  document.addEventListener(
    "mousemove",
    (e: MouseEvent) => {
      if (!drag) return;
      if (!drag.active) {
        const dx = e.clientX - drag.startX;
        const dy = e.clientY - drag.startY;
        if (dx * dx + dy * dy < DRAG_ACTIVATION_PX * DRAG_ACTIVATION_PX) return;
        drag.active = true;
        document.body.classList.add("tervia-fs-dragging");
      }
      // Highlight the drop target under the cursor. `elementFromPoint`
      // is more reliable than `e.target` here because the cursor may be
      // over an element our `mousemove` listener doesn't bubble to
      // (e.g. xterm internal layers).
      const targetEl = dropTargetAt(e.clientX, e.clientY, drag);
      if (targetEl !== drag.currentTarget) {
        drag.currentTarget?.classList.remove("tervia-fs-drop-target");
        drag.currentTarget = targetEl;
        targetEl?.classList.add("tervia-fs-drop-target");
      }
    },
    true,
  );

  document.addEventListener(
    "mouseup",
    (e: MouseEvent) => {
      if (!drag) return;
      const d = drag;
      const wasActive = d.active;
      const path = d.path;
      const lastTarget = d.currentTarget;
      // Any button release ends the gesture and clears `tervia-fs-dragging` FIRST,
      // so the body class (which forces cursor:copy + user-select:none app-wide)
      // can never get stuck if the terminating release isn't the left button
      // (chorded click, or a WebView2 quirk). Only a left-button release over a
      // terminal or another drop target commits a drop; a right-click mid-drag
      // still just cancels.
      reset();
      if (e.button !== 0) return;
      // Below the activation threshold → treat as a click; let onClick
      // on the source row run normally (we never preventDefault on
      // mousedown, so the click event still fires).
      if (!wasActive) return;
      // Resolve the target at release time in case the cursor moved off the
      // highlighted one in the final frame. Only a local row falls back to the
      // last frame's target, and only to a terminal: a stale Remote row must not
      // take an upload, and a Remote row released over nothing, or back on
      // itself, does nothing.
      const target =
        dropTargetAt(e.clientX, e.clientY, d) ??
        (d.tree === null && lastTarget?.hasAttribute("data-terminal-leaf-id") ? lastTarget : null);
      if (!target) return;
      const leafIdAttr = target.getAttribute("data-terminal-leaf-id");
      if (leafIdAttr !== null) {
        const leafId = Number(leafIdAttr);
        if (Number.isNaN(leafId)) return;
        writeToLeaf(leafId, quoteForShell(path));
        return;
      }
      // A move or download goes to the source's Remote tree, an upload to the
      // target's; `SshFileExplorer` tells them apart.
      (d.tree ?? target.closest<HTMLElement>("[data-sftp-tree]"))?.dispatchEvent(
        new CustomEvent<FsRowDropDetail>(FS_ROW_DROP_EVENT, {
          bubbles: true,
          detail: { from: path, target, upload: d.tree === null },
        }),
      );
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e: KeyboardEvent) => {
      if (e.key === "Escape" && drag) reset();
    },
    true,
  );

  // Cancel if the gesture is interrupted - focus loss / alt-tab (blur), a
  // cancelled pointer, or the window being hidden/minimized - so the body class
  // never gets stuck. (HTML5 `dragend` is intentionally not used: Tauri's
  // dragDropEnabled intercept consumes drag events, so it would never fire.)
  const hardReset = () => {
    if (drag) reset();
  };
  window.addEventListener("blur", hardReset);
  document.addEventListener("pointercancel", hardReset, true);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) hardReset();
  });
}

export function useTerminalFileDrop(): void {
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    getCurrentWebviewWindow()
      .onDragDropEvent((event) => {
        if (event.payload.type !== "drop") return;
        const { position, paths } = event.payload;
        if (!paths || paths.length === 0) return;
        // `position` is in physical pixels; `elementFromPoint` wants CSS pixels.
        const dpr = window.devicePixelRatio || 1;
        const x = position.x / dpr;
        const y = position.y / dpr;
        const leafId = findLeafIdFromPoint(x, y);
        if (leafId == null) return;
        const text = paths.map(quoteForShell).join(" ");
        writeToLeaf(leafId, text);
      })
      .then((un) => {
        if (cancelled) un();
        else unlisten = un;
      })
      .catch((err) => console.error("terminal drag-drop listen failed:", err));

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);
}
