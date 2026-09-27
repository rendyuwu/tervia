import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useEffect, useRef, type RefObject } from "react";
import { treeDropDir } from "./remotePath";

// OS drag-and-drop onto the SSH file tree. Rides Tauri's `tauri://drag-drop`
// (the same OS-level target the terminal file-drop uses); we hit-test the drop
// point against this panel's rows so a drop meant for a terminal or another
// surface is ignored. A drop on a folder row targets it, on a file row its
// parent dir, on empty tree area the root. The upload itself is `onDrop`'s.

type Params = {
  sessionId: number | null;
  rootPath: string | null;
  containerRef: RefObject<HTMLElement | null>;
  /** OS files dropped onto the panel, with the remote folder they target. */
  onDrop: (paths: string[], remoteDir: string) => void;
};

export function useSshFileDrop({ sessionId, rootPath, containerRef, onDrop }: Params): void {
  // Latest callback kept in a ref so the Tauri listener subscribes once per
  // session/root instead of re-subscribing on every tree re-render (which
  // could drop an in-flight drag event).
  const onDropRef = useRef(onDrop);
  onDropRef.current = onDrop;

  useEffect(() => {
    if (sessionId === null || !rootPath) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    const highlight = (on: boolean) => {
      const el = containerRef.current;
      if (!el) return;
      // Inline outline avoids any CSS plumbing; cleared by passing "".
      el.style.outline = on ? "2px solid var(--ring)" : "";
      el.style.outlineOffset = on ? "-2px" : "";
    };

    // Remote directory under a window point (physical px, as Tauri reports),
    // or null when the point isn't over this panel.
    const dirAtPoint = (physX: number, physY: number): string | null => {
      const dpr = window.devicePixelRatio || 1;
      const under = document.elementFromPoint(physX / dpr, physY / dpr) as HTMLElement | null;
      const container = containerRef.current;
      if (!under || !container || !container.contains(under)) return null;
      return treeDropDir(under.closest("[data-fs-path]"), rootPath);
    };

    getCurrentWebviewWindow()
      .onDragDropEvent((event) => {
        const payload = event.payload;
        if (payload.type === "leave") {
          highlight(false);
          return;
        }
        if (payload.type === "enter" || payload.type === "over") {
          highlight(dirAtPoint(payload.position.x, payload.position.y) !== null);
          return;
        }
        if (payload.type !== "drop") return;
        highlight(false);
        const { position, paths } = payload;
        if (!paths || paths.length === 0 || sessionId === null) return;
        const dir = dirAtPoint(position.x, position.y);
        if (dir === null) return; // dropped elsewhere (e.g. a terminal)
        onDropRef.current(paths, dir);
      })
      .then((un) => {
        if (cancelled) un();
        else unlisten = un;
      })
      .catch((err) => console.error("ssh drag-drop listen failed:", err));

    return () => {
      cancelled = true;
      highlight(false);
      unlisten?.();
    };
  }, [sessionId, rootPath, containerRef]);
}
