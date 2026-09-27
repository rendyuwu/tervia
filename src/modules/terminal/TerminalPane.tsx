import { readClipboardText } from "@/lib/clipboard";
import { usePreferencesStore } from "@/modules/settings/preferences";
import { useTheme } from "@/modules/theme";
import type { SearchAddon } from "@xterm/addon-search";
import { useEffect, useImperativeHandle, useRef, type Ref } from "react";
import {
  useTerminalSession,
  type TerviaOpenInput,
  type TerviaSpawnTabInput,
} from "./lib/useTerminalSession";
import type { SshStatus } from "@/modules/ssh/status";
import type { AiCliKind, AiCliStatus } from "./lib/aiCliStatus";

export type TerminalPaneHandle = {
  write: (data: string) => void;
  /** Run an AI CLI here and tag the pane as running `tool` (null = no badge).
   *  See `useTerminalSession.launchAgent` for why the tag must be explicit. */
  launchAgent: (command: string, tool: AiCliKind | null) => void;
  focus: () => void;
  getBuffer: (maxLines?: number) => string | null;
  getSelection: () => string | null;
  /** Bracketed-paste-aware insert. Prevents multi-line snippets from auto-executing under bash/zsh. */
  paste: (data: string) => void;
  /** True when the cursor sits on a shell prompt (PS1/zsh/pwsh/cmd) on the
   *  normal screen, i.e. safe for the AI to inject a command. False on the
   *  alt-screen (TUI app) or mid-command-output. */
  isAtPrompt: () => boolean;
  /** True when a foreground command is genuinely running (alt-screen TUI or
   *  an in-flight OSC 133 command). Prompt-text independent, so an idle
   *  terminal never reports busy. Backs the close-confirmation modal. */
  isProcessRunning: () => boolean;
};

type Props = {
  /** Leaf identifier passed back through callbacks. */
  leafId: number;
  /** Tab containing this pane is on screen. */
  visible: boolean;
  /** Active pane within its tab. Receives auto-focus. */
  focused?: boolean;
  initialCwd?: string;
  /** When set, opens an SSH session instead of a local PTY. */
  hostId?: string;
  /**
   * Daemon-side PTY UUID from a previously saved workspace. The terminal
   * session tries `pty_attach` first and falls back to a fresh spawn on
   * failure. Forwarded to `useTerminalSession`.
   */
  savedPtyId?: string;
  /**
   * AI CLI kind that was running when the workspace was last saved. Forwarded
   * to `useTerminalSession` to pre-activate the detector on reattach so a
   * still-running agent's badge resumes immediately.
   */
  savedActiveTool?: AiCliKind;
  /**
   * Per-leaf terminal theme override id (a `TERMINAL_PRESETS` id). When set,
   * this pane paints its own palette regardless of the global terminal theme.
   * Set from the pane header's right-click "Terminal theme" menu.
   */
  terminalThemeId?: string;
  onSearchReady?: (leafId: number, addon: SearchAddon) => void;
  onExit?: (leafId: number, code: number) => void;
  onCwd?: (leafId: number, cwd: string) => void;
  onDetectedLocalUrl?: (leafId: number, url: string) => void;
  onTerviaOpen?: (leafId: number, input: TerviaOpenInput) => void;
  onTerviaSpawnTab?: (leafId: number, input: TerviaSpawnTabInput) => void;
  onSshStatus?: (leafId: number, status: SshStatus) => void;
  onAiCliStatus?: (leafId: number, status: AiCliStatus) => void;
  /**
   * Fires once whenever the daemon hands back a session UUID. Caller
   * (the pane stack consumer) writes it into the leaf so the workspace
   * serializer persists it for restore on next launch.
   */
  onPtyId?: (leafId: number, ptyId: string) => void;
  ref?: Ref<TerminalPaneHandle>;
};

export function TerminalPane({
  leafId,
  visible,
  focused = true,
  initialCwd,
  hostId,
  savedPtyId,
  savedActiveTool,
  terminalThemeId,
  onSearchReady,
  onExit,
  onCwd,
  onDetectedLocalUrl,
  onTerviaOpen,
  onTerviaSpawnTab,
  onSshStatus,
  onAiCliStatus,
  onPtyId,
  ref,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { resolvedTheme } = useTheme();
  // Re-apply the xterm theme whenever the Theme-tab custom palette or
  // wallpaper opacity changes. The `customTheme` reference flips on every
  // setter call so identity comparison is enough.
  const customTheme = usePreferencesStore((s) => s.customTheme);
  const customThemeEnabled = usePreferencesStore((s) => s.customThemeEnabled);
  // Terminal theme is independent of the app chrome. In custom mode these drive
  // the palette; in follow-app mode the customTheme/resolvedTheme deps already
  // cover it. `applyTerminalTheme` (ThemeProvider) sets the CSS vars on the same
  // store change; the rAF below defers a frame so they're in place first.
  const terminalThemeMode = usePreferencesStore((s) => s.terminalThemeMode);
  // Global terminal theme id (aliased so it doesn't collide with this pane's
  // per-leaf `terminalThemeId` prop). Both belong in the re-theme effect deps:
  // the global one re-applies when the pane follows the global theme, the
  // per-leaf one is handled inside `useTerminalSession`.
  const globalTerminalThemeId = usePreferencesStore((s) => s.terminalThemeId);
  const terminalCustomPalette = usePreferencesStore((s) => s.terminalCustomPalette);
  // Note: app-opacity changes re-theme the terminal via the rAF-throttled
  // `tervia:canvas-opacity` window listener in `useTerminalSession`, so it stays
  // smooth during live slider drags (not a per-tick effect here).

  const session = useTerminalSession({
    leafId,
    container: containerRef,
    visible,
    focused,
    initialCwd,
    hostId,
    savedPtyId,
    savedActiveTool,
    terminalThemeId,
    onSearchReady: (a) => onSearchReady?.(leafId, a),
    onExit: (c) => onExit?.(leafId, c),
    onCwd: (c) => onCwd?.(leafId, c),
    onDetectedLocalUrl: (u) => onDetectedLocalUrl?.(leafId, u),
    onTerviaOpen: (input) => onTerviaOpen?.(leafId, input),
    onTerviaSpawnTab: (input) => onTerviaSpawnTab?.(leafId, input),
    onSshStatus: (status) => onSshStatus?.(leafId, status),
    onAiCliStatus: (status) => onAiCliStatus?.(leafId, status),
    onPtyId: (ptyId) => onPtyId?.(leafId, ptyId),
  });

  // `useTerminalSession` returns a fresh object literal every render, so
  // keeping `session` in the theme effect's deps would rebuild the theme on
  // every render. Hold the latest session in a ref and read it lazily inside
  // the rAF so the effect can depend only on the real theme inputs.
  const sessionRef = useRef(session);
  sessionRef.current = session;

  useEffect(() => {
    // Defer one frame so CSS variable tokens see the new class / new
    // `--tervia-canvas-*` values written by `applyCustomTheme`.
    const id = requestAnimationFrame(() => sessionRef.current.applyTheme());
    return () => cancelAnimationFrame(id);
  }, [
    resolvedTheme,
    customTheme,
    customThemeEnabled,
    terminalThemeMode,
    globalTerminalThemeId,
    terminalCustomPalette,
  ]);

  // PuTTY-style select-to-copy: a left-button drag, double-click word or
  // triple-click line is copied wherever the button comes up. xterm keeps
  // tracking the drag on `document`, so the release can land past the bottom
  // edge while autoscrolling, right of the end of a line, or on the pane
  // padding, all outside this div.
  // - `mousedown` listens in the capture phase: in a mouse-reporting app,
  //   `SelectionService.handleMouseDown` calls `stopPropagation()` on the press
  //   that forces a selection (Shift, or Option on macOS), so a bubbling
  //   listener (React's `onMouseDown` included) never sees it. Every left press
  //   anywhere in the app runs `onDown`, so a press elsewhere disarms this pane.
  // - `mouseup` listens on `window` in the bubble phase, after xterm's own
  //   `document` mouseup has finished the selection. Nothing stops mouseup:
  //   xterm's `cancel()` is a no-op unless `cancelEvents` is set, which Tervia
  //   does not set.
  // - Only a press in this pane arms the copy, so SearchAddon's `term.select()`
  //   and any other selection made in code never reaches the clipboard. A plain
  //   click leaves no selection, so nothing is copied.
  // - An arming press clears any leftover selection (except with Shift, which
  //   extends it, `_handleIncrementalClick`). A normal click already clears and
  //   SGR mouse reports clear through `onUserInput`, but a DEFAULT-encoded mouse
  //   report (`triggerBinaryEvent`) clears nothing, so a search match left
  //   selected would be copied by a plain click into such an app. Double- and
  //   triple-click select after this capture-phase clear, so they still work.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let armed = false;
    const onDown = (e: MouseEvent) => {
      if (e.button !== 0) return;
      armed = e.target instanceof Node && el.contains(e.target);
      if (armed && !e.shiftKey) sessionRef.current.clearSelection();
    };
    const onUp = (e: MouseEvent) => {
      if (e.button !== 0 || !armed) return;
      armed = false;
      const sel = sessionRef.current.getSelection();
      if (!sel) return;
      void navigator.clipboard.writeText(sel).catch((err) => {
        console.warn("terminal select-to-copy: clipboard write failed:", err);
      });
    };
    window.addEventListener("mousedown", onDown, true);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousedown", onDown, true);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  useImperativeHandle(
    ref,
    () => ({
      write: (data: string) => session.write(data),
      focus: () => session.focus(),
      getBuffer: (max?: number) => session.getBuffer(max),
      getSelection: () => session.getSelection(),
      paste: (data: string) => session.paste(data),
      launchAgent: session.launchAgent,
      isAtPrompt: () => session.isAtPrompt(),
      isProcessRunning: () => session.isProcessRunning(),
    }),
    [session],
  );

  return (
    <div
      ref={containerRef}
      className="h-full w-full"
      data-terminal-leaf-id={leafId}
      // Right-click is context-aware (Windows Terminal / VSCode "copyPaste"):
      // with a selection it COPIES it (block then right-click = copy) and clears
      // the highlight so the next right-click PASTES; with no selection it pastes
      // straight away. Identical for local + SSH terminals. Copy uses the WebView
      // clipboard, paste the host one (see `readClipboardText`) and routes through
      // session.paste so bracketed paste keeps multi-line snippets from
      // auto-executing. Keyboard Ctrl+Shift+C / Ctrl+Shift+V / Shift+Insert and
      // select-to-copy still work.
      onContextMenu={(e) => {
        e.preventDefault();
        const sel = session.getSelection();
        if (sel) {
          void navigator.clipboard.writeText(sel).catch((err) => {
            console.warn("terminal right-click copy: clipboard write failed:", err);
          });
          session.clearSelection();
          return;
        }
        void readClipboardText().then((text) => {
          if (text) session.paste(text);
        });
      }}
      // Internal drag-drops (file explorer rows → terminal) are
      // synthesized from mouse events by `ensureFsDragListener`
      // (HTML5 drag-drop is unreliable under Tauri's default
      // `dragDropEnabled: true`). The listener hit-tests
      // `closest("[data-terminal-leaf-id]")` and writes a
      // shell-quoted path to the matching PTY. The Tauri OS-level
      // drop path is separate and lives in `useTerminalFileDrop`.
      style={{
        // `visibility: hidden` is not enough here: WebView2 can composite
        // xterm's native viewport scrollbar even when its DOM ancestors are
        // invisible, letting an inactive tab's scrollbar appear over the
        // active pane. `display: none` suppresses that compositor surface
        // while keeping this React component and its PTY/xterm session alive.
        // The visibility effect in useTerminalSession re-fits and re-syncs
        // the PTY when this host becomes visible again.
        display: visible ? undefined : "none",
        pointerEvents: visible ? "auto" : "none",
      }}
    />
  );
}
