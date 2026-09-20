import { invoke, Channel } from "@tauri-apps/api/core";
import { parseFrameBatch, type RdpFrameBatch } from "./frame";

/**
 * Typed wrapper over the eight `rdp_*` commands, mirroring `ssh/bridge.ts`.
 *
 * The session `Channel` carries JSON control events ONLY. Pixels are pulled:
 * `frameReady` says dirty rects are waiting and `rdpTakeFrame` collects them
 * as raw bytes, so a framebuffer never goes through JSON and never sits in
 * Tauri's process-global channel queue.
 */

/** First-connect certificate confirmation request from the backend. Emitted
 *  from INSIDE the TLS handshake, so before CredSSP - no credential has been
 *  sent, and rejecting aborts the connect before one is. */
export type RdpCertPrompt = {
  promptId: string;
  fingerprint: string;
  host: string;
  subject: string;
  issuer: string;
};

/** Control events. Field names are camelCase on this side because the Rust enum
 *  carries `rename_all_fields = "camelCase"`. */
export type RdpEvent =
  | {
      type: "connected";
      desktopWidth: number;
      desktopHeight: number;
      serverFingerprint: string;
    }
  | {
      type: "certPrompt";
      promptId: string;
      fingerprint: string;
      host: string;
      subject: string;
      issuer: string;
    }
  | { type: "resize"; width: number; height: number }
  | { type: "pointerDefault" }
  | { type: "pointerHidden" }
  | { type: "pointerPosition"; x: number; y: number }
  /** Dirty rects are waiting. Collect them with `rdpTakeFrame`; no pixels
   *  travel on the channel. */
  | { type: "frameReady" }
  | { type: "disconnected"; reason: string }
  | { type: "error"; message: string };

/**
 * Where `rdp_open` gets the password.
 *
 * `keychain` is the path for every SAVED connection: a reference travels, the
 * host process reads the plaintext, and it is handed straight into the CredSSP
 * exchange without ever coming back here.
 *
 * `inline` exists for exactly ONE caller: the connection dialog's Test button,
 * where the user has just typed a password that is not in the keychain yet, so
 * there is no reference to send. Using it anywhere else would put the secret
 * back in the webview and defeat the whole point of the reference form.
 */
export type RdpCredential =
  { kind: "keychain"; service: string; account: string } | { kind: "inline"; password: string };

export type RdpOpenInput = {
  host: string;
  port: number;
  username: string;
  /** NetBIOS or DNS domain. Omit for a local account or a UPN in `username`. */
  domain?: string;
  credential: RdpCredential;
  width: number;
  height: number;
  /** SHA-256 fingerprint recorded by a previous connect. When set, the TLS
   *  handshake fails fast on anything else - before a credential is sent.
   *  Omit on first connect, which prompts the user instead. */
  expectedCertFingerprint?: string;
};

/** One live session, as `rdp_list_sessions` reports it. */
export type RdpSessionInfo = {
  id: number;
  host: string;
  username: string;
  desktopWidth: number;
  desktopHeight: number;
  serverFingerprint: string;
  alive: boolean;
  createdAtMs: number;
};

/**
 * One input event. Deliberately close to the DOM events that produce them:
 * `button` is `MouseEvent.button`, and `scancode` is a PC/AT set-1 code with the
 * `0xE0` prefix in the high byte (see `scancodes.ts`).
 */
export type RdpInputEvent =
  | { kind: "mouseMove"; x: number; y: number }
  | { kind: "mouseDown"; button: number }
  | { kind: "mouseUp"; button: number }
  /** One notch. `delta` is in RDP rotation units (120 per detent) and its sign
   *  follows RDP, not the DOM - see `wheelRotation`. */
  | { kind: "wheel"; vertical: boolean; delta: number }
  | { kind: "keyDown"; scancode: number }
  | { kind: "keyUp"; scancode: number }
  /** A character with no scancode: dead keys, IME output, anything a
   *  layout table cannot express. */
  | { kind: "unicodeDown"; ch: string }
  | { kind: "unicodeUp"; ch: string }
  /** Release every held key and button. MUST be sent on blur, or a modifier
   *  held while focus left stays down on the server for every later keystroke. */
  | { kind: "releaseAll" };

export type RdpHandlers = {
  onConnected?: (desktopWidth: number, desktopHeight: number, serverFingerprint: string) => void;
  /** First-connect certificate confirmation. Show the fingerprint and call
   *  `confirmRdpCert(promptId, accept)`; the handshake is paused (no credential
   *  sent) until then. */
  onCertPrompt?: (prompt: RdpCertPrompt) => void;
  /** The desktop changed size (Deactivation-Reactivation). The framebuffer has
   *  been rebuilt at this size and is BLANK; the server repaints it, so the
   *  next frames arrive as ordinary deltas. */
  onResize?: (width: number, height: number) => void;
  /** Dirty rects are waiting on the backend. Call `rdpTakeFrame` to collect
   *  them; nothing is sent until you do, which is the backpressure. */
  onFrameReady?: () => void;
  onDisconnected?: (reason: string) => void;
  onError?: (message: string) => void;
};

export type RdpSession = {
  id: number;
  /** Queue a batch of input events. Batched on purpose: a single mouse drag
   *  produces dozens of moves per second and each IPC round trip costs far more
   *  than the frame it produces. */
  sendInput: (events: RdpInputEvent[]) => Promise<void>;
  close: () => Promise<void>;
};

/** Answer a first-connect certificate prompt. `accept = true` lets the paused
 *  handshake proceed (and the caller pins the fingerprint); `false` aborts the
 *  connect before any credential is sent. */
export function confirmRdpCert(promptId: string, accept: boolean): Promise<void> {
  return invoke("rdp_confirm_cert", { promptId, accept });
}

/**
 * Every live session the host process is holding.
 *
 * One of two wrappers here that nothing in `src/` calls - the other being
 * {@link rdpAttach}. Neither is speculative API: both commands are registered
 * in `lib.rs`, and a registered command with no typed wrapper is one that gets
 * invoked by hand with a mistyped argument the first time someone needs it.
 * This module is the whole command surface, so a caller never reaches for
 * `invoke` directly.
 *
 * The pane needs none of them because it owns exactly one session and knows its
 * id: enumeration is for a supervisor (an orphan sweep, a detached window),
 * which is what would use this first.
 */
export function rdpListSessions(): Promise<RdpSessionInfo[]> {
  return invoke<RdpSessionInfo[]>("rdp_list_sessions");
}

export function rdpInput(id: number, events: RdpInputEvent[]): Promise<void> {
  return invoke("rdp_input", { id, events });
}

export function rdpClose(id: number): Promise<void> {
  return invoke("rdp_close", { id });
}

/**
 * Mirror a live session onto a second sink. Unlike SSH there is no byte stream
 * to replay, so the new sink gets a `connected` event and then takes its first
 * picture from {@link rdpSnapshot}, repainting from it again on each
 * `frameReady` - a mirror does NOT share the primary's batcher, so it must
 * never call {@link rdpTakeFrame}. Resolves with whether the session is still
 * alive.
 *
 * Uncalled: there is no detach-to-window. See
 * {@link rdpListSessions} for why the wrapper exists anyway.
 */
export function rdpAttach(id: number, handlers: RdpHandlers): Promise<boolean> {
  return invoke<boolean>("rdp_attach", { id, onEvent: buildChannel(handlers) });
}

/**
 * The current framebuffer as one keyframe batch, in the same wire format
 * {@link rdpTakeFrame} returns. Raw, so the pixels never go through JSON.
 * `null` when the payload is not a batch this build understands.
 *
 * A mirror's first picture and its repaint on every `frameReady`: a mirror
 * does not share the primary's batcher, so this is the only way it sees
 * pixels, and on an idle desktop nothing else will ever paint it.
 *
 * Uncalled by the pane, which pulls deltas and has no resync path. See
 * {@link rdpListSessions} for why the wrapper exists anyway.
 */
export async function rdpSnapshot(id: number): Promise<RdpFrameBatch | null> {
  const raw = await invoke<ArrayBuffer>("rdp_snapshot", { id });
  return parseFrameBatch(raw);
}

/**
 * Drain the session's pending dirty rects. `null` when nothing is pending -
 * the backend returns a zero-length body and `parseFrameBatch` refuses
 * anything shorter than a header.
 *
 * This is the frame transport; the caller's own pace is the backpressure, and
 * the `rdp_take_frame` command documents why the channel cannot carry pixels.
 */
export async function rdpTakeFrame(id: number): Promise<RdpFrameBatch | null> {
  const raw = await invoke<ArrayBuffer>("rdp_take_frame", { id });
  return parseFrameBatch(raw);
}

/**
 * Build the session channel. It carries JSON control events only - pixels come
 * from {@link rdpTakeFrame}, never from here.
 *
 * `onmessage` is wrapped because an exception escaping it reaches Tauri's own
 * `.catch(console.error)` and buys nothing, while losing every event queued
 * behind it. The handler is total: it drops what it cannot understand and
 * always returns normally.
 */
function buildChannel(handlers: RdpHandlers): Channel<RdpEvent> {
  const channel = new Channel<RdpEvent>();
  // Assigned exactly once, and never replaced or detached while the session is
  // live: swapping the handler on a channel Tauri is still delivering to would
  // orphan whatever is in flight. A session is ended by `rdp_close`, not by
  // taking away its listener.
  channel.onmessage = (message) => {
    try {
      dispatch(message, handlers);
    } catch (e) {
      // Deliberately swallowed, after logging. Rethrowing reaches Tauri's own
      // `.catch(console.error)` and buys nothing, while risking the parked
      // payload above.
      console.error("rdp: dropped a channel message that could not be handled", e);
    }
  };
  return channel;
}

/** The whole of the message handling, so `onmessage` above is nothing but the
 *  try/catch that has to wrap it. */
function dispatch(event: RdpEvent, handlers: RdpHandlers): void {
  switch (event.type) {
    case "connected":
      handlers.onConnected?.(event.desktopWidth, event.desktopHeight, event.serverFingerprint);
      break;
    case "certPrompt":
      handlers.onCertPrompt?.({
        promptId: event.promptId,
        fingerprint: event.fingerprint,
        host: event.host,
        subject: event.subject,
        issuer: event.issuer,
      });
      break;
    case "resize":
      handlers.onResize?.(event.width, event.height);
      break;
    case "frameReady":
      handlers.onFrameReady?.();
      break;
    case "disconnected":
      handlers.onDisconnected?.(event.reason);
      break;
    case "error":
      handlers.onError?.(event.message);
      break;
    // The remote cursor is composited into the framebuffer by the server, so
    // these carry nothing the canvas needs: the CSS cursor stays default and
    // a warp is already visible in the pixels. Drawing a second cursor from
    // them would render two. No cursor bitmap is drawn from them at all.
    case "pointerDefault":
    case "pointerHidden":
    case "pointerPosition":
      break;
  }
}

/**
 * Open a session. Resolves once the connect sequence has reached the active
 * stage (or rejects with the backend's message); frames and later events arrive
 * on the handlers.
 *
 * `null` is sent for absent optional fields rather than omitting the key, so
 * serde sees an explicit `None` - the same shape `ssh/bridge.ts` sends.
 */
export async function openRdp(input: RdpOpenInput, handlers: RdpHandlers): Promise<RdpSession> {
  const id = await invoke<number>("rdp_open", {
    input: {
      host: input.host,
      port: input.port,
      username: input.username,
      domain: input.domain ?? null,
      credential: input.credential,
      width: input.width,
      height: input.height,
      expectedCertFingerprint: input.expectedCertFingerprint ?? null,
    },
    onEvent: buildChannel(handlers),
  });
  return {
    id,
    sendInput: (events) => (events.length === 0 ? Promise.resolve() : rdpInput(id, events)),
    close: () => rdpClose(id),
  };
}
