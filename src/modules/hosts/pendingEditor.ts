import { create } from "zustand";

// The one-way channel from "something asked for the host editor" to the Hosts
// page that owns it.
//
// It exists because the callers are not the page's children. The header's
// quick-connect opens the Hosts TAB and then asks for the editor, so at the
// moment of the request the page may not be mounted at all - there is no prop to
// pass and no callback to hold. A request the page picks up once it mounts needs
// neither.
//
// ONE pending request, not a queue. Two editors cannot be open at once, so a
// second request arriving before the first is consumed is the user changing their
// mind, and the newer target is the one to honour.

export type HostEditorPrefill = {
  name?: string;
  host?: string;
  port?: number;
  /** SSH user or RDP username, whichever the protocol wants. */
  user?: string;
  groupId?: string;
};

export type HostEditorTarget =
  | { mode: "create"; protocol: "ssh" | "rdp"; prefill?: HostEditorPrefill }
  | { mode: "edit"; hostId: string };

type PendingEditorState = {
  target: HostEditorTarget | null;
  request: (target: HostEditorTarget) => void;
  clear: () => void;
};

/**
 * Private: the three functions below are the whole surface.
 *
 * The state holds the target OBJECT and {@link useHostEditorRequest} hands it back
 * by reference. That is a zustand v5 requirement rather than a matter of taste -
 * v5 compares selector results with `Object.is` and dropped the equality-function
 * overload, so a selector rebuilding `{ mode, hostId }` on every call would
 * re-subscribe forever and throw "Maximum update depth exceeded".
 */
const usePendingEditor = create<PendingEditorState>((set) => ({
  target: null,
  request: (target) => set({ target }),
  clear: () => set({ target: null }),
}));

/** Ask the Hosts page to open its editor. The header's quick-connect calls this
 *  after opening the Hosts tab, so the page does not have to be mounted yet. */
export function requestHostEditor(target: HostEditorTarget): void {
  usePendingEditor.getState().request(target);
}

export function useHostEditorRequest(): HostEditorTarget | null {
  return usePendingEditor((s) => s.target);
}

export function clearHostEditorRequest(): void {
  usePendingEditor.getState().clear();
}
