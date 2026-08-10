import { type EditorPaneHandle } from "@/modules/editor";
import type { SearchAddon } from "@xterm/addon-search";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type Dispatch,
  type RefObject,
  type SetStateAction,
} from "react";

type Params = {
  searchAddons: RefObject<Map<number, SearchAddon>>;
  editorRefs: RefObject<Map<number, EditorPaneHandle>>;
  detectedUrls: RefObject<Map<number, string>>;
  activeId: number;
  activeLeafIdInTab: number | null;
  activeLeafKindCurrent: "terminal" | "editor" | null;
  isTerminalLike: boolean;
  setActiveSearchAddon: Dispatch<SetStateAction<SearchAddon | null>>;
  setActiveEditorHandle: Dispatch<SetStateAction<EditorPaneHandle | null>>;
};

/**
 * Surfaces the active leaf's runtime handles to the chrome: on active leaf/tab
 * change it publishes the focused terminal's search addon + detected URL and
 * the focused editor's handle. Also owns the detected-URL state, which
 * `detectedBrowserUrl` turns into the pane header's open-in-browser pill.
 *
 * `activeSearchAddon` / `activeEditorHandle` stay in App (read by the chrome
 * derivations and the editor bridge, and `activeEditorHandle` is also set by
 * `usePaneHandles`), so their setters are threaded in. The per-leaf maps live
 * in App too. Effects/handlers moved verbatim with identical dependency arrays.
 */
export function useActiveLeafSurface({
  searchAddons,
  editorRefs,
  detectedUrls,
  activeId,
  activeLeafIdInTab,
  activeLeafKindCurrent,
  isTerminalLike,
  setActiveSearchAddon,
  setActiveEditorHandle,
}: Params): {
  handleSearchReady: (leafId: number, addon: SearchAddon) => void;
  handleDetectedLocalUrl: (leafId: number, url: string) => void;
  handleProjectUrl: (url: string | null) => void;
  detectedBrowserUrl: string | null;
} {
  const [activeDetectedUrl, setActiveDetectedUrl] = useState<string | null>(null);
  // The open project's own url, resolved from its config by `useProjectUrl` and
  // only set while that port answers. Not per-leaf: it belongs to the workspace,
  // not to whichever terminal happens to be focused.
  const [projectUrl, setProjectUrl] = useState<string | null>(null);

  // On active leaf or tab change, surface its search addon, editor handle,
  // and detected URL to the chrome.
  useEffect(() => {
    setActiveSearchAddon(
      activeLeafIdInTab !== null && activeLeafKindCurrent === "terminal"
        ? (searchAddons.current.get(activeLeafIdInTab) ?? null)
        : null,
    );
    setActiveEditorHandle(
      activeLeafIdInTab !== null && activeLeafKindCurrent === "editor"
        ? (editorRefs.current.get(activeLeafIdInTab) ?? null)
        : null,
    );
    setActiveDetectedUrl(
      activeLeafIdInTab !== null && activeLeafKindCurrent === "terminal"
        ? (detectedUrls.current.get(activeLeafIdInTab) ?? null)
        : null,
    );
  }, [activeId, activeLeafIdInTab, activeLeafKindCurrent]);

  const handleDetectedLocalUrl = useCallback(
    (leafId: number, url: string) => {
      detectedUrls.current.set(leafId, url);
      if (leafId === activeLeafIdInTab) setActiveDetectedUrl(url);
    },
    [activeLeafIdInTab],
  );

  const detectedBrowserUrl = useMemo(() => {
    // A url the focused terminal printed wins over the project's declared one:
    // it is what the user is looking at right now, and on an SSH leaf it is the
    // tunnelled address, which the config could not have known.
    const url = activeDetectedUrl ?? projectUrl;
    return isTerminalLike ? (url ?? null) : null;
  }, [isTerminalLike, activeDetectedUrl, projectUrl]);

  const handleSearchReady = useCallback(
    (leafId: number, addon: SearchAddon) => {
      searchAddons.current.set(leafId, addon);
      if (leafId === activeLeafIdInTab) setActiveSearchAddon(addon);
    },
    [activeLeafIdInTab],
  );

  return {
    handleSearchReady,
    handleDetectedLocalUrl,
    handleProjectUrl: setProjectUrl,
    detectedBrowserUrl,
  };
}
