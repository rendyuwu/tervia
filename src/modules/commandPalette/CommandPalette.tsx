import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Command as CommandPrimitive } from "cmdk";
import { CommandDialog, CommandEmpty, CommandGroup, CommandItem } from "@/components/ui/command";
import { InputGroup, InputGroupAddon } from "@/components/ui/input-group";
import { usePreferencesStore } from "@/modules/settings/preferences";
import {
  getBindingTokens,
  SHORTCUTS,
  type Shortcut,
  type ShortcutId,
} from "@/modules/shortcuts/shortcuts";
import { COMMAND_PALETTE_MODAL, runCommand } from "@/modules/shortcuts";
import { Kbd } from "@/components/ui/kbd";
import { KEY_SEP } from "@/lib/platform";
import { fileIconUrl } from "@/modules/explorer/lib/iconResolver";
import { invoke } from "@tauri-apps/api/core";
import { File, Monitor, Search, Server, X } from "lucide-react";
import { useHostGroups, useHosts } from "@/modules/hosts/useHosts";
import { rankHosts, searchRows, type HostSearchRow } from "@/modules/hosts/search";
import type { Host } from "@/modules/hosts/types";
import { useVault } from "@/modules/vault/useVault";

/** The `fs_search` row shape. Mirrors `ExplorerSearch`, same Rust command. */
type SearchHit = {
  path: string;
  rel: string;
  name: string;
  is_dir: boolean;
};

/** Typing this as the first character searches files instead of commands. */
const FILE_SIGIL = "@";

/** Typing this as the first character searches saved hosts instead of commands.
 *  Ranked by `rankHosts` over `searchRows`, the pair the header quick-connect and
 *  the Hosts page use, so all three agree on the top match for a query. */
const HOST_SIGIL = "#";

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Root of the opened folder, or null when no folder is open. */
  explorerRoot: string | null;
  onOpenFile: (path: string) => void;
  /** App's `handleConnectHost`: the one saved-host dispatcher, routed by
   *  `host.protocol`, that the header quick-connect and the Hosts page also use. */
  onConnectHost: (host: Host) => void;
};

function CommandPaletteImpl({
  open,
  onOpenChange,
  explorerRoot,
  onOpenFile,
  onConnectHost,
}: Props) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  // What to do once the dialog has closed, run from onCloseAutoFocus so it
  // lands after Radix's focus restore instead of racing it.
  const pending = useRef<(() => void) | null>(null);

  const userShortcuts = usePreferencesStore((s) => s.shortcuts);
  const showHiddenFiles = usePreferencesStore((s) => s.showHiddenFiles);

  const fileMode = query.startsWith(FILE_SIGIL);
  const fileQuery = fileMode ? query.slice(FILE_SIGIL.length).trim() : "";
  const hostMode = query.startsWith(HOST_SIGIL);
  const hostQuery = hostMode ? query.slice(HOST_SIGIL.length) : "";
  // Read while closed too, like the header's quick-connect: a list that only
  // started loading when `#` was typed would flash "No saved hosts" first.
  const hosts = useHosts();
  const groups = useHostGroups();
  const vault = useVault();
  const rankedHosts = useMemo(
    () =>
      hostMode ? rankHosts(searchRows(Array.from(hosts.values()), groups, vault), hostQuery) : [],
    [hostMode, hostQuery, hosts, groups, vault],
  );
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (!open) {
      setQuery("");
      return;
    }
    const t = setTimeout(() => inputRef.current?.focus(), 0);
    return () => clearTimeout(t);
  }, [open]);

  // File search. Same `fs_search` the explorer's "Go to file" uses, so the
  // ranking, the hidden-file rule and the ignore rules are all already right.
  useEffect(() => {
    if (!open || !fileMode || !explorerRoot || !fileQuery) {
      setHits([]);
      setSearching(false);
      return;
    }
    setSearching(true);
    let alive = true;
    const t = setTimeout(async () => {
      try {
        const found = await invoke<SearchHit[]>("fs_search", {
          root: explorerRoot,
          query: fileQuery,
          limit: 50,
          includeHidden: showHiddenFiles,
        });
        if (alive) setHits(found.filter((h) => !h.is_dir));
      } catch (e) {
        console.error("fs_search failed:", e);
        if (alive) setHits([]);
      } finally {
        if (alive) setSearching(false);
      }
    }, 120);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [open, fileMode, fileQuery, explorerRoot, showHiddenFiles]);

  const select = useCallback(
    (run: () => void) => {
      // Stash the action and close; it runs from onCloseAutoFocus below.
      pending.current = run;
      onOpenChange(false);
    },
    [onOpenChange],
  );

  const selectCommand = useCallback((id: ShortcutId) => select(() => runCommand(id)), [select]);

  // Radix restores focus when the close animation ends. Run the action here, at
  // that moment: if it moves focus to its own target (Go to file, Search in
  // files, Find and replace, address bar, an opened editor …), preventDefault so
  // that focus sticks; otherwise let Radix restore focus to where it was.
  const runPending = useCallback((e: Event) => {
    const run = pending.current;
    if (!run) return;
    pending.current = null;
    const before = document.activeElement;
    run();
    if (document.activeElement !== before) e.preventDefault();
  }, []);

  const items = useMemo(() => {
    const groups = new Map<string, Shortcut[]>();
    for (const s of SHORTCUTS) {
      // Skip commands that can't be run from a list: readOnly ones are
      // documentation-only key hints (e.g. Enter to send) with no handler;
      // tab.selectByIndex needs a specific digit; commandPalette.open is this
      // palette itself.
      if (s.readOnly || s.id === "tab.selectByIndex" || s.id === "commandPalette.open") {
        continue;
      }
      const g = groups.get(s.group) ?? [];
      g.push(s);
      groups.set(s.group, g);
    }
    return groups;
  }, []);

  const bindingTokens = useCallback(
    (s: Shortcut): string[] => {
      const bindings = userShortcuts[s.id] || s.defaultBindings;
      if (!bindings || bindings.length === 0) return [];
      return getBindingTokens(bindings[0]);
    },
    [userShortcuts],
  );

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      // Names this dialog in the modal stack. `commandPalette.open` is
      // the one chord exempt from the modal gate, and the exemption applies
      // only while THIS dialog is the topmost open modal - so the chord can
      // close the palette but cannot open it over the host editor. Threaded
      // straight through `CommandDialog`'s `{...props}` into `Dialog`.
      modalName={COMMAND_PALETTE_MODAL}
      title="Command Palette"
      description="Search for a command to run..."
      className="sm:max-w-lg"
      showCloseButton={false}
      onCloseAutoFocus={runPending}
      // `fs_search` and `rankHosts` already ranked their rows; letting cmdk filter
      // them again against a query that still carries the sigil would hide every
      // one, and re-sort the hosts away from the order the header shows.
      shouldFilter={!fileMode && !hostMode}
    >
      <div className="flex items-center justify-between gap-2 px-2 pt-1.5 pb-0.5">
        <span className="text-muted-foreground px-1 text-[11px] font-medium tracking-tight">
          Command Palette
        </span>
        <button
          type="button"
          onClick={() => onOpenChange(false)}
          aria-label="Close"
          className="text-muted-foreground hover:bg-muted hover:text-foreground flex size-6 shrink-0 cursor-pointer items-center justify-center rounded-md transition-colors"
        >
          <X size={14} strokeWidth={2} />
        </button>
      </div>

      <div className="p-1 pb-0">
        <InputGroup className="bg-input/50 h-9">
          <InputGroupAddon align="inline-start">
            <Search strokeWidth={2} className="size-4 shrink-0 opacity-50" />
          </InputGroupAddon>
          <CommandPrimitive.Input
            ref={inputRef}
            data-slot="command-input"
            value={query}
            onValueChange={setQuery}
            placeholder="Type a command, @ to find a file, # to connect to a host…"
            className="placeholder:text-muted-foreground w-full text-sm outline-hidden disabled:cursor-not-allowed disabled:opacity-50"
          />
          {query ? (
            <InputGroupAddon align="inline-end">
              <button
                type="button"
                onClick={() => setQuery("")}
                aria-label="Clear search"
                className="text-muted-foreground hover:text-foreground flex size-5 shrink-0 cursor-pointer items-center justify-center rounded-md transition-colors"
              >
                <X size={14} strokeWidth={2} />
              </button>
            </InputGroupAddon>
          ) : null}
        </InputGroup>
      </div>

      <CommandPrimitive.List
        data-slot="command-list"
        className="max-h-80 scroll-py-1 overflow-x-hidden overflow-y-auto outline-none"
      >
        {fileMode ? (
          <FileResults
            hits={hits}
            searching={searching}
            query={fileQuery}
            hasRoot={!!explorerRoot}
            onPick={(path) => select(() => onOpenFile(path))}
          />
        ) : hostMode ? (
          <HostResults
            ranked={rankedHosts}
            hasHosts={hosts.size > 0}
            onPick={(host) => select(() => onConnectHost(host))}
          />
        ) : (
          <>
            <CommandEmpty>No matching command.</CommandEmpty>
            {[...items.entries()].map(([group, shortcuts]) => (
              <CommandGroup key={group} heading={group}>
                {shortcuts.map((s) => {
                  const tokens = bindingTokens(s);
                  return (
                    <CommandItem
                      key={s.id}
                      value={`${s.id} ${s.label}`}
                      keywords={[s.label, s.id, group]}
                      onSelect={() => selectCommand(s.id)}
                    >
                      <span className="flex-1">{s.label}</span>
                      {tokens.length > 0 ? (
                        <Kbd className="ml-auto">{tokens.join(KEY_SEP)}</Kbd>
                      ) : null}
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            ))}
          </>
        )}
      </CommandPrimitive.List>
    </CommandDialog>
  );
}

/**
 * The `@` branch of the list. Split out so the palette body stays one JSX
 * ternary, and so the empty states can say WHICH of the three reasons applies:
 * no folder open, nothing typed yet, or a search that genuinely found nothing.
 */
function FileResults({
  hits,
  searching,
  query,
  hasRoot,
  onPick,
}: {
  hits: SearchHit[];
  searching: boolean;
  query: string;
  hasRoot: boolean;
  onPick: (path: string) => void;
}) {
  if (!hasRoot) {
    return (
      <div className="text-muted-foreground px-3 py-6 text-center text-sm">No open folder</div>
    );
  }
  if (!query) {
    return (
      <div className="text-muted-foreground px-3 py-6 text-center text-sm">
        Type part of a file name
      </div>
    );
  }
  if (hits.length === 0) {
    return (
      <div className="text-muted-foreground px-3 py-6 text-center text-sm">
        {searching ? "Searching…" : "No matching file"}
      </div>
    );
  }
  return (
    <CommandGroup heading="Files">
      {hits.map((hit) => (
        <CommandItem key={hit.path} value={hit.path} onSelect={() => onPick(hit.path)}>
          <FileGlyph name={hit.name} />
          <span className="truncate">{hit.name}</span>
          <span className="text-muted-foreground ml-auto truncate pl-3 text-[11px]">{hit.rel}</span>
        </CommandItem>
      ))}
    </CommandGroup>
  );
}

/**
 * The `#` branch of the list, on `FileResults`' pattern. Rows arrive in
 * `rankHosts` order and must stay in it: the palette turns cmdk's own filter off
 * in this mode, so DOM order is rank order and Enter connects the top match, the
 * same host the header quick-connect would. No ad-hoc `user@host` create path
 * here; that stays `HeaderQuickConnect`'s.
 */
function HostResults({
  ranked,
  hasHosts,
  onPick,
}: {
  ranked: HostSearchRow[];
  hasHosts: boolean;
  onPick: (host: Host) => void;
}) {
  if (ranked.length === 0) {
    return (
      <div className="text-muted-foreground px-3 py-6 text-center text-sm">
        {hasHosts ? "No matching host" : "No saved hosts"}
      </div>
    );
  }
  return (
    <CommandGroup heading="Hosts">
      {ranked.map((row) => {
        const Icon = row.host.protocol === "ssh" ? Server : Monitor;
        return (
          <CommandItem key={row.host.id} value={row.host.id} onSelect={() => onPick(row.host)}>
            <Icon size={14} strokeWidth={1.75} className="text-muted-foreground shrink-0" />
            <span className="truncate">{row.host.name}</span>
            <span className="text-muted-foreground ml-auto truncate pl-3 text-[11px]">
              {row.username ? `${row.username}@` : ""}
              {row.host.host}
            </span>
          </CommandItem>
        );
      })}
    </CommandGroup>
  );
}

/** The file tree's own icon for this name, falling back to a generic glyph. */
function FileGlyph({ name }: { name: string }) {
  const url = fileIconUrl(name);
  return url ? (
    <img src={url} alt="" className="size-3.5 shrink-0" draggable={false} />
  ) : (
    <File size={14} strokeWidth={1.75} className="text-muted-foreground shrink-0" />
  );
}

export const CommandPalette = memo(CommandPaletteImpl);
