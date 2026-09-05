import { Button } from "@/components/ui/button";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { CommandEmpty, CommandItem, CommandList } from "@/components/ui/command";
import { Popover, PopoverAnchor, PopoverContent } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { TOOLBAR_HOVER } from "@/lib/toolbarButton";
import { Command as CommandPrimitive } from "cmdk";
import { useHosts, useHostGroups } from "@/modules/hosts/useHosts";
import { parseAdHocTarget, rankHosts, searchRows } from "@/modules/hosts/search";
import { requestHostEditor } from "@/modules/hosts/pendingEditor";
import type { Host } from "@/modules/hosts/types";
import { useVault } from "@/modules/vault/useVault";
import { useCallback, useMemo, useRef, useState } from "react";
import { Monitor, Plug, Server } from "lucide-react";

type Props = {
  /** Collapse to an icon-only button until opened. Mirrors `SearchInline`'s
   *  `compact` contract so both fields disappear at the same header width. */
  compact?: boolean;
  /** The same connect path the header's SSH/RDP menus already use. Routes by
   *  `host.protocol` in App - not here - so this stays a single reusable path
   *  rather than two copies of the same dispatch. */
  onConnectHost: (host: Host) => void;
  /** Open the Hosts tab. Backs the ad-hoc "no saved host matched, but it
   *  parses as a target" path below. */
  onOpenHostsPage: () => void;
};

/**
 * Type to filter saved hosts by name or `user@host`; Enter connects the
 * top match. A query that matches no saved host but parses as
 * `user@host[:port]` opens the Hosts page with the editor prefilled instead -
 * there is no first-class ad-hoc connect path to dial straight into, and
 * inventing one is out of scope.
 *
 * `Command` is the outermost element, not `Popover`: its root keydown handler
 * needs the visible input as a real DOM descendant (so Enter/Escape bubble to
 * it), while the ranked list lives in a portaled `PopoverContent`. React
 * context crosses that portal boundary fine - only the DOM does not - which is
 * why the nesting is `Command > Popover > (Anchor, Content)` and not the other
 * way around. See the mousedown-drag guard comment at `Header.tsx:83`: because
 * the list is portaled, it is never a real DOM descendant of the header's drag
 * row, so that guard already leaves clicks on it alone.
 *
 * Enter fires `cmdk`'s own selection: the arrow-key-highlighted row's
 * `onSelect`, or the top-ranked row when nothing has been arrowed to, since
 * `cmdk` auto-highlights the first valid item as soon as the list mounts.
 * `handleKeyDown` only intervenes when the list is empty, where there is no
 * row for `cmdk` to select but there may be an ad-hoc target to open the
 * editor for instead.
 *
 * That delegation rests on an invariant the `onInteractOutside` handler below
 * exists to hold: while the input has focus the list is open. Break it and Enter
 * silently does nothing, because handing the key to `cmdk` when the list has
 * unmounted hands it to no one.
 */
export function HeaderQuickConnect({ compact, onConnectHost, onOpenHostsPage }: Props) {
  const [opened, setOpened] = useState(false);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const inputRef = useRef<HTMLInputElement>(null);
  // The anchor element, so the popover can recognise a click on its own input as
  // NOT an outside interaction. See the `onInteractOutside` comment below - Radix
  // cannot work this out for itself here, because it asks the trigger and this
  // popover has an anchor instead.
  const anchorRef = useRef<HTMLDivElement>(null);
  // Mirrors SearchInline's pattern: the input isn't mounted yet on the same
  // render that expands from the collapsed icon, so focus is deferred to the
  // ref callback that fires once it commits.
  const pendingFocusRef = useRef(false);
  const setInputRef = useCallback((el: HTMLInputElement | null) => {
    inputRef.current = el;
    if (!el || !pendingFocusRef.current) return;
    pendingFocusRef.current = false;
    el.focus();
  }, []);

  const hosts = useHosts();
  const groups = useHostGroups();
  // The vault, for `searchRows` to resolve a bound host's username with. This
  // used to build its rows with `inlineUsername`, which is `undefined` for a
  // vault-bound host, while the Hosts page resolved the identity - so a host
  // bound to an identity named "deploy" matched on the page, matched NOTHING
  // here, and the empty state then offered "Press Enter to add deploy as a new
  // host" for a host that already exists. `useVault` is synchronous (two store
  // maps, memoised), so there is no cost to reading it on this path.
  const vault = useVault();

  const rows = useMemo(
    () => searchRows(Array.from(hosts.values()), groups, vault),
    [hosts, groups, vault],
  );

  const ranked = useMemo(() => rankHosts(rows, query), [rows, query]);

  const trimmedQuery = query.trim();
  const adHocTarget = trimmedQuery.length > 0 ? parseAdHocTarget(trimmedQuery) : null;
  const emptyMessage =
    trimmedQuery.length === 0
      ? "Type a host name or user@host"
      : adHocTarget
        ? `Press Enter to add "${trimmedQuery}" as a new host`
        : "No matching host";

  const resetAndClose = useCallback(() => {
    setQuery("");
    setOpen(false);
    inputRef.current?.blur();
    if (compact) setOpened(false);
  }, [compact]);

  const handleConnect = useCallback(
    (host: Host) => {
      onConnectHost(host);
      resetAndClose();
    },
    [onConnectHost, resetAndClose],
  );

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      // A non-empty list is left to `cmdk`'s own Enter handling: it dispatches
      // a select on whichever row is `aria-selected` (arrow-highlighted, or
      // the top-ranked row by default since `cmdk` auto-selects the first
      // valid item on mount), which runs that `CommandItem`'s `onSelect` -
      // `handleConnect(row.host)` below. Calling `preventDefault` here
      // unconditionally, as this used to, suppresses that dispatch entirely
      // (it runs only `if(!e.defaultPrevented)`), so Enter always connected
      // `ranked[0]` no matter what arrow keys had highlighted.
      if (ranked.length > 0) return;
      e.preventDefault();
      if (adHocTarget) {
        onOpenHostsPage();
        requestHostEditor({
          mode: "create",
          protocol: "ssh",
          prefill: { host: adHocTarget.host, port: adHocTarget.port, user: adHocTarget.user },
        });
        resetAndClose();
      }
      // Matches nothing and doesn't parse: no visible effect beyond the
      // empty-state copy already saying so - never open a blank editor on
      // garbage input.
      return;
    }
    if (e.key === "Escape") {
      e.preventDefault();
      resetAndClose();
    }
  };

  if (compact && !opened) {
    return (
      <IconTooltip label="Connect to a host…" side="bottom">
        <Button
          variant="ghost"
          size="icon"
          className={cn("text-muted-foreground", TOOLBAR_HOVER, "size-7 shrink-0 rounded-md")}
          onClick={() => {
            pendingFocusRef.current = true;
            setOpened(true);
          }}
          aria-label="Connect to a host…"
        >
          <Plug size={15} strokeWidth={1.75} />
        </Button>
      </IconTooltip>
    );
  }

  return (
    <CommandPrimitive shouldFilter={false} onKeyDown={handleKeyDown} className="contents">
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverAnchor asChild>
          <div ref={anchorRef} className="relative h-7 w-40 shrink-0">
            <Plug
              size={13}
              strokeWidth={1.75}
              className="text-muted-foreground pointer-events-none absolute top-1/2 left-2 -translate-y-1/2"
            />
            <CommandPrimitive.Input
              ref={setInputRef}
              value={query}
              onValueChange={(v) => {
                setQuery(v);
                setOpen(true);
              }}
              onFocus={() => setOpen(true)}
              onBlur={() => {
                setOpen(false);
                if (compact && !query) setOpened(false);
              }}
              placeholder="Connect…"
              className="bg-muted/80 border-border placeholder:text-muted-foreground/70 h-7 w-full rounded-md border pr-2 pl-7 text-[12.5px] outline-hidden focus-visible:ring-0"
            />
          </div>
        </PopoverAnchor>
        <PopoverContent
          align="start"
          sideOffset={4}
          className="rounded-2xl p-1"
          // Keep focus on the always-visible input rather than letting Radix
          // move it into the portaled list on open/close.
          onOpenAutoFocus={(e) => e.preventDefault()}
          onCloseAutoFocus={(e) => e.preventDefault()}
          // Escape is owned entirely by `handleKeyDown` above (clear + close +
          // blur) so there is exactly one place that decides what it does,
          // instead of this dismiss firing alongside it.
          onEscapeKeyDown={(e) => e.preventDefault()}
          // Radix decides what counts as "outside" by asking whether the target
          // is inside the TRIGGER, and this popover has an `Anchor` and no
          // trigger, so `context.triggerRef.current` is null and a click on the
          // INPUT counted as outside. That dismissed the list while leaving the
          // input focused, and because it was already focused no new `focus`
          // event fired, so the `onFocus` re-open above never ran. The resulting
          // state - focused, closed, non-empty query, non-empty `ranked` - made
          // Enter do nothing at all: it takes the `ranked.length > 0` early
          // return in `handleKeyDown`, cmdk consumes the key, and cmdk's own
          // item lookup finds nothing because the list unmounted with the
          // portal. Telling Radix where the anchor is fixes the cause. Gating
          // Enter on `open` instead would only stop Enter being dead, and leave
          // a click on the input closing the input's own dropdown.
          onInteractOutside={(e) => {
            const target = e.target;
            if (target instanceof Node && anchorRef.current?.contains(target)) e.preventDefault();
          }}
        >
          <CommandList>
            {ranked.length === 0 ? (
              <CommandEmpty>{emptyMessage}</CommandEmpty>
            ) : (
              ranked.map((row) => (
                <CommandItem
                  key={row.host.id}
                  value={row.host.id}
                  onSelect={() => handleConnect(row.host)}
                  className="gap-2"
                >
                  {row.host.protocol === "ssh" ? (
                    <Server size={13} strokeWidth={2} className="text-muted-foreground shrink-0" />
                  ) : (
                    <Monitor size={13} strokeWidth={2} className="text-muted-foreground shrink-0" />
                  )}
                  <span className="min-w-0 flex-1 truncate">{row.host.name}</span>
                  <span className="text-muted-foreground shrink-0 truncate text-[11px]">
                    {row.username ? `${row.username}@` : ""}
                    {row.host.host}
                  </span>
                </CommandItem>
              ))
            )}
          </CommandList>
        </PopoverContent>
      </Popover>
    </CommandPrimitive>
  );
}
