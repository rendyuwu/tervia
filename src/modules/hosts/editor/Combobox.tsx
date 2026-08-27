import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { ChevronDown } from "lucide-react";
import { useState } from "react";

// The searchable picker the two old dialogs had three copies of - jump host, RDP
// tunnel, desktop size - identical but for their strings. One copy here, because
// the merged editor would otherwise carry four (a group picker too) and the
// popover's one real subtlety is spelled out in exactly one of them.

export type ComboboxOption = {
  /** "" is a legitimate value and means "none": it is an option like any other,
   *  so the empty choice is searchable and shows a tick like the rest. */
  value: string;
  label: string;
  /** A second, monospaced line under the label. */
  hint?: string;
  /** What cmdk matches typing against. Include the id so two like-named entries
   *  are never collapsed into one. */
  search: string;
};

export function Combobox({
  options,
  value,
  onChange,
  searchPlaceholder,
  emptyLabel,
}: {
  options: ComboboxOption[];
  value: string;
  onChange: (value: string) => void;
  searchPlaceholder: string;
  emptyLabel: string;
}) {
  const [open, setOpen] = useState(false);
  const selected = options.find((o) => o.value === value);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      {/* NOT `modal`. It looks like the fix for "cmdk items only answer Enter,
          never a click" inside a Dialog, but it buys that by making the whole
          page inert: every field behind it freezes and clicking away cannot even
          close it, since the click lands on nothing that listens. The click was
          never a focus problem - the portaled content was inheriting
          `pointer-events: none` from the body, which `PopoverContent` now
          overrides for itself. Focus is fine either way: any mounted FocusScope
          pauses the Dialog's, trapped or not. */}
      <PopoverTrigger asChild>
        <Button
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="h-8 w-full justify-between px-2.5 text-[12px] font-normal"
        >
          <span className={cn("truncate", !value && "text-muted-foreground")}>
            {selected?.label ?? ""}
          </span>
          <ChevronDown size={13} strokeWidth={2} className="ml-2 shrink-0 opacity-60" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        sideOffset={6}
        className="w-[var(--radix-popover-trigger-width)] gap-0 overflow-hidden rounded-2xl p-0"
      >
        <Command className="rounded-2xl">
          <CommandInput placeholder={searchPlaceholder} className="text-[12px]" />
          <CommandList
            className="max-h-56"
            // VLT-47: this popover is portaled to `document.body` as a sibling
            // of the host editor's `Dialog`, not a descendant of it - so when
            // the editor is open (it always is, here; every caller sits inside
            // `HostEditorDialog`), Radix's modal scroll lock
            // (`react-remove-scroll`, driven by that Dialog) treats every wheel
            // event in here as happening OUTSIDE its own subtree and calls
            // `preventDefault()` on it globally before the browser's native
            // wheel-to-scroll runs (`react-remove-scroll/dist/.../SideEffect.js`,
            // the `!lastProps.current.noIsolation` branch - there is no `shards`
            // registration reaching into a nested portal). The list keeps
            // working from the search box and the arrow keys because neither
            // goes through that wheel path; only the mouse wheel does.
            //
            // The lock's listener is `document.addEventListener('wheel',
            // shouldPrevent, nonPassive)` (same file, further down), and
            // `nonPassive` (`react-remove-scroll/dist/.../aggresiveCapture.js`)
            // is `{ passive: false }` with NO `capture: true` - so it runs in
            // the BUBBLE phase on `document`, which is strictly LATER than any
            // handler on this element: React dispatches this `onWheel` at its
            // one root listener (attached inside `document.body`, an ancestor
            // of this portaled node in the REACT tree even though not in the
            // DOM tree - portals still bubble through React's tree for event
            // purposes) before the native event ever reaches `document`
            // itself. That means `e.stopPropagation()` here reaches the lock's
            // listener before it fires at all, so it never calls its
            // `preventDefault()`, and the browser's own default wheel-to-
            // scroll then runs UNMODIFIED - real momentum/inertia included,
            // unlike a hand-rolled `scrollTop += deltaY`. It is also a no-op,
            // not a bug, wherever this component is mounted with no modal
            // Dialog above it (6e's vault picker is the likely next such
            // caller): with no `RemoveScroll` mounted there is no document
            // listener to stop propagation to, and native wheel-scroll simply
            // runs on its own, so nothing here double-scrolls it. An earlier
            // version of this fix wrote `scrollTop += deltaY` unconditionally,
            // which is correct only INSIDE a modal (where the browser's own
            // scroll is suppressed and this write is the only one that lands)
            // and double-scrolls the instant this component is used outside
            // one - exactly the trap `hosts-combobox-wheel-verify.ts` guards.
            onWheel={(e) => {
              e.stopPropagation();
            }}
            // Fixed once, here, covers all three pickers this file is shared by
            // (see the top-of-file comment): the jump host (`SshOptions.tsx`),
            // and the RDP tunnel target and desktop size (`RdpOptions.tsx`,
            // two separate `<Combobox>` instances) - all three mount inside the
            // same `HostEditorDialog`, so all three had the identical defect.
            //
            // `components/ui/command.tsx`'s `CommandList` was deliberately left
            // untouched: its own CSS (`overflow-y-auto`, inherited here under
            // this file's `max-h-56` override) is not the defect - the list
            // scrolls correctly the moment it is not fighting the Dialog's
            // scroll lock. Editing the primitive would also reach every OTHER
            // `CommandList` consumer (`HeaderQuickConnect.tsx`,
            // `settings/sections/components/FormattersTable.tsx`, the command
            // palette) - checked, and none of them is a popover portaled
            // outside a modal Dialog the way this one is, so there is no
            // reason to believe they share the bug, and no reason to touch a
            // file this many other surfaces depend on to fix a problem that
            // is local to this one.
          >
            <CommandEmpty className="py-4 text-[11px]">{emptyLabel}</CommandEmpty>
            <CommandGroup>
              {options.map((o) => (
                <CommandItem
                  key={o.value}
                  value={o.search}
                  data-checked={o.value === value ? "true" : undefined}
                  onSelect={() => {
                    onChange(o.value);
                    setOpen(false);
                  }}
                  className="gap-2 rounded-xl px-2.5 py-1.5 text-[12px]"
                >
                  {o.hint ? (
                    <span className="flex min-w-0 flex-col">
                      <span className="truncate">{o.label}</span>
                      <span className="text-muted-foreground truncate font-mono text-[10px]">
                        {o.hint}
                      </span>
                    </span>
                  ) : (
                    <span className="truncate">{o.label}</span>
                  )}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
