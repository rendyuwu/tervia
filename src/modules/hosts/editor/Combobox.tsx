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
          <CommandList className="max-h-56">
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
