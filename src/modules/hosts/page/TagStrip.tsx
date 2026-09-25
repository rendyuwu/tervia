/**
 * The Hosts page's tag filter strip: one chip per tag in use, multi-select,
 * plus a clear action once any are selected. A sibling to `GroupStrip.tsx`
 * rather than grown inside it - that file is already the nested-group tree
 * plus its own create/rename/move/delete UI, and a flat multi-select row needs
 * none of that machinery, only the `Chip` it already exports.
 */
import { X } from "lucide-react";
import type { ReactNode } from "react";

import type { TagCount, TagFilter } from "./derive";
import { Chip } from "./GroupStrip";

export type TagStripProps = {
  /** Every tag in use, one entry per canonical spelling - see `tagCounts` in
   *  `./derive`. */
  tags: readonly TagCount[];
  /** Lowercased tag keys currently selected. */
  selected: TagFilter;
  /** Toggle one tag, by its lowercased key. */
  onToggle: (key: string) => void;
  onClear: () => void;
};

/** `null` rather than an empty strip, so a fleet with no tags shows no empty
 *  bar above the grid. */
export function TagStrip({ tags, selected, onToggle, onClear }: TagStripProps): ReactNode {
  if (tags.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Tags">
      {tags.map((entry) => {
        const key = entry.tag.toLowerCase();
        return (
          <Chip
            key={key}
            label={entry.tag}
            count={entry.count}
            selected={selected.has(key)}
            onClick={() => onToggle(key)}
          />
        );
      })}
      {selected.size > 0 ? (
        <button
          type="button"
          aria-label="Clear tag filter"
          onClick={onClear}
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-xs transition-colors"
        >
          <X size={12} strokeWidth={2} />
          Clear
        </button>
      ) : null}
    </div>
  );
}
