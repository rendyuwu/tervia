import { Input } from "@/components/ui/input";
import { X } from "lucide-react";
import { useId, useState } from "react";

import { normalizeHostTags } from "../types";

// The host editor's tag field: chips with a remove button, plus a text input
// that commits a new chip on Enter or comma. Not `Combobox` (`./Combobox.tsx`):
// that component is built for "pick exactly one of these strings" - a group, a
// jump host, a desktop size - and every one of its four call sites in this
// module wants a single value. This wants several, added and removed one at a
// time, which is a difference in shape, not styling.
//
// A native `<datalist>` backs the suggestions rather than a second popover:
// it needs no new dependency, and a suggestion here is a typing aid, not a
// constraint - `normalizeHostTags` still runs on every commit and again on
// save, so a typo the datalist did not catch is caught there instead.

export type TagsInputProps = {
  tags: readonly string[];
  onChange: (tags: readonly string[]) => void;
  /** Every tag already used across saved hosts, offered through the
   *  `<datalist>`. Exact stored spellings, not deduped across case - the
   *  datalist is a hint, and `normalizeHostTags` is what actually dedupes. */
  suggestions: readonly string[];
};

export function TagsInput({ tags, onChange, suggestions }: TagsInputProps) {
  const [draft, setDraft] = useState("");
  const listId = useId();

  function commit(candidate: string): void {
    const next = normalizeHostTags([...tags, candidate]);
    onChange(next ?? []);
    setDraft("");
  }

  function remove(tag: string): void {
    const key = tag.toLowerCase();
    onChange(tags.filter((t) => t.toLowerCase() !== key));
  }

  return (
    <div className="flex flex-col gap-1.5">
      {tags.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {tags.map((tag) => (
            <span
              key={tag}
              className="border-border inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs"
            >
              {tag}
              <button
                type="button"
                aria-label={`Remove tag ${tag}`}
                onClick={() => remove(tag)}
                className="text-muted-foreground hover:text-foreground"
              >
                <X size={11} strokeWidth={2} />
              </button>
            </span>
          ))}
        </div>
      ) : null}
      <Input
        list={listId}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            if (draft.trim()) commit(draft);
          } else if (e.key === "Backspace" && draft === "" && tags.length > 0) {
            remove(tags[tags.length - 1]);
          }
        }}
        // A typed-but-not-committed tag on blur (tabbing to the next field, or
        // closing the dialog straight from here) is not silently dropped - it
        // commits the same way Enter or a comma would.
        onBlur={() => {
          if (draft.trim()) commit(draft);
        }}
        placeholder="Add a tag…"
        spellCheck={false}
        autoComplete="off"
        className="h-8 text-[12px]"
      />
      <datalist id={listId}>
        {suggestions.map((s) => (
          <option key={s} value={s} />
        ))}
      </datalist>
    </div>
  );
}
