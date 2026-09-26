import { Input } from "@/components/ui/input";
import { X } from "lucide-react";
import { useId, useRef, useState } from "react";

import { HOST_TAG_MAX_LENGTH, normalizeHostTags } from "../types";

// The host editor's tag field: chips with a remove button, plus a text input
// that commits a new chip on Enter or comma. Not `Combobox` (`./Combobox.tsx`):
// that component is built for "pick exactly one of these strings" - a group, a
// jump host, a desktop size - and every call site of it in this module wants a
// single value. This wants several, added and removed one at a time, which is
// a difference in shape, not styling.
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
  const inputRef = useRef<HTMLInputElement>(null);

  function commit(candidate: string): void {
    const next = normalizeHostTags([...tags, candidate]) ?? [];
    if (next.length <= tags.length) {
      // The normaliser dropped the candidate - a case-duplicate, or the
      // HOST_TAG_MAX_COUNT cap. Keep the draft rather than clearing it with
      // no sign anything happened.
      return;
    }
    onChange(next);
    setDraft("");
  }

  function remove(tag: string): void {
    const key = tag.toLowerCase();
    onChange(tags.filter((t) => t.toLowerCase() !== key));
    // The removed chip's own button unmounts with it, so keyboard focus would
    // otherwise fall back to the dialog container. Send it to the input.
    inputRef.current?.focus();
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
                className="text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-ring/50 flex size-5 items-center justify-center rounded outline-none focus-visible:ring-2"
              >
                <X size={11} strokeWidth={2} />
              </button>
            </span>
          ))}
        </div>
      ) : null}
      <Input
        ref={inputRef}
        list={listId}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          // An Enter pressed to confirm an IME (CJK) conversion must not
          // commit the unconverted draft as a tag - same guard as the Enter
          // handler in `src/modules/terminal/lib/session-lifecycle.ts`.
          if (e.nativeEvent.isComposing || e.keyCode === 229) return;
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
        maxLength={HOST_TAG_MAX_LENGTH}
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
