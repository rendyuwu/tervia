import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  TRAILING_BTN_BASE,
  TRAILING_BTN_VARIANT,
  TRAILING_ICON_SIZE,
} from "@/modules/tabs/components/TrailingIconButton";
import type { LucideIcon } from "lucide-react";

/**
 * A trailing icon action on a real `<button>`: hover- or focus-revealed, icon
 * only, label in a tooltip and in `aria-label`.
 *
 * The sibling of `modules/tabs/components/TrailingIconButton.tsx`, which is the
 * same control rendered as a span carrying the button role and a hand-written
 * tab index. (Spelled out rather than quoted, so a grep for that attribute over
 * THIS file stays empty and means what it looks like it means.) Two components
 * because the element type is not a preference here - the span exists solely
 * because its one caller renders it inside a `TabsTrigger`, which Radix renders
 * as a real `<button>`, and a `<button>` inside a `<button>` is invalid HTML.
 * Anywhere that constraint does not apply, the control should be the real
 * element: a `<button>` has the role and the tab order natively, and turns
 * Enter and Space into a click without a hand-rolled key handler.
 *
 * Splitting rather than making the element a prop of one component is a
 * deliberate trade: the nested-button rule is enforced by walking what
 * `renderEntryBody.tsx` renders under its trigger and following each component
 * one import across, so "which element is this?" has to be answerable from the
 * import graph. Behind a prop it is not - passing the wrong value, or none, is
 * invisible to that walk. Two components makes the mistake an import, which is
 * exactly what the walk already reports.
 *
 * Styling is imported, not copied, so the two cannot drift into two
 * different-looking controls.
 */
export function IconActionButton({
  icon: Icon,
  label,
  onClick,
  variant = "default",
}: {
  icon: LucideIcon;
  label: string;
  onClick: () => void;
  variant?: keyof typeof TRAILING_BTN_VARIANT;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={label}
          // The propagation stops the span sibling carries, kept here so the
          // controls that were split apart differ in element type and nothing
          // else. In this component's current placement they suppress nothing:
          // its caller's wrapper is a plain `div` and no ancestor of it listens
          // for a pointer event. Copied ANYWAY, and the reason is worth
          // stating, because the tempting justification is the wrong one - an
          // unreachability argument is only as good as the enumeration of
          // affordances behind it, and this repo has already had to give one up
          // once. Zero delta against the behaviour these two chips have today
          // is a claim that stays true when someone adds a handler above them.
          //
          // No `onKeyDown` twin, though. A real `<button>` turns Enter and
          // Space into a synthesised `click`, so the click stop below already
          // covers the keyboard; a hand-rolled keydown beside it would be a
          // second activation route and a double-fire waiting for whoever drops
          // the `preventDefault` that masks it.
          //
          // Worth knowing before you touch them: NOTHING pins these four. The
          // span sibling's stops carry six checks in `rail-views-verify.ts`,
          // because there they hold a real invariant; here they are defensive,
          // so what covers this file is the element type and the styling
          // import, and all four of these could be deleted with the suite
          // green. The paragraph above is the only thing arguing for them.
          onPointerDown={(ev) => ev.stopPropagation()}
          onMouseDown={(ev) => ev.stopPropagation()}
          onFocus={(ev) => ev.stopPropagation()}
          onClick={(ev) => {
            ev.stopPropagation();
            onClick();
          }}
          className={cn(TRAILING_BTN_BASE, TRAILING_BTN_VARIANT[variant])}
        >
          <Icon size={TRAILING_ICON_SIZE} strokeWidth={2} />
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}
