import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { LucideIcon } from "lucide-react";

/** Trailing icon button styling. Only close lives here; rotate and move are in the right-click menu. */
const TRAILING_BTN_BASE =
  "inline-flex size-3.5 shrink-0 cursor-pointer items-center justify-center rounded opacity-0 transition-opacity group-hover:opacity-60";

const TRAILING_BTN_VARIANT = {
  default: "text-current hover:bg-accent hover:opacity-100",
  danger: "hover:bg-destructive/10 hover:text-destructive hover:opacity-100",
} as const;

const TRAILING_ICON_SIZE = 9;

export function TrailingIconButton({
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
        <span
          // A span carrying the button ROLE, and not a `<button>`, because the
          // only caller renders this INSIDE `TabsTrigger`, which Radix renders
          // as a real `<button>`. A `<button>` nested in a `<button>` is
          // invalid HTML: React logs it, and the parser is entitled to close
          // the outer one early and reparent this out of the chip, which would
          // leave the X painted where it is and hit-testable somewhere else.
          //
          // `tabIndex={0}`, not `-1`, because the `<button>` this replaced was
          // keyboard-reachable and a fix aimed at the DOM must not quietly
          // delete a control the user can reach today. That reachability is
          // what the `onKeyDown` below is for: a span gets no synthesised
          // click from Enter or Space, so without it the X would be focusable
          // and dead.
          role="button"
          tabIndex={0}
          aria-label={label}
          // FOUR separate native events, and the X has to stop all four,
          // because closing a tab must never first ACTIVATE it - a background
          // tab's X under an open Vault or Port Forwarding view would otherwise
          // throw the user out of the view they were reading (`tabView.ts`'s
          // `rehomeTabView`: a removal is not a route into the tab area).
          // Naming them individually rather than as "so click doesn't activate
          // the tab or start a drag", which is what the old comment said while
          // stopping only two of them:
          //
          // - pointerdown: dnd-kit's `PointerSensor` activator on the enclosing
          //   trigger. Without it a press on the X starts a tab drag.
          // - mousedown: Radix's OWN activation route. `TabsTrigger`'s
          //   `onMouseDown` calls `context.onValueChange(value)` with no guard
          //   on the current value, so for a BACKGROUND chip the value really
          //   does change, `useControllableState` lets it through, and
          //   `focusTabView` clears `railView` before `onCloseEntry` runs.
          //   A separate event from pointerdown - stopping that one does not
          //   stop this one, which is exactly how it was missed.
          // - click: the trigger's own select route (`lib/selectEntry.ts`),
          //   which is unconditional on purpose and so fires on the X too.
          // - keydown: `TabsTrigger` activates on Enter and Space. An unstopped
          //   keydown from a focused X therefore selects the very tab it is
          //   closing - the keyboard's copy of the mousedown route above, and
          //   the one the `<button>` never had, since a button's Enter/Space
          //   arrives at the trigger as a synthesised `click` that the click
          //   stop already caught. `preventDefault` before the stop, so Space
          //   does not also scroll the strip.
          //
          // Stopped here at the X rather than by teaching those handlers what
          // an X is: the trigger's route stays unconditional, which is what
          // makes an already-active chip clickable at all.
          onPointerDown={(ev) => ev.stopPropagation()}
          onMouseDown={(ev) => ev.stopPropagation()}
          onClick={(ev) => {
            ev.stopPropagation();
            onClick();
          }}
          onKeyDown={(ev) => {
            if (ev.key !== "Enter" && ev.key !== " ") return;
            ev.preventDefault();
            ev.stopPropagation();
            onClick();
          }}
          className={cn(TRAILING_BTN_BASE, TRAILING_BTN_VARIANT[variant])}
        >
          <Icon size={TRAILING_ICON_SIZE} strokeWidth={2} />
        </span>
      </TooltipTrigger>
      <TooltipContent side="bottom">{label}</TooltipContent>
    </Tooltip>
  );
}
