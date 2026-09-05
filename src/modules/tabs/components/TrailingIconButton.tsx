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
        <button
          type="button"
          aria-label={label}
          // THREE separate native events, and the X has to stop all three,
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
          //
          // Stopped here at the button rather than by teaching those handlers
          // what an X is: the trigger's route stays unconditional, which is what
          // makes an already-active chip clickable at all.
          onPointerDown={(ev) => ev.stopPropagation()}
          onMouseDown={(ev) => ev.stopPropagation()}
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
