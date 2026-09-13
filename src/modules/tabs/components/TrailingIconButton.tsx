import { cn } from "@/lib/utils";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { LucideIcon } from "lucide-react";

/**
 * Trailing icon button styling. Only close lives here; rotate and move are in
 * the right-click menu.
 *
 * Exported rather than module-private because `components/IconActionButton.tsx`
 * is this same control on a real `<button>` - see the element comment below for
 * why there are two of them. One base string, one variant map, one icon size,
 * imported by both, so two elements cannot become two different-looking
 * controls.
 *
 * The reveal carries `group-focus-within` and `focus-visible` beside
 * `group-hover` because this control is keyboard-reachable (`tabIndex={0}`
 * below). Without them a keyboard user focuses something at `opacity-0`: the
 * control is invisible and so is its focus ring.
 */
export const TRAILING_BTN_BASE =
  "inline-flex size-3.5 shrink-0 cursor-pointer items-center justify-center rounded opacity-0 transition-opacity group-focus-within:opacity-60 group-hover:opacity-60 focus-visible:opacity-100";

export const TRAILING_BTN_VARIANT = {
  default: "text-current hover:bg-accent hover:opacity-100",
  danger: "hover:bg-destructive/10 hover:text-destructive hover:opacity-100",
} as const;

export const TRAILING_ICON_SIZE = 9;

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
          // as a real `<button>`.
          //
          // That sentence is true as written for the first time. The Hosts
          // page's group filter strip used to render this component too, as a
          // DOM sibling of a real `<button>` inside a plain `div` - inside no
          // button at all - and so paid this element's cost for a constraint
          // that never reached it. It renders `components/IconActionButton.tsx`
          // now: the same control, on a real `<button>`, with native activation
          // instead of the hand-rolled `onKeyDown` below. A third caller picks
          // whichever of the two its parent element allows.
          //
          // A `<button>` nested in a `<button>` is invalid HTML, and the
          // reachable consequence is the React warning: `validateDOMNesting`
          // logs it, on every closable entry, in a development build. A
          // production build is silent about it, which is why nobody saw it
          // for as long as they did.
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
          // FIVE separate native events, stopped here because closing a tab
          // must never first ACTIVATE it - a background tab's X under an open
          // Vault or Port Forwarding view would otherwise throw the user out of
          // the view they were reading (`tabView.ts`'s `rehomeTabView`: a
          // removal is not a route into the tab area).
          //
          // What makes the set of five the right set, in the one sense that can
          // be checked: these are the events an ancestor has an activation
          // handler for AND that reach it from a target inside the X. Radix's
          // tabs trigger handles `onMouseDown`, `onKeyDown` and `onFocus`;
          // dnd-kit's `PointerSensor` activates on pointerdown; the strip's own
          // select route runs on click.
          //
          // Reaching is not the same as arriving somewhere that acts, and one
          // of the five turns out not to: the trigger's `onKeyDown` guards on
          // the target, so that stop is DEFENSIVE and is marked so below. The
          // criterion predicts that exception rather than being contradicted by
          // it - the handler exists, the event reaches it, and the handler
          // declines.
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
          // - focus: the one the other four leave open, and it has two ways in.
          //   Of the trigger's three activation handlers, `onKeyDown` is the
          //   ONLY one that tests `event.target !== event.currentTarget` - so
          //   mousedown and focus both activate from a descendant target, and
          //   focus arrives on the bubbling `focusin` that React maps `onFocus`
          //   to. Under Radix's default automatic activation `!isSelected`
          //   holds for every background chip, and `onFocus` is the only one of
          //   the three that tests it at all (`lib/selectEntry.ts` records that
          //   half from the other side). Both ways in are live:
          //     - Tab key. Radix's roving-focus item gives the strip a single
          //       tab stop, so a background trigger sits at `tabIndex={-1}`
          //       while every X inside one stays at `0`. Tab-walking the strip
          //       lands on the X directly, without ever focusing a trigger.
          //       No mouse, no platform behaviour - this is the deterministic
          //       half.
          //     - Mouse. `stopPropagation` on mousedown does not cancel its
          //       DEFAULT action, which focuses the nearest focusable element -
          //       this span, because of the `tabIndex={0}` above. Whether
          //       mousedown focuses it is the webview's call, so this half is
          //       platform-conditional.
          //   The stop also swallows the roving-focus item's own `onFocus`,
          //   which is how the group learns its tab stop moved, so the strip's
          //   tab stop stops following the X. Benign - the X is not somewhere
          //   the arrow keys should land - and said here because a stop's
          //   stated reason has to be what it actually does.
          // - keydown: DEFENSIVE, and the odd one out. `TabsTrigger` does
          //   activate on Enter and Space, but its `onKeyDown` returns early
          //   when `event.target !== event.currentTarget`, so a keydown
          //   originating on the X never reaches that branch. What this stop
          //   covers is a Radix version without that guard, and ancestor
          //   handlers that make no such test. It is not the thing holding the
          //   invariant. Nor is the `preventDefault` beside it: Space's default
          //   action is a scroll in the block direction, and there is nothing
          //   above this element for it to act on - the strip is
          //   `overflow-y-hidden`, no ancestor between it and the root scrolls
          //   vertically, and `globals.css` puts `overflow: hidden` on `body`.
          //   Kept, because it costs nothing and is right by default for a
          //   synthesised activation, but what it guards is a scroll container
          //   appearing above the strip later and a webview whose default
          //   differs. The load-bearing parts of this handler are the two key
          //   tests and the `onClick()` call - without that call the X is
          //   focusable and dead, because a span gets no synthesised click from
          //   Enter or Space. A `<button>` needs neither the handler nor either
          //   guard; this element needs the handler.
          //
          // Stopped here at the X rather than by teaching those handlers what
          // an X is: the trigger's route stays unconditional, which is what
          // makes an already-active chip clickable at all.
          //
          // NOT fixed here: the mouse route leaves focus on the X, which then
          // unmounts with the tab it just closed, so focus falls to `<body>`.
          onPointerDown={(ev) => ev.stopPropagation()}
          onMouseDown={(ev) => ev.stopPropagation()}
          onClick={(ev) => {
            ev.stopPropagation();
            onClick();
          }}
          onFocus={(ev) => ev.stopPropagation()}
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
