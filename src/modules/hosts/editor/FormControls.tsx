import type { ReactNode } from "react";

// The two presentational primitives both connection dialogs carried a private
// copy of. Shared here because the merged editor needs each of them twice - the
// label wrapper on every row, and the segmented button for the protocol toggle as
// well as the SSH auth tabs - and two toggles that look almost the same read as a
// bug.

/** A label above one control. */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-muted-foreground text-[11px] font-medium tracking-tight">{label}</span>
      {children}
    </div>
  );
}

/** One segment of a small exclusive group. */
export function ToggleButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        "flex cursor-pointer items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11.5px] transition-colors " +
        (active
          ? "border-accent bg-accent/60"
          : "border-border/60 hover:bg-accent/30 bg-transparent")
      }
    >
      {children}
    </button>
  );
}
