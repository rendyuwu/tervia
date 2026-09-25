import { cn } from "@/lib/utils";
import {
  Cloud,
  Container,
  Database,
  Globe,
  Laptop,
  Monitor,
  Router,
  Server,
  Shield,
  Terminal,
  type LucideIcon,
} from "lucide-react";

import { Field, ToggleButton } from "./editor/FormControls";
import {
  HOST_COLOR_IDS,
  HOST_ICON_IDS,
  hostColorId,
  hostIconId,
  type HostColorId,
  type HostIconId,
} from "./types";

// Draws a host's optional icon and colour. The stored ids live in `./types.ts`;
// this file only turns them into a lucide component or a colour class. Colours
// are the active theme's ANSI tokens, each written out as a literal class so
// Tailwind's source scan emits it. Nothing here reads or writes the store.

const HOST_ICONS: Record<HostIconId, { label: string; Icon: LucideIcon }> = {
  server: { label: "Server", Icon: Server },
  database: { label: "Database", Icon: Database },
  globe: { label: "Web", Icon: Globe },
  cloud: { label: "Cloud", Icon: Cloud },
  monitor: { label: "Desktop", Icon: Monitor },
  laptop: { label: "Laptop", Icon: Laptop },
  terminal: { label: "Shell", Icon: Terminal },
  shield: { label: "Firewall", Icon: Shield },
  router: { label: "Network device", Icon: Router },
  container: { label: "Container", Icon: Container },
};

const HOST_COLORS: Record<HostColorId, { label: string; className: string }> = {
  red: { label: "Red", className: "text-[color:var(--tervia-ansi-red)]" },
  yellow: { label: "Yellow", className: "text-[color:var(--tervia-ansi-yellow)]" },
  green: { label: "Green", className: "text-[color:var(--tervia-ansi-green)]" },
  cyan: { label: "Cyan", className: "text-[color:var(--tervia-ansi-cyan)]" },
  blue: { label: "Blue", className: "text-[color:var(--tervia-ansi-blue)]" },
  magenta: { label: "Magenta", className: "text-[color:var(--tervia-ansi-magenta)]" },
};

/** The host's icon in its colour (muted without one), else a swatch of its
 *  colour, else nothing - the card as it was before either field existed.
 *  Decorative: the host name always sits beside it. */
export function HostGlyph({ icon, color }: { icon?: string; color?: string }) {
  const iconId = hostIconId(icon);
  const colorId = hostColorId(color);
  const tint = colorId ? HOST_COLORS[colorId].className : "text-muted-foreground";
  if (iconId) {
    const { Icon } = HOST_ICONS[iconId];
    return <Icon size={14} strokeWidth={1.75} aria-hidden className={cn("shrink-0", tint)} />;
  }
  if (colorId) return <span aria-hidden className={cn("size-2.5 shrink-0 bg-current", tint)} />;
  return null;
}

/** The editor's icon and colour rows. A stored id this build does not know
 *  leaves no button pressed, and the draft keeps it until the user picks. */
export function HostAppearancePicker({
  icon,
  color,
  onIconChange,
  onColorChange,
}: {
  icon: string;
  color: string;
  onIconChange: (icon: string) => void;
  onColorChange: (color: string) => void;
}) {
  return (
    <>
      <Field label="Icon (optional)">
        <div role="group" aria-label="Icon" className="flex flex-wrap gap-1">
          <ToggleButton active={icon === ""} onClick={() => onIconChange("")}>
            None
          </ToggleButton>
          {HOST_ICON_IDS.map((id) => {
            const { label, Icon } = HOST_ICONS[id];
            return (
              <ToggleButton
                key={id}
                active={icon === id}
                onClick={() => onIconChange(id)}
                title={label}
              >
                <Icon size={14} strokeWidth={1.75} aria-hidden />
                <span className="sr-only">{label}</span>
              </ToggleButton>
            );
          })}
        </div>
      </Field>
      <Field label="Color (optional)">
        <div role="group" aria-label="Color" className="flex flex-wrap gap-1">
          <ToggleButton active={color === ""} onClick={() => onColorChange("")}>
            None
          </ToggleButton>
          {HOST_COLOR_IDS.map((id) => {
            const { label, className } = HOST_COLORS[id];
            return (
              <ToggleButton key={id} active={color === id} onClick={() => onColorChange(id)}>
                <span aria-hidden className={cn("size-2.5 shrink-0 bg-current", className)} />
                {label}
              </ToggleButton>
            );
          })}
        </div>
      </Field>
    </>
  );
}
