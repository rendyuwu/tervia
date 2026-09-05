import type { SshHost } from "../types";
import { Combobox } from "./Combobox";
import { Field } from "./FormControls";
import { savedHostOptions } from "./hostOptions";

// The SSH-only row: the jump host.
//
// What used to sit beside it is gone rather than moved. Port forwarding was
// edited here against `SshConnection.forwards`; `Host` carries no such field,
// because a forward rule is now its own record, edited on its own page instead
// of buried in the per-host dialog.

export function SshOptions({
  hosts,
  proxyJumpId,
  onChange,
}: {
  /** Every saved SSH host except the one being edited. */
  hosts: SshHost[];
  proxyJumpId: string;
  onChange: (proxyJumpId: string) => void;
}) {
  return (
    <Field label="Jump host (optional)">
      <Combobox
        options={savedHostOptions(hosts, "None (direct connection)")}
        value={proxyJumpId}
        onChange={onChange}
        searchPlaceholder="Search saved hosts…"
        emptyLabel="No saved host found."
      />
      <span className="text-muted-foreground text-[10.5px]">
        Tunnel through another saved host to reach this one (ProxyJump). Chains transitively if the
        jump host has its own jump host.
      </span>
    </Field>
  );
}
