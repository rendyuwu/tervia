import { RDP_SIZE_PRESETS, type SshHost } from "../types";
import { Combobox, type ComboboxOption } from "./Combobox";
import { Field } from "./FormControls";
import { savedHostOptions } from "./hostOptions";

// The two RDP-only rows: the negotiated desktop size, and the SSH host to tunnel
// through.

const SIZE_OPTIONS: ComboboxOption[] = RDP_SIZE_PRESETS.map((p) => ({
  value: p.id,
  label: p.label,
  search: `${p.label} ${p.id}`,
}));

export function RdpOptions({
  sshHosts,
  presetId,
  tunnelSshHostId,
  onPresetChange,
  onTunnelChange,
}: {
  /** Saved SSH hosts, offered as tunnels. The whole list: any host that can reach
   *  the target's 3389 works, and it is usually not the target itself - a Linux
   *  jump box on the same network needs nothing installed on the Windows side. */
  sshHosts: SshHost[];
  presetId: string;
  tunnelSshHostId: string;
  onPresetChange: (presetId: string) => void;
  onTunnelChange: (sshHostId: string) => void;
}) {
  const selectedTunnel = sshHosts.find((h) => h.id === tunnelSshHostId);

  return (
    <>
      <Field label="Desktop size">
        <Combobox
          options={SIZE_OPTIONS}
          value={presetId}
          onChange={onPresetChange}
          searchPlaceholder="Search sizes…"
          emptyLabel="No matching size."
        />
        <span className="text-muted-foreground text-[10.5px]">
          The desktop is negotiated at this size and the pane letterboxes it, so a pane that is not
          the same shape shows bars rather than cropping. Resizing the desktop to follow the pane is
          a later change.
        </span>
      </Field>

      <Field label="SSH tunnel (optional)">
        <Combobox
          options={savedHostOptions(sshHosts, "None (dial the host directly)")}
          value={tunnelSshHostId}
          onChange={onTunnelChange}
          searchPlaceholder="Search saved SSH hosts…"
          emptyLabel="No saved SSH host found."
        />
        <span className="text-muted-foreground text-[10.5px]">
          {selectedTunnel ? (
            <>
              Host and port above are resolved{" "}
              <span className="font-medium">from {selectedTunnel.name}</span>, not from this machine
              — so a Windows box with no public 3389 is reached at its private address. The SSH host
              needs nothing installed and does not have to be the Windows machine itself; anything
              that can reach its 3389 will do. Its own jump-host chain applies too.
            </>
          ) : (
            <>
              Reach this host through a saved SSH connection instead of dialling it directly, for a
              machine whose 3389 is not exposed. The trusted certificate is the same either way.
            </>
          )}
        </span>
      </Field>
    </>
  );
}
