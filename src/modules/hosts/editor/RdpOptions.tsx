import {
  RDP_DEFAULT_PRESET,
  RDP_FIT_SIZE_ID,
  RDP_SIZE_PRESETS,
  type RdpClipboardMode,
  type SshHost,
} from "../types";
import { Combobox, type ComboboxOption } from "./Combobox";
import { Field } from "./FormControls";
import { savedHostOptions } from "./hostOptions";

// The three RDP-only rows: the negotiated desktop size, the SSH host to tunnel
// through, and which directions the clipboard carries.

const SIZE_OPTIONS: ComboboxOption[] = [
  { value: RDP_FIT_SIZE_ID, label: "Fit to pane", search: "fit pane follow resize automatic" },
  ...RDP_SIZE_PRESETS.map((p) => ({
    value: p.id,
    label: p.label,
    search: `${p.label} ${p.id}`,
  })),
];

const CLIPBOARD_OPTIONS: ComboboxOption[] = [
  { value: "both", label: "Both directions", search: "clipboard copy paste both" },
  { value: "hostToRemote", label: "This machine to remote only", search: "clipboard copy out" },
  { value: "remoteToHost", label: "Remote to this machine only", search: "clipboard paste in" },
  { value: "off", label: "Off", search: "clipboard disabled off none" },
];

export function RdpOptions({
  sshHosts,
  presetId,
  tunnelSshHostId,
  clipboardMode,
  onPresetChange,
  onTunnelChange,
  onClipboardChange,
}: {
  /** Saved SSH hosts, offered as tunnels. The whole list: any host that can reach
   *  the target's 3389 works, and it is usually not the target itself - a Linux
   *  jump box on the same network needs nothing installed on the Windows side. */
  sshHosts: SshHost[];
  presetId: string;
  tunnelSshHostId: string;
  clipboardMode: RdpClipboardMode;
  onPresetChange: (presetId: string) => void;
  onTunnelChange: (sshHostId: string) => void;
  onClipboardChange: (mode: RdpClipboardMode) => void;
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
          {presetId === RDP_FIT_SIZE_ID ? (
            <>
              The desktop is resized to match the pane as you drag it. This needs the server's
              Display Control channel, which Windows Server 2012 and later have; a server without it
              stays at {RDP_DEFAULT_PRESET.label} and the pane letterboxes it.
            </>
          ) : (
            <>
              The desktop is negotiated at this size and the pane letterboxes it, so a pane that is
              not the same shape shows bars rather than cropping.
            </>
          )}
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

      <Field label="Clipboard">
        <Combobox
          options={CLIPBOARD_OPTIONS}
          value={clipboardMode}
          onChange={(value) => onClipboardChange(value as RdpClipboardMode)}
          searchPlaceholder="Search clipboard modes…"
          emptyLabel="No matching mode."
        />
        <span className="text-muted-foreground text-[10.5px]">
          {clipboardMode === "off" ? (
            <>
              The clipboard channel is not opened at all, so the server is never told this
              connection has a clipboard.
            </>
          ) : (
            <>
              Text and images are carried across; files are not. The transfer happens as focus
              enters and leaves the pane, so a copy made without leaving it is picked up on the next
              switch.
            </>
          )}
        </span>
      </Field>
    </>
  );
}
