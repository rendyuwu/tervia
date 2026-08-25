/**
 * Import/Export live here because the Hosts page replaced the header SSH
 * dropdown that used to own these two actions (`SshMenu.tsx`, before 6d).
 * Ported near verbatim - the state, the dialog, and the pick-then-read-then-open
 * ordering in `openImport` below are unchanged, only the presentation (two page
 * buttons instead of two menu items) and the error placement (next to the
 * buttons instead of inside a menu that has already closed by then) differ.
 *
 * The payload this writes and reads is still backup **v2** - SSH and RDP hosts
 * and their credentials, sealed as one blob. 6g takes it to v3, where
 * identities, keys and forward rules travel alongside the hosts. A reader who
 * finds a v2 writer on a page that shows vault-bound hosts should not have to
 * guess whether that is a bug: it is not, yet.
 */
import { Button } from "@/components/ui/button";
import type { FsReadResult } from "@/lib/ipc";
import type { BackupMode } from "@/modules/ssh/SshBackupDialog";
import { BACKUP_EXTENSION, BACKUP_EXTENSION_V1 } from "@/modules/ssh/backupFile";
import { invoke } from "@tauri-apps/api/core";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { Download, Upload } from "lucide-react";
import { lazy, Suspense, useState, type ReactNode } from "react";

import { useHosts } from "../useHosts";

// Same treatment SshMenu gave it: the backup dialog pulls in the crypto/IO
// path, which nobody pays for until they actually move machines.
const SshBackupDialog = lazy(() =>
  import("@/modules/ssh/SshBackupDialog").then((m) => ({ default: m.SshBackupDialog })),
);

export function HostsBackupActions(): ReactNode {
  // Only for the Export button's enabled state: one backup covers both
  // protocols, so an empty SSH-only view of the store would be the wrong
  // thing to check - only every host being gone makes the export empty.
  const hosts = useHosts();
  const [backup, setBackup] = useState<BackupMode | null>(null);
  const [backupOpen, setBackupOpen] = useState(false);
  const [pickError, setPickError] = useState<string | null>(null);

  const openExport = () => {
    setPickError(null);
    setBackup({ kind: "export" });
    setBackupOpen(true);
  };

  // The file is picked and read BEFORE the dialog opens, so an unreadable or
  // wrong-type file is rejected up front instead of after the user has typed a
  // passphrase for it.
  const openImport = async () => {
    setPickError(null);
    try {
      const selected = await openFileDialog({
        multiple: false,
        filters: [
          {
            name: "Tervia backup",
            // The v1 extension stays offered: those files still import.
            extensions: [BACKUP_EXTENSION, BACKUP_EXTENSION_V1, "json"],
          },
        ],
      });
      const path = typeof selected === "string" ? selected : null;
      if (!path) return;
      const result = await invoke<FsReadResult>("fs_read_file", { path });
      if (result.kind !== "text") {
        setPickError("That file is not a UTF-8 text file.");
        return;
      }
      setBackup({ kind: "import", path, text: result.content });
      setBackupOpen(true);
    } catch (e) {
      setPickError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="flex items-center gap-2">
      <Button
        variant="outline"
        size="sm"
        onClick={openExport}
        disabled={hosts.size === 0}
        className="gap-1.5"
      >
        <Download size={13} strokeWidth={1.75} />
        Export…
      </Button>
      <Button variant="outline" size="sm" onClick={() => void openImport()} className="gap-1.5">
        <Upload size={13} strokeWidth={1.75} />
        Import…
      </Button>
      {/* The one improvement over the menu this replaces: the menu closed
          itself before a failed pick could be reported, so the message had
          nowhere to land. This surface stays on screen. */}
      {pickError ? <span className="text-destructive text-[11px]">{pickError}</span> : null}

      {/* Unmounted once closed: the dialog holds a passphrase and, for an
          import, the decrypted file text in state, so there is no reason to
          keep either resident for a close animation. */}
      {backup ? (
        <Suspense fallback={null}>
          <SshBackupDialog
            open={backupOpen}
            onOpenChange={(o) => {
              setBackupOpen(o);
              if (!o) setBackup(null);
            }}
            mode={backup}
          />
        </Suspense>
      ) : null}
    </div>
  );
}
