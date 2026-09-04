/**
 * Import/Export live here because the Hosts page replaced the header SSH
 * dropdown that used to own these two actions (`SshMenu.tsx`, before 6d).
 * Ported near verbatim - the state and the dialog are unchanged, only the
 * presentation (two page buttons instead of two menu items) and the error
 * placement (next to the buttons instead of inside a menu that has already
 * closed by then) differ. `openImport`'s ordering gained one more step in
 * VLT-60: the envelope is validated between the read and the dialog opening,
 * not only picked-then-read-then-opened.
 *
 * The format is **v3**, and v1 and v2 files are refused by name rather than by
 * a parse error - which is why the picker still offers the v1 extension. A v3
 * payload now carries identities, keys and forward rules alongside the hosts
 * and groups, so this page - which shows only vault-bound hosts - sealing all
 * five collections into one backup is expected, not a mismatch to puzzle over.
 */
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/toast";
import type { FsReadResult } from "@/lib/ipc";
import type { BackupMode } from "@/modules/backup/BackupDialog";
import { BACKUP_EXTENSION, BACKUP_EXTENSION_V1, parseBackupFile } from "@/modules/backup/file";
import { invoke } from "@tauri-apps/api/core";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { Download, Upload } from "lucide-react";
import { lazy, Suspense, useState, type ReactNode } from "react";

// Same treatment SshMenu gave it: the backup dialog pulls in the crypto/IO
// path, which nobody pays for until they actually move machines.
const BackupDialog = lazy(() =>
  import("@/modules/backup/BackupDialog").then((m) => ({ default: m.BackupDialog })),
);

export function HostsBackupActions(): ReactNode {
  const [backup, setBackup] = useState<BackupMode | null>(null);
  const [backupOpen, setBackupOpen] = useState(false);

  const openExport = () => {
    setBackup({ kind: "export" });
    setBackupOpen(true);
  };

  // The file is picked, read, AND its envelope validated - all before the
  // dialog opens - so an unreadable, wrong-type, or plainly non-Tervia file is
  // rejected up front instead of after the user has typed a passphrase for it.
  const openImport = async () => {
    try {
      const selected = await openFileDialog({
        multiple: false,
        filters: [
          {
            name: "Tervia backup",
            // The v1 extension stays offered even though v1 no longer imports:
            // a filtered-out file gives the user nothing to click and no reason
            // why, where picking one reaches the refusal that names the format
            // and says there is no converter.
            extensions: [BACKUP_EXTENSION, BACKUP_EXTENSION_V1, "json"],
          },
        ],
      });
      const path = typeof selected === "string" ? selected : null;
      if (!path) return;
      const result = await invoke<FsReadResult>("fs_read_file", { path });
      if (result.kind !== "text") {
        toast("That file is not a UTF-8 text file.", { variant: "error" });
        return;
      }
      // The envelope - kind, version, and for v2 the presence of a sealed
      // payload block - is exactly what `parseBackupFile` can establish WITHOUT
      // a passphrase: v2 seals the inventory itself, but not the wrapper around
      // it, and v1's inventory is plaintext anyway. Checking it here, before the
      // dialog ever asks for a secret, means a plainly non-Tervia file is
      // rejected on the pick instead of after the user has typed a passphrase
      // for a file that was never going to be read. `applyBackup` runs this
      // same check again on its own input regardless - a function reachable on
      // its own should not trust that some caller already validated it - so
      // this is a duplicate ahead of the prompt, not a relocation of the only
      // check.
      let raw: unknown;
      try {
        raw = JSON.parse(result.content);
      } catch {
        toast("That file is not valid JSON.", { variant: "error" });
        return;
      }
      try {
        parseBackupFile(raw);
      } catch (e) {
        toast(e instanceof Error ? e.message : String(e), { variant: "error" });
        return;
      }
      setBackup({ kind: "import", path, text: result.content });
      setBackupOpen(true);
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), { variant: "error" });
    }
  };

  return (
    <div className="flex items-center gap-2">
      {/* Label hidden below the same `@container` threshold "New host" uses
          (HostsPage.tsx) - this file has no `@container` of its own, so the
          query resolves against the page root that already wraps it. `hidden`
          drops the span from the flex layout entirely, so each button floors
          at icon + `px-3` padding (~37px) instead of icon-plus-text. The
          `aria-label` stays SEPARATE from that span (see `CardAction` in
          HostCard.tsx for the same split): a hidden span still has an
          accessible name via the DOM, but relying on that would make the
          collapsed state's accessible name silently track whatever text the
          span happens to hold, rather than being an explicit, always-present
          label. */}
      {/* DCR-3 (owner, 2026-08-28): the DESKTOP arrow convention - export
          points OUT of the box, import points IN. Lucide's `Upload` is an
          arrow leaving a tray and `Download` an arrow entering one, so the two
          names read backwards against these two labels and that is the whole
          swap. What shipped first was the WEB-FORM convention ("download the
          result" / "upload your file"); both are live conventions, which is why
          this was never a defect and why it needs a comment and a check rather
          than looking self-evident. Accepted residual, stated when the decision
          was made: a bare arrow still reads backwards to someone arriving from
          web tooling. Below 420px both labels collapse and the arrow IS the
          affordance - `scripts/hosts-header-narrow-verify.ts` owns both facts. */}
      <Button
        variant="outline"
        size="sm"
        onClick={openExport}
        aria-label="Export…"
        className="gap-1.5"
      >
        <Upload size={13} strokeWidth={1.75} />
        <span className="@max-[420px]:hidden">Export…</span>
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={() => void openImport()}
        aria-label="Import…"
        className="gap-1.5"
      >
        <Download size={13} strokeWidth={1.75} />
        <span className="@max-[420px]:hidden">Import…</span>
      </Button>
      {/* The menu this replaces closed itself before a failed pick could be
          reported, so the message had nowhere to land - the improvement is a
          surface that outlives the click. VLT-36: that surface used to be an
          inline line with NO dismiss of its own - cleared only implicitly, at
          the top of the next `openExport`/`openImport`, so a failed pick from
          one attempt could sit here through several unrelated successful
          ones. `toast()` outlives it more completely than an inline line ever
          did (it is not even tied to this component's mount), expires on its
          own, and - new on this surface - gets an actual dismiss `×`. */}

      {/* Unmounted once closed: the dialog holds a passphrase and, for an
          import, the decrypted file text in state, so there is no reason to
          keep either resident for a close animation. */}
      {backup ? (
        <Suspense fallback={null}>
          <BackupDialog
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
