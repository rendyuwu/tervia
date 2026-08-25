import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { IconTooltip } from "@/components/ui/icon-tooltip";
import { cn } from "@/lib/utils";
import { DESTRUCTIVE_ACTION, TOOLBAR_EXPANDED, TOOLBAR_HOVER } from "@/lib/toolbarButton";
import { lazy, Suspense, useEffect, useState } from "react";
import {
  deleteHost,
  duplicateHost,
  listHosts,
  noForwardRules,
  onHostsChanged,
} from "@/modules/hosts/store";
import { isRdpHost, isSshHost, type SshHost } from "@/modules/hosts/types";
import { useHosts } from "@/modules/hosts/useHosts";
import type { BackupMode } from "./SshBackupDialog";
import type { FsReadResult } from "@/lib/ipc";
import { BACKUP_EXTENSION, BACKUP_EXTENSION_V1 } from "./backupFile";
import { invoke } from "@tauri-apps/api/core";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
// `CopyPlus`, not `Copy`: plain Copy already means copy-to-clipboard everywhere
// else in the app (code blocks, chat), and one glyph per action is the rule.
import {
  CopyPlus,
  Download,
  Pencil,
  Plus,
  Server,
  Trash2,
  Upload,
  type LucideIcon,
} from "lucide-react";

// Heavy module. Lazy-load until the user opens the add/edit modal.
const SshConnectionDialog = lazy(() =>
  import("./SshConnectionDialog").then((m) => ({ default: m.SshConnectionDialog })),
);

// Same treatment: the backup dialog pulls in the crypto/IO path, which nobody
// pays for until they actually move machines.
const SshBackupDialog = lazy(() =>
  import("./SshBackupDialog").then((m) => ({ default: m.SshBackupDialog })),
);

type Props = {
  /** Opens a saved host as a new terminal tab. */
  onConnect: (conn: SshHost) => void;
};

export function SshMenu({ onConnect }: Props) {
  const [conns, setConns] = useState<SshHost[] | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  // Latches once the editor opens. Keeps the lazy dialog mounted so Radix's
  // close animation can play. Mirrors the latch in App.tsx.
  const [editorMounted, setEditorMounted] = useState(false);
  useEffect(() => {
    if (editorOpen) setEditorMounted(true);
  }, [editorOpen]);
  const [editing, setEditing] = useState<SshHost | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<SshHost | null>(null);
  // A failed delete is reported INSIDE the confirm dialog rather than through
  // `pickError` like the duplicate path: by the time this can fail the menu is
  // already closed, so a message down there would only appear the next time the
  // user opened it. The dialog is the one surface still on screen.
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [backup, setBackup] = useState<BackupMode | null>(null);
  const [backupOpen, setBackupOpen] = useState(false);
  const [pickError, setPickError] = useState<string | null>(null);
  // Only for the export item's enabled state: one backup covers both protocols,
  // so this menu has to know whether any RDP host exists even though it never
  // lists one.
  const hosts = useHosts();
  const hasRdpHost = [...hosts.values()].some(isRdpHost);

  useEffect(() => {
    const load = () => void listHosts().then((list) => setConns(list.filter(isSshHost)));
    load();
    const unsub = onHostsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);

  const openAdd = () => {
    setEditing(null);
    setEditorOpen(true);
    setMenuOpen(false);
  };

  const openEdit = (c: SshHost) => {
    setEditing(c);
    setEditorOpen(true);
    setMenuOpen(false);
  };

  // Copy, then open the copy: what a duplicate is for is changing the one field
  // that differs, usually the host or the port. The list refreshes itself off
  // the store's change event.
  //
  // `duplicateHost` throws (not returns null) when the source's jump host is
  // dangling or the chain is cyclic - `upsertHost`'s write guard runs on the
  // copy too. Surfaced through `pickError` rather than left as an unhandled
  // rejection.
  const openDuplicate = async (c: SshHost) => {
    try {
      const copy = await duplicateHost(c.id);
      // `null` means the source was gone by the time the queue reached it -
      // deleted in another window. A copy of an SSH host that is not an SSH host
      // cannot happen, and both read the same way from here, so neither returns
      // in silence with the menu still open and nothing said.
      if (!copy || !isSshHost(copy)) {
        setPickError(`"${c.name}" could not be duplicated: it is no longer saved.`);
        return;
      }
      setEditing(copy);
      setEditorOpen(true);
      setMenuOpen(false);
    } catch (e) {
      setPickError(e instanceof Error ? e.message : String(e));
    }
  };

  const askDelete = (c: SshHost) => {
    setConfirmDelete(c);
    setDeleteError(null);
    setMenuOpen(false);
  };

  // `deleteHost` clears the host's keychain accounts and rewrites every row that
  // pointed at it, so it has real failure modes - a locked keychain, a store it
  // cannot write. Left unhandled it was an unhandled rejection: the dialog closed,
  // the list reloaded the row straight back, and the user retried forever with no
  // message. The dialog stays open on failure instead.
  const runDelete = async (target: SshHost) => {
    setDeleteError(null);
    setDeleting(true);
    try {
      await deleteHost(target.id, noForwardRules);
      setConfirmDelete(null);
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
    }
  };

  const onPick = (c: SshHost) => {
    setMenuOpen(false);
    onConnect(c);
  };

  const openExport = () => {
    setPickError(null);
    setBackup({ kind: "export" });
    setBackupOpen(true);
    setMenuOpen(false);
  };

  // The file is picked and read BEFORE the dialog opens, so an unreadable or
  // wrong-type file is rejected up front instead of after the user has typed a
  // passphrase for it.
  const openImport = async () => {
    setPickError(null);
    setMenuOpen(false);
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
    <>
      <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
        <IconTooltip label="SSH connections">
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                "text-muted-foreground",
                TOOLBAR_HOVER,
                TOOLBAR_EXPANDED,
                "size-7 shrink-0 rounded-md",
              )}
              aria-label="SSH connections"
            >
              <Server size={15} strokeWidth={1.75} />
            </Button>
          </DropdownMenuTrigger>
        </IconTooltip>
        <DropdownMenuContent align="end" className="w-72 min-w-72">
          <DropdownMenuLabel className="text-muted-foreground text-[10px] tracking-wide uppercase">
            SSH connections
          </DropdownMenuLabel>
          {conns === null ? (
            <div className="text-muted-foreground px-3 py-2 text-[11px]">Loading…</div>
          ) : conns.length === 0 ? (
            <div className="text-muted-foreground px-3 py-2 text-[11px]">No saved hosts yet.</div>
          ) : (
            conns.map((c) => (
              <DropdownMenuItem
                key={c.id}
                onSelect={() => onPick(c)}
                // Override Radix's blue focus styling with a muted hover so
                // the row reads as a list entry, not a primary action.
                // `[&_span]:text-current!` blocks the parent cascade from
                // recolouring the label spans (including the muted host line,
                // which is a grandchild). Scoped to spans on purpose: a bare
                // `**:` also swept the row's action BUTTONS, and being important
                // it out-ranked their own colour and greyed out the red trash.
                className="group focus:bg-muted! focus:text-foreground! flex items-center justify-between gap-2 pr-1 text-[12px] focus:[&_span]:text-current!"
              >
                <span className="flex min-w-0 flex-col">
                  <span className="truncate">{c.name}</span>
                  <span className="text-muted-foreground truncate font-mono text-[10px]">
                    {c.credential.kind === "inline" ? `${c.credential.user}@` : ""}
                    {c.host}:{c.port}
                  </span>
                </span>
                {/* Action buttons. preventDefault on click blocks the row's
                    onSelect (which would also trigger connect).
                    stopPropagation on pointerDown stops the menu treating
                    the click as a row select. Icons stay visible at rest
                    (no opacity fade) so the affordance is discoverable
                    without hovering each row. */}
                <span className="ml-1 flex shrink-0 items-center gap-0.5">
                  <RowIconButton
                    label={`Edit ${c.name}`}
                    onClick={() => openEdit(c)}
                    icon={Pencil}
                  />
                  <RowIconButton
                    label={`Duplicate ${c.name}`}
                    onClick={() => void openDuplicate(c)}
                    icon={CopyPlus}
                  />
                  <RowIconButton
                    label={`Delete ${c.name}`}
                    onClick={() => askDelete(c)}
                    icon={Trash2}
                    danger
                  />
                </span>
              </DropdownMenuItem>
            ))
          )}
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={openAdd} className="gap-2 text-[12px]">
            <Plus size={13} strokeWidth={1.75} />
            <span>Add new connection…</span>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          {/* The backup covers RDP too, so an empty SSH list is not an empty
              export - only both being empty is. */}
          <DropdownMenuItem
            onSelect={openExport}
            disabled={conns !== null && conns.length === 0 && !hasRdpHost}
            className="gap-2 text-[12px]"
          >
            <Download size={13} strokeWidth={1.75} />
            <span>Export connections…</span>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => void openImport()} className="gap-2 text-[12px]">
            <Upload size={13} strokeWidth={1.75} />
            <span>Import connections…</span>
          </DropdownMenuItem>
          {pickError ? (
            <div className="text-destructive px-3 py-1 text-[10.5px]">{pickError}</div>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>

      {editorMounted ? (
        <Suspense fallback={null}>
          <SshConnectionDialog open={editorOpen} onOpenChange={setEditorOpen} editing={editing} />
        </Suspense>
      ) : null}

      {/* Unmounted once closed, unlike the editor above: the dialog holds a
          passphrase and, for an import, the decrypted file text in state, so
          there is no reason to keep either resident for a close animation. */}
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

      <AlertDialog
        open={confirmDelete !== null}
        onOpenChange={(open) => {
          if (!open) {
            setConfirmDelete(null);
            setDeleteError(null);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete connection?</AlertDialogTitle>
            <AlertDialogDescription>
              {confirmDelete
                ? `"${confirmDelete.name}" will be removed and its stored credentials wiped from the keychain.`
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          {deleteError ? (
            <p className="text-destructive text-[11px]">Delete failed: {deleteError}</p>
          ) : null}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={deleting}
              // preventDefault, because Radix closes the dialog on click: the
              // whole point is to still be here when the delete fails. Closing
              // is `runDelete`'s job, on success only.
              onClick={(e) => {
                e.preventDefault();
                if (confirmDelete) void runDelete(confirmDelete);
              }}
            >
              {deleting ? "Deleting…" : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function RowIconButton({
  label,
  onClick,
  icon,
  danger,
}: {
  label: string;
  onClick: () => void;
  icon: LucideIcon;
  danger?: boolean;
}) {
  const Icon = icon;
  return (
    <IconTooltip label={label} side="top">
      <button
        type="button"
        aria-label={label}
        // Run on mousedown, before the row's pointerup fires and highlights it.
        // preventDefault stops focus shifting here (which would also blue-paint
        // the parent row via Radix focus styling).
        onMouseDown={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onClick();
        }}
        // Block propagation so the parent DropdownMenuItem never fires its
        // onSelect (the row's connect action). Both pointer events must be
        // stopped: Radix's menu item records isPointerDownRef on its own
        // pointerdown, and if it never sees one (because we swallowed it) it
        // synthesizes a click() on itself at pointerup - which would connect
        // and open a tab. Stopping pointerup blocks that synthetic select.
        onPointerDown={(e) => e.stopPropagation()}
        onPointerUp={(e) => e.stopPropagation()}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
        }}
        className={cn(
          "flex size-6 cursor-pointer items-center justify-center rounded-md transition-colors",
          danger
            ? DESTRUCTIVE_ACTION
            : "text-muted-foreground hover:bg-accent hover:text-foreground",
        )}
      >
        <Icon size={12} strokeWidth={1.75} />
      </button>
    </IconTooltip>
  );
}
