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
import { DESTRUCTIVE_ACTION, TOOLBAR_EXPANDED, TOOLBAR_HOVER } from "@/lib/toolbarButton";
import { cn } from "@/lib/utils";
import { Monitor, Pencil, Plus, Trash2, type LucideIcon } from "lucide-react";
import { lazy, Suspense, useEffect, useState } from "react";
import { deleteHost, listHosts, noForwardRules, onHostsChanged } from "@/modules/hosts/store";
import { isRdpHost, type RdpHost } from "@/modules/hosts/types";

// Heavy-ish module (the whole dialog plus the combobox stack). Lazy until the
// user opens the add/edit modal, exactly as SshMenu does with its own.
const RdpConnectionDialog = lazy(() =>
  import("./RdpConnectionDialog").then((m) => ({ default: m.RdpConnectionDialog })),
);

type Props = {
  /** Opens a saved host as a new RDP pane tab. */
  onConnect: (conn: RdpHost) => void;
  /**
   * Controlled open state. The dropdown IS the connection picker, and the
   * command palette has to be able to raise it ("Connect RDP…"), so the state
   * lives in App rather than here - a palette command cannot click a trigger.
   */
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

/**
 * The RDP counterpart of `SshMenu`: the header's saved-host list, with connect
 * on a row click and edit / delete per row.
 *
 * Deliberately narrower than the SSH menu in one place: there is no Duplicate.
 * SSH's copies the credentials, which means reading the plaintext password out
 * of the keychain and into the webview - the exact thing the RDP credential
 * path exists to prevent. A copy that silently dropped the password would be a
 * connection that looks saved and cannot connect, so the action is left out
 * rather than shipped half-working.
 *
 * Export / import are absent for a different reason, and no longer a
 * credential one: backup format v2 covers RDP hosts and their keychain rows
 * without the passwords passing through JS (`ssh/backup.ts` sends keychain
 * references and Rust seals the values). But there is ONE backup covering both
 * protocols, so a second pair of menu items would just be two doors to the
 * same dialog. They live in the SSH menu.
 */
export function RdpMenu({ onConnect, open, onOpenChange }: Props) {
  const [conns, setConns] = useState<RdpHost[] | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  // Latches once the editor opens, so the lazy dialog stays mounted for Radix's
  // close animation. Mirrors the latch in SshMenu.
  const [editorMounted, setEditorMounted] = useState(false);
  useEffect(() => {
    if (editorOpen) setEditorMounted(true);
  }, [editorOpen]);
  const [editing, setEditing] = useState<RdpHost | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<RdpHost | null>(null);
  // Reported inside the confirm dialog, exactly as SshMenu does: the menu is
  // already closed by the time a delete can fail, so that is the only surface
  // still on screen.
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const load = () => void listHosts().then((list) => setConns(list.filter(isRdpHost)));
    load();
    const unsub = onHostsChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);

  const openAdd = () => {
    setEditing(null);
    setEditorOpen(true);
    onOpenChange(false);
  };

  const openEdit = (c: RdpHost) => {
    setEditing(c);
    setEditorOpen(true);
    onOpenChange(false);
  };

  const askDelete = (c: RdpHost) => {
    setConfirmDelete(c);
    setDeleteError(null);
    onOpenChange(false);
  };

  // `deleteHost` clears the host's keychain account and rewrites every row that
  // pointed at it, so it has real failure modes - a locked keychain, a store it
  // cannot write. Left unhandled it was an unhandled rejection: the dialog closed,
  // the list reloaded the row straight back, and the user retried forever with no
  // message. The dialog stays open on failure instead.
  const runDelete = async (target: RdpHost) => {
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

  const onPick = (c: RdpHost) => {
    onOpenChange(false);
    onConnect(c);
  };

  return (
    <>
      <DropdownMenu open={open} onOpenChange={onOpenChange}>
        <IconTooltip label="RDP connections">
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
              aria-label="RDP connections"
            >
              <Monitor size={15} strokeWidth={1.75} />
            </Button>
          </DropdownMenuTrigger>
        </IconTooltip>
        <DropdownMenuContent align="end" className="w-72 min-w-72">
          <DropdownMenuLabel className="text-muted-foreground text-[10px] tracking-wide uppercase">
            RDP connections
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
                // Same treatment as the SSH rows: a muted hover so the row
                // reads as a list entry rather than a primary action, with the
                // span override scoped to spans so it cannot grey out the red
                // trash button.
                className="group focus:bg-muted! focus:text-foreground! flex items-center justify-between gap-2 pr-1 text-[12px] focus:[&_span]:text-current!"
              >
                <span className="flex min-w-0 flex-col">
                  <span className="truncate">{c.name}</span>
                  <span className="text-muted-foreground truncate font-mono text-[10px]">
                    {c.credential.kind === "inline" ? (
                      <>
                        {c.credential.domain ? `${c.credential.domain}\\` : ""}
                        {c.credential.username}@
                      </>
                    ) : null}
                    {c.host}:{c.port}
                  </span>
                </span>
                <span className="ml-1 flex shrink-0 items-center gap-0.5">
                  <RowIconButton
                    label={`Edit ${c.name}`}
                    onClick={() => openEdit(c)}
                    icon={Pencil}
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
        </DropdownMenuContent>
      </DropdownMenu>

      {editorMounted ? (
        <Suspense fallback={null}>
          <RdpConnectionDialog open={editorOpen} onOpenChange={setEditorOpen} editing={editing} />
        </Suspense>
      ) : null}

      <AlertDialog
        open={confirmDelete !== null}
        onOpenChange={(o) => {
          if (!o) {
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
                ? `"${confirmDelete.name}" will be removed, its stored password wiped from the keychain, and its pinned certificate forgotten.`
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

/** Per-row action button. Same event gymnastics as SshMenu's: Radix synthesizes
 *  a click on the menu item at pointerup if it never saw the pointerdown, so
 *  both have to be stopped or editing a row would also connect to it. */
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
        onMouseDown={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onClick();
        }}
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
