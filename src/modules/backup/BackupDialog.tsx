import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { toast } from "@/components/ui/toast";
import { applyBackup, buildBackup } from "./apply";
import { BACKUP_EXTENSION } from "./file";
import { describeExport, summarize, type ImportSummary } from "./summary";
import { invoke } from "@tauri-apps/api/core";
import { save as saveFileDialog } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";

export type BackupMode =
  | { kind: "export" }
  /** Import already has the file text: the native picker runs before this
   *  dialog so the user is not asked for a passphrase and only then told
   *  they picked the wrong file. */
  | { kind: "import"; path: string; text: string };

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  mode: BackupMode;
};

export function BackupDialog({ open, onOpenChange, mode }: Props) {
  const isExport = mode.kind === "export";
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The result line AND the refusals under it, held together because they are
  // one report - see `summary.ts`. An export has no refusals to carry and says
  // so with an empty list rather than with a second piece of state.
  const [done, setDone] = useState<ImportSummary | null>(null);

  // Reset per opening. The passphrase must never survive a closed dialog, and
  // a stale result line would otherwise read as if it applied to this run.
  useEffect(() => {
    if (!open) return;
    setPassphrase("");
    setConfirm("");
    setError(null);
    setDone(null);
    setBusy(false);
  }, [open, mode]);

  const mismatch = isExport && confirm.length > 0 && passphrase !== confirm;
  const canSubmit =
    !busy && passphrase.length > 0 && (!isExport || (confirm.length > 0 && !mismatch));

  const run = async () => {
    setError(null);
    setBusy(true);
    try {
      if (isExport) {
        const { text, counts } = await buildBackup(passphrase);
        // Built BEFORE the save dialog on purpose: "There is nothing saved to
        // export" or a keychain refusal should surface without first making
        // the user pick a filename for a file that was never going to be
        // written.
        const target = await saveFileDialog({
          defaultPath: `tervia-connections.${BACKUP_EXTENSION}`,
          filters: [{ name: "Tervia backup", extensions: [BACKUP_EXTENSION] }],
        });
        if (!target) {
          setBusy(false);
          return;
        }
        await invoke<void>("fs_write_file", { path: target, content: text });
        setDone({ line: `Exported ${describeExport(counts)} to ${target}`, problems: [] });
      } else {
        const result = await applyBackup(mode.text, passphrase);
        setDone(summarize(result));
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (isExport) {
        // Export's failure stays inline. Consolidating it with import's onto
        // one surface is a separate change and is not made here.
        setError(message);
      } else {
        // Import's failure routes through the shared toast instead of the old
        // inline line: a toast self-expires, carries its own dismiss `×`, and
        // outlives this dialog closing, where the inline line vanished only
        // when the DIALOG did - so retyping a wrong passphrase, giving up, and
        // closing left nothing behind for the user to reread. See
        // HostsBackupActions.tsx's openImport for the same treatment of a bad
        // file PICK; this is the same failure one step later, after the file
        // was accepted and a passphrase typed for it.
        toast(message, { variant: "error" });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      // A CLOSE REQUEST IS REFUSED WHILE THE WRITE IS RUNNING, and it is refused
      // HERE rather than on the content's own `onEscapeKeyDown` and
      // `onPointerDownOutside` because those two reach only half the routes.
      // `DialogContent` renders a Radix `Close` for the `X`, and the footer's
      // Cancel is another one; a `Close` calls the Root's `onOpenChange`
      // directly and passes through neither content handler. All four routes -
      // Escape, a pointer down outside, the `X` and Cancel - funnel through
      // this one callback, which is what makes it the only place that can
      // answer for all of them.
      //
      // THE DISMISSAL IS WHAT STOPS; THE WORK NEVER DOES. Nothing aborts
      // `applyBackup`, deliberately: a partial import that stops halfway is
      // worse than one that finishes and reports, and `applyV3`'s whole
      // ordering argument - records before secrets, containment per record -
      // depends on it running to the end. What this prevents is the summary
      // landing on a dialog that is already gone.
      onOpenChange={(next) => {
        if (!next && busy) return;
        onOpenChange(next);
      }}
    >
      {/* The `X` goes with the gate rather than sitting there inert: a control
          that is visible and silently does nothing is the same dead end the
          refused Escape would be if it were the only half that shipped. */}
      <DialogContent className="sm:max-w-md" showCloseButton={!busy}>
        <DialogHeader>
          <DialogTitle>{isExport ? "Export backup" : "Import backup"}</DialogTitle>
          <DialogDescription>
            {isExport
              ? "Writes every saved host, host group, vault identity, vault key and forward rule, and their stored credentials, to one encrypted file. Keep the passphrase: without it the file cannot be read, and there is no recovery."
              : "Merges the hosts, host groups, vault identities, vault keys and forward rules in the file into what is already saved, matching on id. Nothing is deleted."}
          </DialogDescription>
        </DialogHeader>

        {!isExport ? (
          <p className="text-muted-foreground truncate font-mono text-[10.5px]" title={mode.path}>
            {mode.path}
          </p>
        ) : null}

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <span className="text-muted-foreground text-[11px] font-medium tracking-tight">
              Passphrase
            </span>
            <Input
              type="password"
              autoFocus
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && canSubmit) void run();
              }}
              className="h-8 font-mono text-[12px]"
            />
          </div>

          {isExport ? (
            <div className="flex flex-col gap-1.5">
              <span className="text-muted-foreground text-[11px] font-medium tracking-tight">
                Confirm passphrase
              </span>
              <Input
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && canSubmit) void run();
                }}
                className="h-8 font-mono text-[12px]"
              />
              {mismatch ? (
                <span className="text-destructive text-[10.5px]">
                  The two passphrases do not match.
                </span>
              ) : null}
            </div>
          ) : null}

          {isExport ? (
            <p className="text-muted-foreground text-[10.5px]">
              The whole file is encrypted with this passphrase (PBKDF2-SHA256, AES-256-GCM) -
              hostnames included, not only the SSH passwords, private keys and RDP passwords. Treat
              it like a key file.
            </p>
          ) : null}

          {error ? <span className="text-destructive text-[10.5px]">{error}</span> : null}
          {done ? (
            <div className="flex flex-col gap-1.5">
              <span className="text-muted-foreground text-[10.5px]">{done.line}</span>
              {/* A LIST, not a clause. The summary line is one sentence and a
                  forty-host import can carry several refusals; folding them in
                  would produce a paragraph nobody reads to the end of. Indexed
                  keys because the text is not one: two records with the same
                  name refused the same way give the same string, and this list
                  is written once from one state update and never reordered. */}
              {done.problems.length > 0 ? (
                <ul className="text-destructive flex flex-col gap-1 text-[10.5px]">
                  {done.problems.map((problem, i) => (
                    <li key={i}>{problem}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
        </div>

        <DialogFooter>
          <DialogClose asChild>
            {/* Disabled with the gate above, for the same reason the `X` is
                hidden: the Root refuses this close, so an enabled button would
                be one the user can press and watch do nothing. */}
            <Button variant="outline" size="sm" disabled={busy}>
              {done ? "Close" : "Cancel"}
            </Button>
          </DialogClose>
          <Button size="sm" disabled={!canSubmit} onClick={() => void run()} className="gap-1.5">
            {busy ? <Spinner className="size-3" /> : null}
            {isExport ? "Export" : "Import"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
