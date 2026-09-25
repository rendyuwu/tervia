/**
 * Review dialog for an `ssh_config`/PuTTY `.reg` import: preview what parsing
 * found (async - `IdentityFile` reads, key inspection, `ProxyJump`
 * resolution against saved hosts), show what will be added and what was
 * refused by reason, then write it only once the user confirms.
 *
 * A SIBLING of `BackupDialog.tsx`, not a mode branch inside it - see
 * `foreignImport.ts`'s header for why. That dialog's whole state
 * (`passphrase`/`confirm`/`mismatch`) exists to collect and confirm a
 * passphrase, which a plaintext source never has. What this dialog copies is
 * its SHAPE: a busy-gated `Dialog` that refuses to close mid-write, and a
 * `done: ImportSummary` rendered as one line plus a `problems` list. What
 * neither dialog has is a synchronous parse to validate up front - this one
 * adds a PREVIEW state in between, because `BackupDialog` never needs one (an
 * encrypted payload cannot be previewed before it is decrypted, and decrypting
 * IS the write's own first step) where this source can and must: nothing
 * async here needs a passphrase, so there is no reason to make the user
 * commit before seeing what would land.
 */
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
import { Spinner } from "@/components/ui/spinner";
import { toast } from "@/components/ui/toast";
import { useEffect, useState, type ReactNode } from "react";

import {
  applyForeignImport,
  previewPuttyImport,
  previewSshConfigImport,
  type ForeignImportPreview,
  type ForeignRefusalReason,
} from "./foreignImport";
import type { PuttyParseResult } from "./puttyRegImport";
import type { SshConfigParseResult } from "./sshConfigImport";
import { FOREIGN_REFUSAL_LABELS, summarizeForeignImport, type ImportSummary } from "./summary";

export type ForeignImportMode =
  | { source: "ssh_config"; parsed: SshConfigParseResult; path: string }
  | { source: "putty_reg"; parsed: PuttyParseResult };

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  mode: ForeignImportMode;
};

const SOURCE_LABEL: Record<ForeignImportMode["source"], string> = {
  ssh_config: "OpenSSH config",
  putty_reg: "PuTTY sessions",
};

/** One line per non-zero refused reason, shared between the preview state
 *  here and `done.line`'s own clause once `summarizeForeignImport` has run -
 *  same labels, same order (`Object.entries` over the same `refused` shape). */
function RefusedList({ refused }: { refused: ForeignImportPreview["refused"] }): ReactNode {
  const entries = Object.entries(refused).filter(([, n]) => (n ?? 0) > 0);
  if (entries.length === 0) return null;
  return (
    <ul className="text-muted-foreground flex flex-col gap-0.5 text-[10.5px]">
      {entries.map(([reasonKey, n]) => (
        <li key={reasonKey}>
          {n} refused - {FOREIGN_REFUSAL_LABELS[reasonKey as ForeignRefusalReason] ?? reasonKey}
        </li>
      ))}
    </ul>
  );
}

export function ForeignImportDialog({ open, onOpenChange, mode }: Props): ReactNode {
  const [preview, setPreview] = useState<ForeignImportPreview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<ImportSummary | null>(null);

  // Reset per opening, same as `BackupDialog`'s own effect - a stale preview
  // or result line would otherwise read as if it belonged to this run.
  useEffect(() => {
    if (!open) return;
    setPreview(null);
    setLoadError(null);
    setDone(null);
    setBusy(false);
    let cancelled = false;
    const load =
      mode.source === "ssh_config"
        ? previewSshConfigImport(mode.parsed, mode.path)
        : previewPuttyImport(mode.parsed);
    void load
      .then((p) => {
        if (!cancelled) setPreview(p);
      })
      .catch((e: unknown) => {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [open, mode]);

  const run = async () => {
    if (!preview) return;
    setBusy(true);
    try {
      const result = await applyForeignImport(preview);
      setDone(summarizeForeignImport(result));
    } catch (e) {
      // Routed through the shared toast rather than an inline line, the same
      // treatment `BackupDialog`'s own import failure gets and for the same
      // reason: it outlives this dialog closing.
      toast(e instanceof Error ? e.message : String(e), { variant: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      // Same close-gate as `BackupDialog`: Escape, a pointer down outside,
      // the `X` and Cancel all funnel through this one callback, and a write
      // in flight refuses every one of them rather than landing on a dialog
      // that is already gone.
      onOpenChange={(next) => {
        if (!next && busy) return;
        onOpenChange(next);
      }}
    >
      <DialogContent className="sm:max-w-md" showCloseButton={!busy}>
        <DialogHeader>
          <DialogTitle>Import from {SOURCE_LABEL[mode.source]}</DialogTitle>
          <DialogDescription>
            Adds every host the file describes as a new saved host. Nothing is written until you
            confirm below.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          {loadError ? <span className="text-destructive text-[10.5px]">{loadError}</span> : null}

          {!preview && !loadError && !done ? (
            <div className="text-muted-foreground flex items-center gap-2 text-[11px]">
              <Spinner className="size-3" /> Reading identity files and resolving jump hosts...
            </div>
          ) : null}

          {preview && !done ? (
            <div className="flex flex-col gap-1.5">
              <span className="text-[11px]">
                {preview.hosts.length} host{preview.hosts.length === 1 ? "" : "s"}
                {preview.keys.length > 0
                  ? `, ${preview.keys.length} vault key${preview.keys.length === 1 ? "" : "s"}`
                  : ""}
                {preview.identities.length > 0
                  ? `, ${preview.identities.length} identit${
                      preview.identities.length === 1 ? "y" : "ies"
                    }`
                  : ""}{" "}
                will be added.
              </span>
              <RefusedList refused={preview.refused} />
            </div>
          ) : null}

          {done ? (
            <div className="flex flex-col gap-1.5">
              <span className="text-muted-foreground text-[10.5px]">{done.line}</span>
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
            <Button variant="outline" size="sm" disabled={busy}>
              {done ? "Close" : "Cancel"}
            </Button>
          </DialogClose>
          {!done ? (
            <Button
              size="sm"
              disabled={!preview || busy || preview.hosts.length === 0}
              onClick={() => void run()}
              className="gap-1.5"
            >
              {busy ? <Spinner className="size-3" /> : null}
              Import
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
