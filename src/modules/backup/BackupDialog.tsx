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
import { applyBackup, buildBackup, type ImportResult } from "./apply";
import { BACKUP_EXTENSION } from "./file";
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
  const [done, setDone] = useState<string | null>(null);

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
        setDone(`Exported ${describeExport(counts)} to ${target}`);
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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
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
          {done ? <span className="text-muted-foreground text-[10.5px]">{done}</span> : null}
        </div>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">
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

function plural(n: number, noun: string, pluralNoun?: string): string {
  return `${n} ${n === 1 ? noun : (pluralNoun ?? `${noun}s`)}`;
}

/**
 * The export result line's five-collection summary. Same rule as
 * summarize()'s per-protocol split below: a collection earns its own clause
 * only when it is non-zero, or a vault-only export would read "0 hosts, 0
 * host groups" and a host-only one, symmetrically, "0 identities, 0 keys, 0
 * rules" - both look broken.
 */
function describeExport(counts: {
  hosts: number;
  groups: number;
  identities: number;
  keys: number;
  rules: number;
}): string {
  const parts: string[] = [];
  if (counts.hosts > 0) parts.push(plural(counts.hosts, "host"));
  if (counts.groups > 0) parts.push(plural(counts.groups, "host group"));
  if (counts.identities > 0) parts.push(plural(counts.identities, "identity", "identities"));
  if (counts.keys > 0) parts.push(plural(counts.keys, "vault key"));
  if (counts.rules > 0) parts.push(plural(counts.rules, "forward rule"));
  return parts.join(", ");
}

function summarize(r: ImportResult): string {
  const added = r.ssh.added + r.rdp.added;
  const replaced = r.ssh.replaced + r.rdp.replaced;
  const withoutSecrets = r.ssh.withoutSecrets + r.rdp.withoutSecrets;
  // The per-protocol split only earns its space when both are present; a
  // v1 file or an SSH-only export would otherwise report "0 RDP".
  //
  // It rides on the HOST count rather than the end of the sentence, because
  // the clauses after it are about other collections: trailing it would put
  // "(3 SSH hosts, 2 RDP hosts)" after a sentence about group names, where it
  // reads as qualifying that instead.
  const split =
    r.rdp.added + r.rdp.replaced > 0 && r.ssh.added + r.ssh.replaced > 0
      ? ` (${plural(r.ssh.added + r.ssh.replaced, "SSH host")}, ${plural(
          r.rdp.added + r.rdp.replaced,
          "RDP host",
        )})`
      : "";
  const parts = [`${added} added`, `${replaced} updated${split}`];
  if (r.skipped > 0) parts.push(`${r.skipped} skipped as unreadable`);
  if (withoutSecrets > 0) parts.push(`${withoutSecrets} without stored credentials`);
  // Same rule as the split above: a collection earns its own clause only
  // when it actually landed something, or a host-only import would read "0
  // identities, 0 keys, 0 rules" and look broken.
  const groupCount = r.groups.added + r.groups.replaced;
  const identityCount = r.identities.added + r.identities.replaced;
  const keyCount = r.keys.added + r.keys.replaced;
  const ruleCount = r.rules.added + r.rules.replaced;
  if (groupCount > 0) parts.push(plural(groupCount, "host group"));
  if (identityCount > 0) parts.push(plural(identityCount, "identity", "identities"));
  if (keyCount > 0) parts.push(plural(keyCount, "vault key"));
  if (ruleCount > 0) parts.push(plural(ruleCount, "forward rule"));
  // Not failures - `problems[]` is for what could not be done - but not
  // silent either: each is a case where the file's hosts landed in a group
  // other than the one the file named, and the file's own record of that is
  // gone the moment this import finishes.
  if (r.groups.merged > 0) {
    const noun = r.groups.merged === 1 ? "group's" : "groups'";
    parts.push(`${r.groups.merged} ${noun} hosts merged into an existing group of the same name`);
  }
  if (r.groups.keptNames > 0) {
    const noun = r.groups.keptNames === 1 ? "group's" : "groups'";
    parts.push(
      `${r.groups.keptNames} ${noun} hosts kept this machine's group name instead of the file's`,
    );
  }
  return `Imported: ${parts.join(", ")}.`;
}
