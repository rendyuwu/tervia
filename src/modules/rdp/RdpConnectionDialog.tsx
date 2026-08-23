import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
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
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import { ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { confirmRdpCert, openRdp, type RdpCredential } from "./bridge";
import {
  clearFingerprint,
  newConnectionId,
  pinFingerprint,
  presetById,
  presetIdFor,
  rdpKeyringAccount,
  upsertConnection,
  RDP_DEFAULT_PORT,
  RDP_DEFAULT_PRESET,
  RDP_KEYRING_SERVICE,
  RDP_SIZE_PRESETS,
  type RdpConnection,
} from "./connections";

/**
 * Add / edit one saved RDP host. Same shape as `SshConnectionDialog` - a draft
 * form, a Test button that dials with the values on screen, and a pinned
 * server identity with a Forget button - with two deliberate differences.
 *
 * 1. The saved password is NEVER loaded into the form. `SshConnectionDialog`
 *    calls `getConnectionSecrets` and puts the plaintext in a controlled input;
 *    the RDP path has no equivalent by design, so an edit leaves the field
 *    blank and blank means "leave the stored password alone". The only way the
 *    field is ever non-empty is the user typing in it.
 * 2. Test therefore picks its credential rather than always sending one. A
 *    typed password goes down inline - the ONE sanctioned use of that form,
 *    since a draft has no keychain entry to reference yet - and an untouched
 *    field on a saved connection sends the keychain reference instead. So Test
 *    exercises exactly what a real connect will use.
 */

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Connection to edit, or `null` to create a new one. */
  editing: RdpConnection | null;
  onSaved?: (conn: RdpConnection) => void;
};

type Draft = {
  name: string;
  host: string;
  port: string;
  username: string;
  domain: string;
  /** Blank means "unchanged" on an edit, and "not set yet" on a new one. */
  password: string;
  /** An `RDP_SIZE_PRESETS` id. */
  presetId: string;
};

const EMPTY_DRAFT: Draft = {
  name: "",
  host: "",
  port: String(RDP_DEFAULT_PORT),
  username: "",
  domain: "",
  password: "",
  presetId: RDP_DEFAULT_PRESET.id,
};

type TestState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "ok"; fingerprint: string; width: number; height: number; durationMs: number }
  | { kind: "fail"; message: string };

/** A full RDP connect is TCP, then TLS, then CredSSP, then the capability
 *  exchange, and a domain controller in the middle of the NTLM leg can be slow.
 *  Generous, because the alternative is calling a working host broken. */
const TEST_TIMEOUT_MS = 30_000;

export function RdpConnectionDialog({ open, onOpenChange, editing, onSaved }: Props) {
  const [draft, setDraft] = useState<Draft>(EMPTY_DRAFT);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<TestState>({ kind: "idle" });
  const [sizePickerOpen, setSizePickerOpen] = useState(false);
  // The certificate this connection trusts as of right now: seeded from the
  // saved pin, cleared by Forget, set by accepting one during Test. The single
  // source of truth for what Test verifies against AND what Save writes, so a
  // certificate accepted here cannot be lost and a forgotten one cannot come
  // back from the stale `editing` prop.
  const [pinnedFingerprint, setPinnedFingerprint] = useState<string | null>(null);
  // The certificate prompt a Test probe currently has outstanding, if any.
  // A ref rather than state because the only reader is the unmount teardown
  // below, and it must see the latest value without a re-render.
  const pendingCertPrompt = useRef<string | null>(null);

  // A Test probe that raised a certificate question has the backend parked
  // INSIDE the TLS handshake: `rdp_open` has not returned, so no session id
  // exists and there is nothing to close. If this dialog goes away with the
  // question unanswered - the window navigates, the header unmounts, a lazy
  // boundary re-mounts - the socket and a blocked thread are held for the full
  // 120-second confirm timeout. Rejecting on the way out is what releases them,
  // and it no-ops if the user already answered.
  useEffect(
    () => () => {
      const outstanding = pendingCertPrompt.current;
      pendingCertPrompt.current = null;
      if (outstanding) useHostKeyPrompt.getState().abandon(outstanding);
    },
    [],
  );

  useEffect(() => {
    if (!open) return;
    setError(null);
    setSaving(false);
    setTest({ kind: "idle" });
    if (!editing) {
      setDraft(EMPTY_DRAFT);
      setPinnedFingerprint(null);
      return;
    }
    setDraft({
      name: editing.name,
      host: editing.host,
      port: String(editing.port),
      username: editing.username,
      domain: editing.domain ?? "",
      // Deliberately blank. See the module docs: the stored password is never
      // read back into the webview, so there is nothing to seed this with.
      password: "",
      // A row written by a build offering a size this one does not falls back
      // to the default rather than showing an empty picker.
      presetId: presetIdFor(editing.desktopWidth, editing.desktopHeight) || RDP_DEFAULT_PRESET.id,
    });
    setPinnedFingerprint(editing.certFingerprint ?? null);
  }, [open, editing]);

  const preset = presetById(draft.presetId) ?? RDP_DEFAULT_PRESET;

  const forgetPinnedCert = async () => {
    if (!editing) return;
    await clearFingerprint(editing.id);
    setPinnedFingerprint(null);
    // A stale "certificate mismatch" result no longer means anything.
    setTest({ kind: "idle" });
  };

  const validateDraft = (): string | null => {
    const port = Number.parseInt(draft.port, 10);
    if (!draft.name.trim()) return "Name is required";
    if (!draft.host.trim()) return "Host is required";
    if (!draft.username.trim()) return "Username is required";
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return "Port must be 1–65535";
    // Blank is only "unchanged" when there IS something to leave unchanged.
    if (!draft.password && !editing?.hasPassword) return "Password is required";
    return null;
  };

  /**
   * Which credential form this dialog may use right now.
   *
   * A typed password has no keychain entry behind it yet, which is the entire
   * reason the inline form exists; anything else must go through the reference.
   */
  const credentialForTest = (): RdpCredential | null => {
    if (draft.password) return { kind: "inline", password: draft.password };
    if (editing?.hasPassword) {
      return {
        kind: "keychain",
        service: RDP_KEYRING_SERVICE,
        account: rdpKeyringAccount(editing.id),
      };
    }
    return null;
  };

  const runTest = async () => {
    const v = validateDraft();
    if (v) {
      setError(v);
      return;
    }
    const credential = credentialForTest();
    if (!credential) {
      setError("Enter a password to test this connection");
      return;
    }
    setError(null);
    setTest({ kind: "running" });
    const port = Number.parseInt(draft.port, 10);
    const started = performance.now();
    // A host with no pinned certificate makes the backend pause the handshake
    // on a first-connect prompt; it is routed to the shared confirmation dialog
    // and the id remembered so it can be withdrawn if the probe ends without an
    // answer.
    let testPromptId: string | null = null;
    try {
      let resolved = false;
      const result = await new Promise<{ fingerprint: string; width: number; height: number }>(
        (resolve, reject) => {
          const timer = setTimeout(() => {
            if (resolved) return;
            resolved = true;
            reject(new Error(`test timed out after ${Math.round(TEST_TIMEOUT_MS / 1000)}s`));
          }, TEST_TIMEOUT_MS);
          openRdp(
            {
              host: draft.host.trim(),
              port,
              username: draft.username.trim(),
              domain: draft.domain.trim() || undefined,
              credential,
              width: preset.width,
              height: preset.height,
              // Pin against what is already recorded, so Test cannot silently
              // re-anchor on a different certificate. A new connection leaves
              // this unset and takes the TOFU prompt.
              expectedCertFingerprint: pinnedFingerprint || undefined,
            },
            {
              onCertPrompt: (prompt) => {
                testPromptId = prompt.promptId;
                // Also on the ref, so the unmount teardown can answer it if the
                // dialog disappears before this probe finishes.
                pendingCertPrompt.current = prompt.promptId;
                // Stop the deadline: the handshake is paused waiting on a
                // human, which can take arbitrarily long, and no credential
                // has been sent. Without this a first-connect Test could only
                // ever time out.
                clearTimeout(timer);
                useHostKeyPrompt.getState().enqueue(
                  {
                    promptId: prompt.promptId,
                    fingerprint: prompt.fingerprint,
                    host: prompt.host,
                    certificate: { subject: prompt.subject, issuer: prompt.issuer },
                    confirm: confirmRdpCert,
                  },
                  // Accepting counts whatever the rest of the test does. A
                  // saved host records it on the spot; a brand-new one has no
                  // id yet, so Save writes it from this same state. Both used
                  // to be forgotten, which is why testing a new server and
                  // then saving it asked the very same question twice.
                  () => {
                    setPinnedFingerprint(prompt.fingerprint);
                    if (editing) {
                      void pinFingerprint(editing.id, prompt.fingerprint).catch(() => {});
                    }
                  },
                );
              },
              onConnected: (width, height, fingerprint) => {
                if (resolved) return;
                resolved = true;
                clearTimeout(timer);
                resolve({ fingerprint, width, height });
              },
              onError: (message) => {
                if (resolved) return;
                resolved = true;
                clearTimeout(timer);
                reject(new Error(message));
              },
              onDisconnected: (reason) => {
                if (resolved) return;
                resolved = true;
                clearTimeout(timer);
                reject(new Error(reason || "session ended before authenticating"));
              },
            },
          )
            .then(async (session) => {
              // Close immediately: only the handshake was under test. Frames
              // for a desktop nobody is looking at are pure cost.
              try {
                await session.close();
              } catch {
                // The runtime reaps a dead session on its own.
              }
            })
            .catch((err) => {
              if (resolved) return;
              resolved = true;
              clearTimeout(timer);
              reject(err);
            });
        },
      );
      setTest({
        kind: "ok",
        fingerprint: result.fingerprint,
        width: result.width,
        height: result.height,
        durationMs: Math.round(performance.now() - started),
      });
    } catch (e) {
      setTest({ kind: "fail", message: e instanceof Error ? e.message : String(e) });
    } finally {
      // A prompt still pending when the probe ended - rejected, timed out, or
      // the user walked away - is answered, not merely dropped. Dropping it
      // would clear this dialog's queue while leaving the backend parked in the
      // handshake until its 120-second confirm timeout, holding the socket and a
      // thread; and a dead prompt left at the head of the shared queue also
      // shadows every later connect's dialog. `abandon` fixes both, and no-ops
      // when the user already answered.
      if (testPromptId) useHostKeyPrompt.getState().abandon(testPromptId);
      pendingCertPrompt.current = null;
    }
  };

  const save = async () => {
    setError(null);
    const v = validateDraft();
    if (v) return setError(v);
    const port = Number.parseInt(draft.port, 10);
    setSaving(true);
    try {
      const id = editing?.id ?? newConnectionId();
      const host = draft.host.trim();
      // A pinned certificate belongs to the machine that presented it.
      // Re-pointing this connection at a different HOST makes it stale, and
      // keeping it would fail the next connect as a MISMATCH - which reads as
      // an attack rather than as an edit. The port is deliberately not part of
      // that test: one machine presents the same certificate on every port it
      // listens on, which is also what lets the same pin survive being reached
      // through a tunnel on an ephemeral port.
      const keepPin = !editing || editing.host === host;
      const conn: RdpConnection = {
        // Spread the existing row first so an edit preserves fields the form
        // does not own (lastConnectedAt, description, tunnel) rather than
        // wiping them.
        ...(editing ?? {}),
        id,
        name: draft.name.trim(),
        host,
        port,
        username: draft.username.trim(),
        domain: draft.domain.trim() || undefined,
        desktopWidth: preset.width,
        desktopHeight: preset.height,
        sizeMode: "preset",
        // Recomputed by `upsertConnection` from what actually reached the
        // keyring, so the flag cannot drift from the keychain.
        hasPassword: false,
        // Written from this dialog's own pin state, not carried over by the
        // spread: `editing` is a snapshot from when the dialog opened, so a
        // certificate accepted during Test would be dropped and one just
        // cleared with Forget would come back.
        certFingerprint: (keepPin && pinnedFingerprint) || undefined,
      };
      // `undefined`, not `""`, when the field was left blank: an empty string
      // would DELETE the stored password, so an edit that only renamed the host
      // would leave it unable to connect.
      await upsertConnection(conn, draft.password ? draft.password : undefined);
      onSaved?.(conn);
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit RDP connection" : "New RDP connection"}</DialogTitle>
          <DialogDescription>
            The password is stored in your OS keychain (Windows Credential Manager / macOS Keychain)
            and read by Tervia's host process when you connect — it is never handed back to the
            interface.
          </DialogDescription>
        </DialogHeader>

        {/* DialogContent caps at calc(100dvh-2rem). min-h-0 lets the inner
            stack shrink so the form scrolls inside the dialog instead of top
            fields sliding off-screen. -mr-2/pr-2 keeps the scrollbar off the
            content edge. */}
        <div className="-mr-2 flex min-h-0 flex-col gap-3 overflow-y-auto pr-2">
          <Field label="Name">
            <Input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="win-build-01"
              spellCheck={false}
              className="h-8 text-[12px]"
            />
          </Field>

          <div className="grid grid-cols-[1fr_5rem] gap-2">
            <Field label="Host">
              <Input
                value={draft.host}
                onChange={(e) => setDraft({ ...draft, host: e.target.value })}
                placeholder="win.example.com or 192.168.1.20"
                spellCheck={false}
                className="h-8 font-mono text-[12px]"
              />
            </Field>
            <Field label="Port">
              <Input
                value={draft.port}
                onChange={(e) => setDraft({ ...draft, port: e.target.value })}
                inputMode="numeric"
                className="h-8 font-mono text-[12px]"
              />
            </Field>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <Field label="Username">
              <Input
                value={draft.username}
                onChange={(e) => setDraft({ ...draft, username: e.target.value })}
                placeholder="Administrator"
                spellCheck={false}
                className="h-8 font-mono text-[12px]"
              />
            </Field>
            <Field label="Domain (optional)">
              <Input
                value={draft.domain}
                onChange={(e) => setDraft({ ...draft, domain: e.target.value })}
                placeholder="CORP"
                spellCheck={false}
                className="h-8 font-mono text-[12px]"
              />
            </Field>
          </div>
          <span className="text-muted-foreground -mt-1.5 text-[10.5px]">
            Leave the domain empty for a local account, or put a UPN (
            <span className="font-mono">user@domain.example</span>) in the username instead.
          </span>

          <Field label="Password">
            <Input
              type="password"
              value={draft.password}
              onChange={(e) => setDraft({ ...draft, password: e.target.value })}
              placeholder={editing?.hasPassword ? "•••••••• (saved, leave blank to keep)" : ""}
              className="h-8 font-mono text-[12px]"
            />
            <span className="text-muted-foreground text-[10.5px]">
              {editing?.hasPassword
                ? "A password is stored for this connection. It is not shown here; leave this blank to keep it, or type a new one to replace it."
                : "Stored in the OS keychain, not in Tervia's settings file."}
            </span>
          </Field>

          <Field label="Desktop size">
            {/* NOT `modal`, for the same reason the SSH dialog's jump-host
                picker is not: modal makes the whole page inert, and the click
                problem it looks like the fix for was `pointer-events: none`
                inheriting into the portaled content, which `PopoverContent`
                already overrides for itself. */}
            <Popover open={sizePickerOpen} onOpenChange={setSizePickerOpen}>
              <PopoverTrigger asChild>
                <Button
                  type="button"
                  variant="outline"
                  role="combobox"
                  aria-expanded={sizePickerOpen}
                  className="h-8 w-full justify-between px-2.5 text-[12px] font-normal"
                >
                  <span className="truncate">{preset.label}</span>
                  <ChevronDown size={13} strokeWidth={2} className="ml-2 shrink-0 opacity-60" />
                </Button>
              </PopoverTrigger>
              <PopoverContent
                align="start"
                sideOffset={6}
                className="w-[var(--radix-popover-trigger-width)] gap-0 overflow-hidden rounded-2xl p-0"
              >
                <Command className="rounded-2xl">
                  <CommandInput placeholder="Search sizes…" className="text-[12px]" />
                  <CommandList className="max-h-56">
                    <CommandEmpty className="py-4 text-[11px]">No matching size.</CommandEmpty>
                    <CommandGroup>
                      {RDP_SIZE_PRESETS.map((p) => (
                        <CommandItem
                          key={p.id}
                          value={`${p.label} ${p.id}`}
                          data-checked={draft.presetId === p.id ? "true" : undefined}
                          onSelect={() => {
                            setDraft((d) => ({ ...d, presetId: p.id }));
                            setSizePickerOpen(false);
                          }}
                          className="gap-2 rounded-xl px-2.5 py-1.5 text-[12px]"
                        >
                          <span className="truncate">{p.label}</span>
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
            <span className="text-muted-foreground text-[10.5px]">
              The desktop is negotiated at this size and the pane letterboxes it, so a pane that is
              not the same shape shows bars rather than cropping. Resizing the desktop to follow the
              pane is a later change.
            </span>
          </Field>

          {editing ? (
            <Field label="Recorded server certificate">
              {pinnedFingerprint ? (
                <div className="border-border/60 bg-muted/30 flex items-center justify-between gap-2 rounded-md border px-2 py-1">
                  <span className="truncate font-mono text-[10.5px]" title={pinnedFingerprint}>
                    {pinnedFingerprint}
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="h-6 shrink-0 px-2 text-[10.5px]"
                    onClick={() => void forgetPinnedCert()}
                  >
                    Forget
                  </Button>
                </div>
              ) : (
                <span className="text-muted-foreground text-[10.5px]">
                  No certificate pinned yet · the next connect will ask you to verify one (TOFU).
                </span>
              )}
              <span className="text-muted-foreground text-[10.5px]">
                Pinned to this saved connection, not to its address, so the same machine keeps one
                trusted certificate however it is reached.
              </span>
            </Field>
          ) : null}

          {error ? <p className="text-destructive text-[11px]">{error}</p> : null}

          {test.kind === "running" ? (
            <p className="text-muted-foreground text-[11px]">Testing connection…</p>
          ) : test.kind === "ok" ? (
            <p className="text-diff-added text-[11px]">
              Connected · {test.width}×{test.height} desktop · certificate{" "}
              {test.fingerprint || "(unavailable)"} · {test.durationMs}ms
            </p>
          ) : test.kind === "fail" ? (
            <p className="text-destructive text-[11px]">Test failed: {test.message}</p>
          ) : null}
        </div>

        {/* Override DialogFooter's flex-col-reverse so Cancel stays on the left
            at any viewport width. */}
        <DialogFooter className="flex-row items-center justify-between gap-2 sm:justify-between sm:[&>button]:flex-none">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void runTest()}
            disabled={test.kind === "running" || saving}
          >
            {test.kind === "running" ? "Testing…" : "Test connection"}
          </Button>
          <div className="flex items-center gap-2">
            <DialogClose asChild>
              <Button variant="outline" size="sm">
                Cancel
              </Button>
            </DialogClose>
            <Button size="sm" onClick={() => void save()} disabled={saving}>
              {saving ? "Saving…" : editing ? "Save" : "Create"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className={cn("flex flex-col gap-1.5")}>
      <span className="text-muted-foreground text-[11px] font-medium tracking-tight">{label}</span>
      {children}
    </div>
  );
}
