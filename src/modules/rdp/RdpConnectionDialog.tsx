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
import {
  listConnections as listSshConnections,
  type SshConnection,
} from "@/modules/ssh/connections";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import { ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { confirmRdpCert, openRdp, type RdpCredential } from "./bridge";
import { openRdpDialTarget, type RdpDialTarget } from "./dial";
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
  /** Saved SSH connection to tunnel through, or "" to dial `host:port`
   *  directly. */
  tunnelSshConnectionId: string;
};

const EMPTY_DRAFT: Draft = {
  name: "",
  host: "",
  port: String(RDP_DEFAULT_PORT),
  username: "",
  domain: "",
  password: "",
  presetId: RDP_DEFAULT_PRESET.id,
  tunnelSshConnectionId: "",
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
  // Saved SSH hosts, offered as tunnels. The whole list: any host that can reach
  // the target's 3389 works, and it is usually not the target itself - a Linux
  // jump box on the same network needs nothing installed on the Windows side.
  const [sshConns, setSshConns] = useState<SshConnection[]>([]);
  const [tunnelPickerOpen, setTunnelPickerOpen] = useState(false);
  // The certificate this connection trusts as of right now: seeded from the
  // saved pin, cleared by Forget, set by accepting one during Test. The single
  // source of truth for what Test verifies against AND what Save writes, so a
  // certificate accepted here cannot be lost and a forgotten one cannot come
  // back from the stale `editing` prop.
  const [pinnedFingerprint, setPinnedFingerprint] = useState<string | null>(null);
  // Trust prompts a Test probe currently has outstanding: the RDP certificate,
  // and the SSH host key of a tunnel it had to dial first. A ref rather than
  // state because the only reader is the unmount teardown below, and it must see
  // the latest value without a re-render.
  const pendingPrompts = useRef<Set<string>>(new Set());

  // A Test probe that raised a trust question has a backend parked INSIDE a
  // handshake: for the certificate, `rdp_open` has not returned, so no session
  // id exists and there is nothing to close; for the tunnel's host key it is
  // `ssh_open` one step earlier. If this dialog goes away with the question
  // unanswered - the window navigates, the header unmounts, a lazy boundary
  // re-mounts - the socket and a blocked thread are held for the full
  // 120-second confirm timeout. Rejecting on the way out is what releases them,
  // and it no-ops if the user already answered.
  useEffect(
    () => () => {
      const outstanding = [...pendingPrompts.current];
      pendingPrompts.current.clear();
      for (const id of outstanding) useHostKeyPrompt.getState().abandon(id);
    },
    [],
  );

  useEffect(() => {
    if (!open) return;
    setError(null);
    setSaving(false);
    setTest({ kind: "idle" });
    void listSshConnections().then((cs) => {
      setSshConns(cs);
      // A tunnel whose SSH connection was deleted is a dangling id that fails
      // every connect with "connection not found". Drop it so the picker and the
      // next save both say what will actually happen: a direct dial.
      setDraft((d) =>
        d.tunnelSshConnectionId && !cs.some((c) => c.id === d.tunnelSshConnectionId)
          ? { ...d, tunnelSshConnectionId: "" }
          : d,
      );
    });
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
      tunnelSshConnectionId: editing.tunnel?.sshConnectionId ?? "",
    });
    setPinnedFingerprint(editing.certFingerprint ?? null);
  }, [open, editing]);

  const preset = presetById(draft.presetId) ?? RDP_DEFAULT_PRESET;
  const selectedTunnel = sshConns.find((c) => c.id === draft.tunnelSshConnectionId);

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
    const host = draft.host.trim();
    // Trust questions this probe raises, in the order they can arrive: the
    // tunnel's SSH host key, then the RDP certificate. Each leaves a backend
    // parked mid-handshake, so each is withdrawn if the probe ends without an
    // answer. Mirrored onto the ref so the unmount teardown can do the same.
    const raised = new Set<string>();
    const remember = (promptId: string) => {
      raised.add(promptId);
      pendingPrompts.current.add(promptId);
    };
    let dial: RdpDialTarget | null = null;
    try {
      // The tunnel first, and deliberately outside the timer below: dialling the
      // bastion can stop for a host-key dialog, and a probe that can only ever
      // time out while a human reads a fingerprint is worse than no probe.
      const target = await openRdpDialTarget(
        {
          host,
          port,
          tunnel: draft.tunnelSshConnectionId
            ? { sshConnectionId: draft.tunnelSshConnectionId }
            : undefined,
        },
        { onHostKeyPrompt: remember },
      );
      dial = target;
      // Measured from here, so the number reported is the RDP handshake and not
      // however long the tunnel (or the user) took.
      const started = performance.now();
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
              // The tunnel's local end when there is one, so Test exercises the
              // transport a real connect will use rather than a direct dial the
              // saved row would never make.
              host: target.host,
              port: target.port,
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
                // Recorded for the `finally` below AND on the ref, so the
                // unmount teardown can answer it if the dialog disappears
                // before this probe finishes.
                remember(prompt.promptId);
                // Stop the deadline: the handshake is paused waiting on a
                // human, which can take arbitrarily long, and no credential
                // has been sent. Without this a first-connect Test could only
                // ever time out.
                clearTimeout(timer);
                useHostKeyPrompt.getState().enqueue(
                  {
                    promptId: prompt.promptId,
                    fingerprint: prompt.fingerprint,
                    // The typed host, not the backend's: through a tunnel the
                    // backend dialled `127.0.0.1`, which names the wrong end of
                    // it for a question about a remote machine's certificate.
                    host,
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
      for (const id of raised) {
        useHostKeyPrompt.getState().abandon(id);
        pendingPrompts.current.delete(id);
      }
      // The probe is over either way, so the tunnel goes with it: a Test that
      // left a bastion session open would hold one for as long as the app runs,
      // since nothing else has a handle on it.
      dial?.release();
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
        // Explicit, because the form now owns this field: leaving it to the
        // spread would make "None (direct)" unselectable on a row that already
        // had a tunnel. `undefined` rather than an empty object, so a direct
        // connection is the absence of a tunnel and not an empty one.
        tunnel: draft.tunnelSshConnectionId
          ? { sshConnectionId: draft.tunnelSshConnectionId }
          : undefined,
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

          <Field label="SSH tunnel (optional)">
            {/* NOT `modal`, for the same reason the size picker above is not. */}
            <Popover open={tunnelPickerOpen} onOpenChange={setTunnelPickerOpen}>
              <PopoverTrigger asChild>
                <Button
                  type="button"
                  variant="outline"
                  role="combobox"
                  aria-expanded={tunnelPickerOpen}
                  className="h-8 w-full justify-between px-2.5 text-[12px] font-normal"
                >
                  <span className={cn("truncate", !selectedTunnel && "text-muted-foreground")}>
                    {selectedTunnel
                      ? `${selectedTunnel.name} (${selectedTunnel.user}@${selectedTunnel.host}:${selectedTunnel.port})`
                      : "None (dial the host directly)"}
                  </span>
                  <ChevronDown size={13} strokeWidth={2} className="ml-2 shrink-0 opacity-60" />
                </Button>
              </PopoverTrigger>
              <PopoverContent
                align="start"
                sideOffset={6}
                className="w-[var(--radix-popover-trigger-width)] gap-0 overflow-hidden rounded-2xl p-0"
              >
                <Command className="rounded-2xl">
                  <CommandInput placeholder="Search saved SSH hosts…" className="text-[12px]" />
                  <CommandList className="max-h-56">
                    <CommandEmpty className="py-4 text-[11px]">
                      No saved SSH host found.
                    </CommandEmpty>
                    <CommandGroup>
                      <CommandItem
                        value="none direct connection"
                        data-checked={!draft.tunnelSshConnectionId ? "true" : undefined}
                        onSelect={() => {
                          setDraft((d) => ({ ...d, tunnelSshConnectionId: "" }));
                          setTunnelPickerOpen(false);
                        }}
                        className="gap-2 rounded-xl px-2.5 py-1.5 text-[12px]"
                      >
                        <span className="truncate">None (dial the host directly)</span>
                      </CommandItem>
                      {sshConns.map((c) => (
                        <CommandItem
                          key={c.id}
                          // Searchable on name + user@host:port; the id keeps the
                          // value unique so cmdk never collapses two like-named hosts.
                          value={`${c.name} ${c.user}@${c.host}:${c.port} ${c.id}`}
                          data-checked={draft.tunnelSshConnectionId === c.id ? "true" : undefined}
                          onSelect={() => {
                            setDraft((d) => ({ ...d, tunnelSshConnectionId: c.id }));
                            setTunnelPickerOpen(false);
                          }}
                          className="gap-2 rounded-xl px-2.5 py-1.5 text-[12px]"
                        >
                          <span className="flex min-w-0 flex-col">
                            <span className="truncate">{c.name}</span>
                            <span className="text-muted-foreground truncate font-mono text-[10px]">
                              {c.user}@{c.host}:{c.port}
                            </span>
                          </span>
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
            <span className="text-muted-foreground text-[10.5px]">
              {selectedTunnel ? (
                <>
                  Host and port above are resolved{" "}
                  <span className="font-medium">from {selectedTunnel.name}</span>, not from this
                  machine — so a Windows box with no public 3389 is reached at its private address.
                  The SSH host needs nothing installed and does not have to be the Windows machine
                  itself; anything that can reach its 3389 will do. Its own jump-host chain applies
                  too.
                </>
              ) : (
                <>
                  Reach this host through a saved SSH connection instead of dialling it directly,
                  for a machine whose 3389 is not exposed. The trusted certificate is the same
                  either way.
                </>
              )}
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
