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
import { Textarea } from "@/components/ui/textarea";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import { Combobox, type ComboboxOption } from "./editor/Combobox";
import { Field, ToggleButton } from "./editor/FormControls";
import {
  RdpCredentialSection,
  rdpCredentialForTest,
  validateRdpCredential,
} from "./editor/RdpCredentialSection";
import { RdpOptions } from "./editor/RdpOptions";
import { runRdpProbe } from "./editor/rdpProbe";
import { SECRET_STORE_LOCATIONS } from "./editor/secretStoreCopy";
import {
  clearsSecret,
  NOTHING_SEEDED,
  sshSecretsForSave,
  type SshSecretSeeded,
} from "./editor/sshSecrets";
import { SshCredentialSection, validateSshCredential } from "./editor/SshCredentialSection";
import { SshOptions } from "./editor/SshOptions";
import { runSshProbe } from "./editor/sshProbe";
import {
  NO_SSH_SECRETS_TOUCHED,
  type RdpCredentialDraft,
  type SharedDraft,
  type SshCredentialDraft,
  type SshSecretTouched,
  type TestState,
} from "./editor/types";
import type { HostEditorTarget } from "./pendingEditor";
import {
  findHost,
  getHostSshSecrets,
  listGroups,
  listHosts,
  newHostId,
  upsertHost,
  type HostSecretInput,
} from "./store";
import {
  CREDENTIAL_STAMP_ABSENT,
  credentialStamp,
  hostPins,
  HostBindingChangedError,
  isRdpHost,
  isSshHost,
  presetById,
  presetIdFor,
  RDP_DEFAULT_PORT,
  RDP_DEFAULT_PRESET,
  SSH_DEFAULT_PORT,
  type Host,
  type HostGroup,
  type HostPins,
  type SshHost,
} from "./types";

// One protocol-aware host editor, replacing `SshConnectionDialog` and
// `RdpConnectionDialog`.
//
// What is merged here is the SHELL: the fields both protocols share, the mode
// handling, the pinned-key row, and the save path. The credential regions are
// lifted into `editor/SshCredentialSection` and `editor/RdpCredentialSection`
// as-they-were, because the three-state secret convention is the part of these two
// dialogs that costs a lost credential when it is got wrong and merging two forms
// is quite enough to do in one pass.
//
// Nothing here makes a secret safer than it was. On Linux a private key sits in a
// mode-0600 JSON file before and after, and the SSH connect path still round-trips
// plaintext through the webview. What the vault binding this form preserves buys is
// FEWER COPIES of one secret.

export type HostEditorDialogProps = {
  /** null = closed. */
  target: HostEditorTarget | null;
  onClose: () => void;
  /** After a successful save, with the persisted record. */
  onSaved?: (host: Host) => void;
};

const EMPTY_SHARED: SharedDraft = { name: "", host: "", port: "", groupId: "", description: "" };

const EMPTY_SSH_CRED: SshCredentialDraft = {
  user: "",
  authMode: "password",
  password: "",
  privateKey: "",
  keyPassphrase: "",
};

const EMPTY_RDP_CRED: RdpCredentialDraft = { username: "", domain: "", password: "" };

function defaultPortFor(protocol: "ssh" | "rdp"): number {
  return protocol === "ssh" ? SSH_DEFAULT_PORT : RDP_DEFAULT_PORT;
}

/**
 * A token for "the row the form is showing RIGHT NOW", stable across re-renders
 * and different for every distinct target.
 *
 * Two jobs. It is the effect's guard, so a parent that builds `target` inline does
 * not restart the load on every one of its own renders - the object's identity
 * changes, this string does not. And it is what a Test probe compares itself
 * against: a probe can outlive the row it started on (the dialog stays mounted, the
 * trust prompt is global and waits on a human), so every write to form state has to
 * ask whether the form still belongs to the row that was tested.
 */
function tokenFor(target: HostEditorTarget | null): string | null {
  if (!target) return null;
  if (target.mode === "edit") return `edit:${target.hostId}`;
  return `create:${target.protocol}:${JSON.stringify(target.prefill ?? {})}`;
}

export function HostEditorDialog({ target, onClose, onSaved }: HostEditorDialogProps): ReactNode {
  const [shared, setShared] = useState<SharedDraft>(EMPTY_SHARED);
  const [protocol, setProtocol] = useState<"ssh" | "rdp">("ssh");
  // Taken from the target when one is applied rather than read off `target` on
  // every render, because `target` goes null the moment the dialog starts closing
  // and the title would flip to "New host" behind the fade.
  const [mode, setMode] = useState<"create" | "edit">("create");
  const [portTouched, setPortTouched] = useState(false);
  const [sshCred, setSshCred] = useState<SshCredentialDraft>(EMPTY_SSH_CRED);
  /**
   * Which SSH secret fields the USER has edited in this sitting.
   *
   * A ref rather than state, and that is load-bearing rather than an
   * optimisation. The keychain seed below lands AFTER an await, and a `useState`
   * value it read would be the one captured when the load started - all three
   * false, forever, because the reset at the top of the same effect is what set
   * them. So a field the user filled while the read was in flight would be
   * overwritten by the seed and still count as touched, and the save would send
   * the seed back over the rotation the user had just typed.
   *
   * ONE record, read by both the seed guard and the save, because two records of
   * the same fact is how a guard and the thing it guards drift apart. Nothing
   * renders from it, so state buys no render either. Always replaced, never
   * mutated in place: the initial value is a shared module constant.
   */
  const sshTouched = useRef<SshSecretTouched>(NO_SSH_SECRETS_TOUCHED);
  /**
   * Which SSH secret fields the keychain seed put a value the user can SEE into.
   *
   * A DIFFERENT FACT from `sshTouched`, not a second copy of it - §5.14's "keep
   * exactly one such record" is about the touched mark, which is still one cell
   * read by both the seed and the save. `touched` says the user edited the field;
   * this says the field was showing a stored value while they did, and only that
   * makes emptying it an instruction to delete something. Without it, one
   * character typed and backspaced before the read landed sent `""` down to the
   * store, which is its CLEAR instruction, and the keychain account went with it.
   *
   * A ref for the same reason `sshTouched` is one: it is written after the seed's
   * await and read by the save, and neither renders from it.
   */
  const sshSeeded = useRef<SshSecretSeeded>(NOTHING_SEEDED);
  const [proxyJumpId, setProxyJumpId] = useState("");
  const [rdpCred, setRdpCred] = useState<RdpCredentialDraft>(EMPTY_RDP_CRED);
  const [presetId, setPresetId] = useState(RDP_DEFAULT_PRESET.id);
  const [tunnelSshHostId, setTunnelSshHostId] = useState("");
  /** The stored record being edited, or null in create mode. */
  const [existing, setExisting] = useState<Host | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<TestState>({ kind: "idle" });
  /**
   * The server keys this host trusts, as of right now, keyed by the ADDRESS each
   * was presented at: seeded from the saved record, added to by trusting a new one
   * during Test, and pruned by Forget.
   *
   * The single source of truth for the pin - what Test verifies against AND what
   * Save writes - so a key trusted here cannot be lost and a forgotten one cannot
   * come back from a stale record.
   *
   * KEYED, and that is the whole of this fix. With one pin per host, Test compared
   * against the pin of the machine the saved record still named, so testing a new
   * address meant pressing Forget first - and Forget went straight to the store, so
   * Cancel reverted the address and left the host with no pin at all, silently back
   * on TOFU. Per address, an address never visited simply has no pin and takes the
   * TOFU prompt, and the saved address's pin is never in the way. Nothing in here
   * is persisted until Save, so Cancel disposes of the whole map.
   */
  const [pins, setPins] = useState<HostPins>({});

  const token = tokenFor(target);
  /** The token whose load has been applied. A ref rather than state because the
   *  effect and the probes both read it without wanting a render. */
  const applied = useRef<string | null>(null);
  // Trust prompts a Test probe currently has outstanding: the RDP certificate, and
  // the SSH host key of a tunnel it had to dial first. A ref because the only
  // reader is the unmount teardown below, and it must see the latest value without
  // a re-render.
  const pendingPrompts = useRef<Set<string>>(new Set());

  // A Test probe that raised a trust question has a backend parked INSIDE a
  // handshake: for the certificate, `rdp_open` has not returned, so no session id
  // exists and there is nothing to close; for the tunnel's host key it is
  // `ssh_open` one step earlier. If this editor goes away with the question
  // unanswered - the tab closes, the window navigates, a lazy boundary re-mounts -
  // the socket and a blocked thread are held for the full 120-second confirm
  // timeout. Rejecting on the way out is what releases them, and it no-ops if the
  // user already answered.
  useEffect(
    () => () => {
      const outstanding = [...pendingPrompts.current];
      pendingPrompts.current.clear();
      for (const id of outstanding) useHostKeyPrompt.getState().abandon(id);
    },
    [],
  );

  // Reset and populate whenever the editor is pointed at a different row. Closing
  // deliberately leaves the draft alone: the next open resets it, and wiping it
  // here would empty every field behind the dialog's own close animation.
  useEffect(() => {
    if (applied.current === token) return;
    applied.current = token;
    if (!target || !token) return;

    setError(null);
    setSaving(false);
    setTest({ kind: "idle" });
    // Per row, or the last row's typing would suppress this one's seed - and the
    // last row's seed would license clearing this one's secret.
    sshTouched.current = NO_SSH_SECRETS_TOUCHED;
    sshSeeded.current = NOTHING_SEEDED;
    setExisting(null);
    setReady(false);
    setMode(target.mode);

    const stale = () => applied.current !== token;

    const load = async () => {
      let allHosts: Host[];
      let allGroups: HostGroup[];
      try {
        [allHosts, allGroups] = await Promise.all([listHosts(), listGroups()]);
      } catch (e) {
        if (!stale()) setError(e instanceof Error ? e.message : String(e));
        return;
      }
      if (stale()) return;
      setHosts(allHosts);
      setGroups(allGroups);

      // A reference whose target is gone is dropped rather than kept: a dangling
      // jump host or tunnel fails every connect with "does not exist", and a
      // dangling group renders as ungrouped anyway. The pickers and the next save
      // then say what will actually happen.
      const liveGroup = (id: string | undefined) =>
        id && allGroups.some((g) => g.id === id) ? id : "";
      const liveSshHost = (id: string | undefined) =>
        id && allHosts.some((h) => h.id === id && isSshHost(h)) ? id : "";

      if (target.mode === "create") {
        const prefill = target.prefill ?? {};
        setProtocol(target.protocol);
        setPortTouched(prefill.port !== undefined);
        setShared({
          name: prefill.name ?? "",
          host: prefill.host ?? "",
          port: String(prefill.port ?? defaultPortFor(target.protocol)),
          groupId: liveGroup(prefill.groupId),
          description: "",
        });
        setSshCred({ ...EMPTY_SSH_CRED, user: prefill.user ?? "" });
        setRdpCred({ ...EMPTY_RDP_CRED, username: prefill.user ?? "" });
        setProxyJumpId("");
        setPresetId(RDP_DEFAULT_PRESET.id);
        setTunnelSshHostId("");
        setPins({});
        setReady(true);
        return;
      }

      const host = allHosts.find((h) => h.id === target.hostId);
      if (!host) {
        setError("That host no longer exists - it was deleted in another window.");
        return;
      }
      setExisting(host);
      setProtocol(host.protocol);
      setPortTouched(true);
      setShared({
        name: host.name,
        host: host.host,
        port: String(host.port),
        groupId: liveGroup(host.groupId),
        description: host.description ?? "",
      });
      // Through `hostPins`, never off the flat field: it is the one place a record
      // written before pins were keyed adopts its pin onto the address that record
      // names, so seeding here from `lastFingerprint` instead would be a second
      // copy of that migration - and the copy that drifts is how a pin silently
      // stops being found.
      setPins(hostPins(host));

      // Narrowed with the exported predicates, never a cast: a lookup by id
      // against the whole host list can hand back either protocol, and a cast
      // would read `desktopWidth` off an SSH row as `undefined` rather than
      // saying so.
      if (isSshHost(host)) {
        // Only the inline arm carries a user and an auth mode to prefill; a
        // vault-bound host has neither, and the section below hides both rather
        // than offering an empty one that a save would then write.
        const inline = host.credential.kind === "inline" ? host.credential : null;
        setSshCred({
          user: inline?.user ?? "",
          authMode: inline?.authMode ?? "password",
          password: "",
          privateKey: "",
          keyPassphrase: "",
        });
        setProxyJumpId(liveSshHost(host.proxyJumpId));
        setRdpCred(EMPTY_RDP_CRED);
        setPresetId(RDP_DEFAULT_PRESET.id);
        setTunnelSshHostId("");
        // Interactive BEFORE the secret read, deliberately. Moving this below the
        // await would close the race the seed below guards against, but it would
        // hold the whole form - name, address, port, group - behind "Loading…" for
        // however long the keychain takes, which on macOS is up to three OS access
        // prompts, and would leave a failed read with nothing on screen but an
        // error unless it re-armed in the catch as well. The seed yielding to a
        // touched field fixes the same defect without making an unrelated edit
        // wait on a secret it never looks at.
        setReady(true);
        // Skipped for a vault-bound row: it owns no accounts, so this returns an
        // empty batch, and asking makes the blank draft look like a read result.
        if (!inline) return;
        try {
          const secrets = await getHostSshSecrets(host.id);
          if (stale()) return;
          // Per field, and only where the user has not typed. `stale()` is not
          // enough on its own: it asks whether the form has moved to a DIFFERENT
          // ROW, and typing does not move it. The form has been interactive since
          // `setReady(true)` above, and this read is three sequential
          // `keyring::Entry::get_password` calls on macOS, any of which can stop
          // on an OS access prompt - so "the user typed a new password into a
          // field this seed is about to fill" is an ordinary race, not a corner.
          // Seeding over it would send the OLD secret back on save (the field
          // counts as touched) and report success, silently losing the rotation.
          //
          // Read out here rather than inside the updater: the ref is already
          // current at this point, and a keystroke arriving between this call and
          // the updater running queues its own patch AFTER this one, so it wins
          // anyway.
          const typed = sshTouched.current;
          setSshCred((d) => ({
            ...d,
            password: typed.password ? d.password : (secrets.password ?? ""),
            privateKey: typed.privateKey ? d.privateKey : (secrets.privateKey ?? ""),
            keyPassphrase: typed.keyPassphrase ? d.keyPassphrase : (secrets.keyPassphrase ?? ""),
          }));
          // What the user can now SEE, which is what licenses a later clear -
          // see `sshSecretsForSave`. Derived from the same `typed` the seed just
          // yielded to, and from the value that actually arrived: a field the
          // seed skipped is NOT seeded however much the keychain held, because
          // the stored value never reached the screen, and a field seeded with
          // nothing is not either. Computed out here rather than inside the
          // updater, which must stay pure - React is free to call it twice.
          sshSeeded.current = {
            password: !typed.password && !clearsSecret(secrets.password ?? ""),
            privateKey: !typed.privateKey && !clearsSecret(secrets.privateKey ?? ""),
            keyPassphrase: !typed.keyPassphrase && !clearsSecret(secrets.keyPassphrase ?? ""),
          };
        } catch (e) {
          // Reported rather than swallowed, and the form stays usable: the three
          // fields are untouched, so a save now writes none of them and the
          // stored secrets are left exactly as they are.
          if (!stale()) setError(e instanceof Error ? e.message : String(e));
        }
        return;
      }

      if (isRdpHost(host)) {
        const inline = host.credential.kind === "inline" ? host.credential : null;
        setRdpCred({
          username: inline?.username ?? "",
          domain: inline?.domain ?? "",
          // Deliberately blank, and there is no path that fills it: the stored
          // password is never read back into the webview, so blank means "leave
          // it alone".
          password: "",
        });
        // A row written by a build offering a size this one does not falls back to
        // the default rather than showing an empty picker.
        setPresetId(presetIdFor(host.desktopWidth, host.desktopHeight) || RDP_DEFAULT_PRESET.id);
        setTunnelSshHostId(liveSshHost(host.tunnel?.sshHostId));
        setSshCred(EMPTY_SSH_CRED);
        setProxyJumpId("");
        setReady(true);
        return;
      }

      const unhandled: never = host;
      setError(`hosts: unhandled protocol ${String(unhandled)}`);
    };

    void load();
  }, [target, token]);

  const boundIdentity =
    existing && existing.credential.kind === "identity" ? existing.credential.identityId : null;
  // Blank is only "unchanged" when there is something stored to leave unchanged,
  // and that flag lives under the inline arm only.
  const hasStoredRdpPassword =
    !!existing &&
    existing.protocol === "rdp" &&
    existing.credential.kind === "inline" &&
    existing.credential.hasPassword;
  // The same flag for SSH, and it is here to keep the help text honest rather
  // than to validate anything: what "leave this blank" produces is the opposite
  // on the two sides of it. On a host with nothing stored, blank saves a host
  // with no password; on a host that has one, blank means the seed has not landed
  // and the save leaves the stored password exactly as it is. Read off the record
  // rather than off the draft, because the draft is blank in both cases.
  const hasStoredSshPassword =
    !!existing &&
    existing.protocol === "ssh" &&
    existing.credential.kind === "inline" &&
    existing.credential.hasPassword;
  // The address the form is proposing, trimmed exactly as Test and Save trim it,
  // so all three agree about which pin is the current one.
  const draftAddress = shared.host.trim();
  /** The pin for the address currently in the form: what Test verifies against,
   *  what the recorded-key row shows, and what Forget removes. */
  const pinnedFingerprint = pins[draftAddress];
  const preset = presetById(presetId) ?? RDP_DEFAULT_PRESET;
  // Jump-host and tunnel options: every saved SSH host except the one being
  // edited, which cannot be its own bastion.
  const sshHosts: SshHost[] = hosts.filter(isSshHost).filter((h) => h.id !== existing?.id);
  const groupOptions: ComboboxOption[] = [
    { value: "", label: "None", search: "none no group ungrouped" },
    ...groups.map((g) => ({ value: g.id, label: g.name, search: `${g.name} ${g.id}` })),
  ];

  /**
   * Every write from a credential section arrives as a patch, and the keys it
   * carries are what mark a secret field as touched.
   *
   * This is the mechanism behind {@link sshSecretsForSave}: the keychain load
   * above writes `setSshCred` directly and so marks nothing, while a keystroke or
   * a key import comes through here. An edit that never touched the password
   * field therefore cannot send one.
   *
   * It is also what the seed yields to, which is why the mark is taken here and
   * not inside an updater: the seed reads it after its own await, so it has to be
   * true the moment the keystroke happens rather than one render later.
   *
   * The mark says the field was EDITED, and deliberately nothing more - `patch.
   * password !== undefined` is true for `""`, because emptying a field is an edit.
   * It is `sshSeeded` that decides whether that particular edit is allowed to
   * delete anything, and the reason the two are separate is that this handler
   * cannot tell a backspace over a seeded password from a backspace over a field
   * the keychain read has not reached yet.
   */
  const patchSshCred = (patch: Partial<SshCredentialDraft>) => {
    setSshCred((d) => ({ ...d, ...patch }));
    sshTouched.current = {
      password: sshTouched.current.password || patch.password !== undefined,
      privateKey: sshTouched.current.privateKey || patch.privateKey !== undefined,
      keyPassphrase: sshTouched.current.keyPassphrase || patch.keyPassphrase !== undefined,
    };
  };

  const changeProtocol = (next: "ssh" | "rdp") => {
    setProtocol(next);
    // Both of these were about the other protocol: a validation message names a
    // field that is no longer on screen, and a Test result describes a handshake
    // nothing on this form would make now.
    setError(null);
    setTest({ kind: "idle" });
    // The port follows the protocol until the user says otherwise, so switching
    // does not leave 22 on an RDP host - and does not overwrite a port that was
    // typed or prefilled.
    if (!portTouched) setShared((s) => ({ ...s, port: String(defaultPortFor(next)) }));
  };

  const validate = (): string | null => {
    const port = Number.parseInt(shared.port, 10);
    if (!shared.name.trim()) return "Name is required";
    if (!shared.host.trim()) return "Host is required";
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return "Port must be 1–65535";
    return protocol === "ssh"
      ? validateSshCredential(sshCred, boundIdentity)
      : validateRdpCredential(rdpCred, boundIdentity, hasStoredRdpPassword);
  };

  /**
   * Forget the pin for the address on screen - IN THE DRAFT. Save is what applies
   * it, and Cancel is what discards it.
   *
   * This used to write the deletion straight to the store, and that was the defect
   * rather than an ordering preference: Cancel correctly reverted the address and
   * nothing reverted the pin, so the host was left with no pinned key, silently
   * back on TOFU, accepting whatever the next connect was presented. Unrecoverable
   * too - only that machine can present that key again. The forced sequence that
   * made it reachable (Forget before you could Test a new address) is gone as well,
   * because pins are keyed per address now.
   *
   * No `existing` guard any more, and the reason is that there is nothing left for
   * it to guard rather than a case it was getting wrong: this touches the draft map
   * and nothing else, so the saved record is not an operand of any of it. The
   * unsaved host it would have refused is not reachable either - `PinnedKeyRow`,
   * which is the only thing that calls this, renders only under `mode === "edit"`.
   */
  const forgetPin = () => {
    setPins((current) => {
      const next = { ...current };
      delete next[draftAddress];
      return next;
    });
    // A stale "mismatch" result no longer means anything.
    setTest({ kind: "idle" });
  };

  const runTest = async () => {
    // UNREACHABLE as the form stands, and kept anyway: the Test button is
    // `disabled` for a vault-bound row, so nothing can call this with one. It
    // exists so that a caller which is NOT that button - a keyboard shortcut, a
    // second Test entry point, the identity picker's own arrival - refuses rather
    // than dialling with the blank draft a bound row loads. Testing one for real
    // needs the identity's credentials, which means the resolver and the picker,
    // both the Vault page's work.
    if (boundIdentity) {
      setError("A host bound to a vault identity cannot be tested from here yet.");
      return;
    }
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setError(null);
    setTest({ kind: "running" });

    const port = Number.parseInt(shared.port, 10);
    const host = shared.host.trim();
    // The row this probe is about. Every write to form state below is gated on the
    // editor still being on it, because the form is per-dialog while the probe is
    // per-row: open row A, Test, close, open row B, then answer A's prompt, and an
    // ungated write puts A's certificate into B's pin state - which Save then
    // persists onto B. It fails closed (B's next connect aborts as a mismatch) but
    // it is still a pin on a row the user never tested.
    const probeToken = token;
    const probeHostId = existing?.id;
    const onProbeRow = () => applied.current === probeToken;
    const onTrusted = (fingerprint: string) => {
      // The FORM's pins follow the row on screen. Unsaved, visible in the
      // recorded-key row, and disposed of by Forget or Cancel, so one of them may
      // describe the address being proposed. Keyed by `host` - the address this
      // probe actually DIALLED - rather than by whatever is in the field now: a
      // trust prompt waits on a human, and the user is free to keep typing while it
      // does.
      if (onProbeRow()) setPins((current) => ({ ...current, [host]: fingerprint }));
      // AND THE STORE IS NOT WRITTEN AT ALL. There used to be a `pinFingerprint`
      // call here, gated on the saved record still naming the address the probe
      // dialled (§5.16, which that gate closed: a cancelled dialog must not leave
      // a FOREIGN machine's fingerprint on a record, because the next real connect
      // aborts as a MISMATCH and that reads as an attack). The gate was sound and
      // still incomplete - it stopped the write landing on the wrong address, not
      // on the right one:
      //
      //   press Forget (which now edits the DRAFT), so the pin for this address is
      //   gone from `pins` but still in the store; Test the same address, which
      //   therefore TOFUs instead of reporting the mismatch the pin existed to
      //   raise; accept; the addresses match, so the write goes through and
      //   REPLACES the stored pin; Cancel. The old pin cannot come back - only that
      //   machine can present it - and nothing warned anyone. Forget-then-Test is
      //   the natural sequence exactly when a key is suspected of having rotated.
      //
      // No gate fixes that, because the destructive write is the one the gate
      // permits. Deleting the write does, and it costs nothing: `pins` above is
      // already the single source of truth, Save writes the whole map, and Cancel
      // disposes of it. §5.16's question - does this survive Cancel, and should it -
      // now has no store write in this dialog to ask it of. Save is the only thing
      // that commits a pin, which is what the comment on `pins` has always claimed.
      //
      // What is given up: accept a key, then Cancel, and nothing is pinned, so the
      // next real connect asks again. That is the safe direction and the one the
      // footnote on the recorded-key row promises.
    };

    try {
      if (protocol === "ssh") {
        const result = await runSshProbe({
          host,
          port,
          user: sshCred.user.trim(),
          authMode: sshCred.authMode,
          secrets: {
            password: sshCred.password,
            privateKey: sshCred.privateKey,
            keyPassphrase: sshCred.keyPassphrase,
          },
          // The pin for the address THIS PROBE DIALS, which is what removes the
          // forced Forget: an address never visited has no pin here, so Test does
          // TOFU against the machine actually being reached rather than comparing it
          // against a different machine's key and refusing.
          expectedFingerprint: pins[host] || undefined,
          proxyJumpId: proxyJumpId || undefined,
          hostId: probeHostId,
          hosts,
          onTrusted,
        });
        if (onProbeRow()) {
          setTest({
            kind: "ok",
            summary: `Connected · server key ${result.fingerprint || "(unavailable)"} · ${result.durationMs}ms`,
          });
        }
        return;
      }

      const credential = rdpCredentialForTest({
        draft: rdpCred,
        boundIdentity,
        hostId: probeHostId,
        hasStoredPassword: hasStoredRdpPassword,
      });
      if (!credential) {
        setTest({ kind: "idle" });
        setError("Enter a password to test this connection");
        return;
      }
      const result = await runRdpProbe({
        host,
        port,
        username: rdpCred.username.trim(),
        domain: rdpCred.domain.trim() || undefined,
        credential,
        width: preset.width,
        height: preset.height,
        expectedCertFingerprint: pins[host] || undefined,
        tunnelSshHostId: tunnelSshHostId || undefined,
        onTrusted,
        prompts: {
          raised: (id) => pendingPrompts.current.add(id),
          settled: (id) => pendingPrompts.current.delete(id),
        },
      });
      if (onProbeRow()) {
        setTest({
          kind: "ok",
          summary: `Connected · ${result.width}×${result.height} desktop · certificate ${result.fingerprint || "(unavailable)"} · ${result.durationMs}ms`,
        });
      }
    } catch (e) {
      if (onProbeRow()) {
        setTest({ kind: "fail", message: e instanceof Error ? e.message : String(e) });
      }
    }
  };

  const save = async () => {
    setError(null);
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    const port = Number.parseInt(shared.port, 10);
    setSaving(true);
    try {
      const id = existing?.id ?? newHostId();
      const host = shared.host.trim();
      // No `keepPin` any more, and its absence is the fix rather than a
      // simplification. It answered "did the address change, so is the pin stale"
      // - a heuristic that was right only while a pin could not be recorded for
      // any address but the saved one. Now that Test can TOFU a new address, the
      // pin the user has just accepted BELONGS to the new address, and that
      // heuristic would have thrown it away. `pins` says which address each key
      // was presented at, so the store projects the right one and keeps the rest
      // under their own keys instead of discarding them.
      // Built field by field rather than spread over the stored record, and that is
      // the point rather than verbosity: a spread is how a credential naming
      // ANOTHER host reaches a save (§5.1), and how the other protocol's fields
      // ride along on a record that has no business carrying them.
      // `lastConnectedAt` is the only field the form does not own, so it is the
      // only one carried across.
      const base = {
        id,
        name: shared.name.trim(),
        host,
        port,
        groupId: shared.groupId || undefined,
        description: shared.description.trim() || undefined,
        lastConnectedAt: existing?.lastConnectedAt,
        // The whole draft map, addresses and all. The store decides which of them
        // is the flat pin every consumer reads, so `lastFingerprint` /
        // `certFingerprint` are deliberately NOT set here - one writer for the
        // projection, and it is the layer that also sees an import and a
        // duplicate. A pin for an address this record no longer names is kept
        // rather than dropped: re-pointing back finds it again instead of asking
        // TOFU about a machine already verified once.
        pins,
      };

      let record: Host;
      let secrets: HostSecretInput;
      if (protocol === "ssh") {
        record = {
          ...base,
          protocol: "ssh",
          // A vault binding is handed back exactly as it came in. There is no
          // identity picker here, so the only honest thing this form can do with a
          // binding it cannot show is leave it alone. Rebuilding an inline
          // credential instead was not a lesser version of that, it was
          // destructive: a non-inline record owns no accounts, so the draft loaded
          // blank and the blank went down as the store's CLEAR instruction - the
          // row lost its binding AND its secret while the identity's own secrets
          // sat untouched somewhere else.
          credential: boundIdentity
            ? { kind: "identity", identityId: boundIdentity }
            : {
                kind: "inline",
                // The host being saved, never another. `assertBindingOwner`
                // refuses anything else on the way in.
                hostId: id,
                user: sshCred.user.trim(),
                authMode: sshCred.authMode,
                // Written by the store from what it actually stored, so these three
                // are placeholders rather than claims.
                hasPassword: false,
                hasPrivateKey: false,
                hasKeyPassphrase: false,
              },
          proxyJumpId: proxyJumpId || undefined,
        };
        // Nothing at all for a vault-bound row: `upsertHost` REFUSES a secret
        // handed in with a vault binding, and the fields it would come from are
        // ones this form never fills.
        secrets = boundIdentity
          ? {}
          : sshSecretsForSave(sshCred, sshTouched.current, sshSeeded.current);
      } else {
        record = {
          ...base,
          protocol: "rdp",
          credential: boundIdentity
            ? { kind: "identity", identityId: boundIdentity }
            : {
                kind: "inline",
                hostId: id,
                username: rdpCred.username.trim(),
                domain: rdpCred.domain.trim() || undefined,
                hasPassword: false,
              },
          desktopWidth: preset.width,
          desktopHeight: preset.height,
          sizeMode: "preset",
          // `undefined` rather than an empty object, so a direct connection is the
          // absence of a tunnel and not an empty one.
          tunnel: tunnelSshHostId ? { sshHostId: tunnelSshHostId } : undefined,
        };
        // `undefined`, not `""`, when the field was left blank: an empty string
        // would DELETE the stored password, so an edit that only renamed the host
        // would leave it unable to connect.
        secrets = boundIdentity
          ? {}
          : { password: rdpCred.password ? rdpCred.password : undefined };
      }

      // `upsertHost` REFUSES rather than ignores a bad jump or tunnel target, a
      // secret against a vault-bound host, and key material against an RDP host -
      // as rejected promises. Caught here so the reason lands in the form instead
      // of the console.
      // The binding this form loaded, handed to the store so it can refuse a save
      // whose credential has moved underneath. Always passed, including in create
      // mode: `existing` is null there, the stamp is "absent", and the store finds
      // no record under a freshly minted id either - so the check passes and there
      // is no `mode` branch here to get wrong.
      const saved = await upsertHost(record, secrets, credentialStamp(existing));
      // The persisted record, not the one built above: the store fills in the
      // presence flags from what it actually wrote, so a caller that renders a
      // credential pip gets the truth rather than three `false`s.
      onSaved?.(saved);
      onClose();
    } catch (e) {
      if (!(e instanceof HostBindingChangedError)) {
        setError(e instanceof Error ? e.message : String(e));
      } else if (e.actual === CREDENTIAL_STAMP_ABSENT) {
        // No recovery offered, deliberately. `existing` is left exactly as it was
        // - nothing here calls `setExisting` - so `id` and the stamp this form
        // sends stay the same on a second press, and the store finds the same
        // absent record and refuses the same way again. Saving again does not
        // create a different host; it does not create anything at all.
        setError(
          `${e.message} Close this editor - pressing Save again will not help: this form ` +
            `still names the deleted record, so the write is refused the same way every time.`,
        );
      } else {
        // ONLY the stored record is refreshed. The draft - and every field the user
        // has typed into it - is deliberately untouched, which is what makes the
        // refusal a stop rather than a dead end: `existing` is what `boundIdentity`
        // and the next stamp are derived from, so one more press of Save writes the
        // same edits over the record as it now stands.
        //
        // Not seeded, either: re-running the keychain read here would overwrite a
        // password the user typed while the first read was in flight, which is the
        // exact defect `sshTouched` exists to prevent. This path reads the record,
        // never a secret.
        const fresh = await findHost(e.hostId).catch(() => undefined);
        if (fresh) setExisting(fresh);
        setError(
          `${e.message} Your edits are still here, and the credential shown below is now the ` +
            `current one - review it and press Save again.`,
        );
      }
    } finally {
      setSaving(false);
    }
  };

  const protocolLabel = protocol === "ssh" ? "SSH" : "RDP";
  const busy = saving || !ready;
  // The protocol is only known once the record has loaded, so until then the
  // title says less rather than naming the protocol of whatever row was open
  // before this one.
  const title = mode === "create" ? "New host" : ready ? `Edit ${protocolLabel} host` : "Edit host";

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {boundIdentity
              ? "This host authenticates with a shared vault identity, so its credential is not edited here."
              : protocol === "rdp"
                ? `The password is stored outside Tervia's settings file (${SECRET_STORE_LOCATIONS}) and read by Tervia's host process when you connect — it is never handed back to the interface.`
                : sshCred.authMode === "agent"
                  ? "Nothing to store: the local ssh-agent holds the key and signs each handshake."
                  : `Credentials are stored outside Tervia's settings file: ${SECRET_STORE_LOCATIONS}.`}
          </DialogDescription>
        </DialogHeader>

        {/* DialogContent caps at calc(100dvh-2rem). min-h-0 lets the inner stack
            shrink so the form scrolls inside the dialog instead of top fields
            sliding off-screen. -mr-2/pr-2 keeps the scrollbar off the content
            edge. */}
        <div className="-mr-2 flex min-h-0 flex-col gap-3 overflow-y-auto pr-2">
          {/* A load that failed reports its reason below instead, so the two do
              not stack up as "Loading…" over "that host no longer exists". */}
          {!ready && !error ? <p className="text-muted-foreground text-[11px]">Loading…</p> : null}
          {ready ? (
            <>
              <Field label="Protocol">
                {mode === "create" ? (
                  <div className="flex gap-1">
                    <ToggleButton active={protocol === "ssh"} onClick={() => changeProtocol("ssh")}>
                      SSH
                    </ToggleButton>
                    <ToggleButton active={protocol === "rdp"} onClick={() => changeProtocol("rdp")}>
                      RDP
                    </ToggleButton>
                  </div>
                ) : (
                  <>
                    <span className="text-[12px]">{protocolLabel}</span>
                    <span className="text-muted-foreground text-[10.5px]">
                      Fixed once a host is saved. Flipping it would leave the stored credential
                      describing the wrong thing - the password account survives the change while
                      the key material is released - so switching means a new host.
                    </span>
                  </>
                )}
              </Field>

              <Field label="Name">
                <Input
                  value={shared.name}
                  onChange={(e) => setShared({ ...shared, name: e.target.value })}
                  placeholder={protocol === "ssh" ? "prod-bastion" : "win-build-01"}
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
              </Field>

              <div className="grid grid-cols-[1fr_5rem] gap-2">
                <Field label="Host">
                  <Input
                    value={shared.host}
                    onChange={(e) => setShared({ ...shared, host: e.target.value })}
                    placeholder={
                      protocol === "ssh"
                        ? "example.com or 192.168.1.10"
                        : "win.example.com or 192.168.1.20"
                    }
                    spellCheck={false}
                    className="h-8 font-mono text-[12px]"
                  />
                </Field>
                <Field label="Port">
                  <Input
                    value={shared.port}
                    onChange={(e) => {
                      setPortTouched(true);
                      setShared({ ...shared, port: e.target.value });
                    }}
                    inputMode="numeric"
                    className="h-8 font-mono text-[12px]"
                  />
                </Field>
              </div>

              {protocol === "ssh" ? (
                <SshCredentialSection
                  boundIdentity={boundIdentity}
                  value={sshCred}
                  onChange={patchSshCred}
                  hasStoredPassword={hasStoredSshPassword}
                />
              ) : (
                <RdpCredentialSection
                  boundIdentity={boundIdentity}
                  value={rdpCred}
                  onChange={(patch) => setRdpCred((d) => ({ ...d, ...patch }))}
                  hasStoredPassword={hasStoredRdpPassword}
                />
              )}

              {protocol === "ssh" ? (
                <SshOptions hosts={sshHosts} proxyJumpId={proxyJumpId} onChange={setProxyJumpId} />
              ) : (
                <RdpOptions
                  sshHosts={sshHosts}
                  presetId={presetId}
                  tunnelSshHostId={tunnelSshHostId}
                  onPresetChange={setPresetId}
                  onTunnelChange={setTunnelSshHostId}
                />
              )}

              <Field label="Group">
                <Combobox
                  options={groupOptions}
                  value={shared.groupId}
                  onChange={(groupId) => setShared({ ...shared, groupId })}
                  searchPlaceholder="Search groups…"
                  emptyLabel="No group found."
                />
                <span className="text-muted-foreground text-[10.5px]">
                  A label for filtering, and a host has at most one. New groups are created on the
                  Hosts page.
                </span>
              </Field>

              <Field label="Description (optional)">
                <Textarea
                  value={shared.description}
                  onChange={(e) => setShared({ ...shared, description: e.target.value })}
                  placeholder="What this machine is for"
                  spellCheck={false}
                  className="h-16 text-[12px]"
                />
              </Field>

              {mode === "edit" ? (
                <PinnedKeyRow
                  label={protocol === "ssh" ? "Recorded server key" : "Recorded server certificate"}
                  fingerprint={pinnedFingerprint}
                  emptyText={
                    protocol === "ssh"
                      ? "No key pinned yet · next successful connect will record one (TOFU)."
                      : "No certificate pinned yet · the next connect will ask you to verify one (TOFU)."
                  }
                  // Says which address this row is about, because the row now
                  // changes as the Host field is edited: with a key per address, a
                  // re-pointed host shows the new address's pin (usually none) while
                  // the old one is still held and still saved.
                  // Both halves of the promise, because both are now true of
                  // every pin: Forget and a key accepted during Test are edits to
                  // this form, and saving is what applies either of them.
                  footnote={
                    protocol === "rdp"
                      ? `Recorded for ${draftAddress || "this address"}, not for a port, so the same machine keeps one trusted certificate however it is reached. Forget, and any certificate accepted while testing, apply when you save — cancelling leaves the recorded one alone.`
                      : `Recorded for ${draftAddress || "this address"}. Forget, and any key accepted while testing, apply when you save — cancelling leaves the recorded one alone.`
                  }
                  onForget={forgetPin}
                />
              ) : null}
            </>
          ) : null}

          {error ? <p className="text-destructive text-[11px]">{error}</p> : null}

          {test.kind === "running" ? (
            <p className="text-muted-foreground text-[11px]">Testing connection…</p>
          ) : test.kind === "ok" ? (
            <p className="text-diff-added text-[11px]">{test.summary}</p>
          ) : test.kind === "fail" ? (
            <p className="text-destructive text-[11px]">Test failed: {test.message}</p>
          ) : null}
        </div>

        {/* Override DialogFooter's flex-col-reverse so Cancel stays on the left at
            any viewport width. */}
        <DialogFooter className="flex-row items-center justify-between gap-2 sm:justify-between sm:[&>button]:flex-none">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void runTest()}
            disabled={test.kind === "running" || busy || boundIdentity !== null}
          >
            {test.kind === "running" ? "Testing…" : "Test connection"}
          </Button>
          <div className="flex items-center gap-2">
            <DialogClose asChild>
              <Button variant="outline" size="sm">
                Cancel
              </Button>
            </DialogClose>
            <Button size="sm" onClick={() => void save()} disabled={busy}>
              {saving ? "Saving…" : mode === "edit" ? "Save" : "Create"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * The pinned server key or certificate for the address on screen, with its Forget
 * action. Edit mode only: a host that has never been saved has nothing pinned to it.
 *
 * Forget edits the DRAFT and Save applies it, which the footnote says out loud -
 * a button that silently dropped a pinned key the moment it was pressed is what
 * left a cancelled dialog with the host back on TOFU.
 */
function PinnedKeyRow({
  label,
  fingerprint,
  emptyText,
  footnote,
  onForget,
}: {
  label: string;
  fingerprint: string | undefined;
  emptyText: string;
  footnote?: string;
  onForget: () => void;
}): ReactNode {
  return (
    <Field label={label}>
      {fingerprint ? (
        <div className="border-border/60 bg-muted/30 flex items-center justify-between gap-2 rounded-md border px-2 py-1">
          <span className="truncate font-mono text-[10.5px]" title={fingerprint}>
            {fingerprint}
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-6 shrink-0 px-2 text-[10.5px]"
            onClick={onForget}
          >
            Forget
          </Button>
        </div>
      ) : (
        <span className="text-muted-foreground text-[10.5px]">{emptyText}</span>
      )}
      {footnote ? <span className="text-muted-foreground text-[10.5px]">{footnote}</span> : null}
    </Field>
  );
}
