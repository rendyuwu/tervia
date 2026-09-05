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
import { Checkbox } from "@/components/ui/checkbox";
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
import { inspectSshKey } from "@/modules/ssh/bridge";
import { useHostKeyPrompt } from "@/modules/ssh/hostKeyPrompt";
import { encryptedKeyRefusal } from "@/modules/vault/editor/draft";
import {
  describeKeyError,
  vaultKeyFactsFrom,
  type VaultKeyFacts,
} from "@/modules/vault/keyInspect";
import type { IdentityRow } from "@/modules/vault/page/derive";
import { listKeys } from "@/modules/vault/store";
import type { VaultKey } from "@/modules/vault/types";
import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

import {
  bindHostToIdentity,
  convertHostToVault,
  detachHostFromVault,
  reusableVaultKey,
} from "./credentialMove";
import { Combobox, type ComboboxOption } from "./editor/Combobox";
import {
  CREDENTIAL_CHOICE_INLINE,
  CREDENTIAL_CHOICE_NEW_IDENTITY,
  credentialChangeFor,
  credentialChangeNote,
  credentialChangeTitle,
  currentCredentialChoice,
  hostKeySecretNames,
  hostOwnedSecretNames,
  identityChoice,
  identityIdFromChoice,
  type CredentialChange,
} from "./editor/credentialChoice";
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
// Nothing here protects a secret better than it was protected before. On Linux a
// private key sits in a mode-0600 JSON file before and after, and the SSH connect
// path still round-trips plaintext through the webview. What the vault binding this
// form preserves buys is FEWER COPIES of one secret.

export type HostEditorDialogProps = {
  /** null = closed. */
  target: HostEditorTarget | null;
  onClose: () => void;
  /** After a successful save, with the persisted record. */
  onSaved?: (host: Host) => void;
  /**
   * Every identity row, UNFILTERED - the credential picker's own options, and
   * the source this dialog resolves a bound identity's name from. A prop
   * rather than a vault subscription of this file's own: `identityRows` is
   * built once by the page from the vault hook it already subscribes to
   * (`vault/page/derive.ts:96-103`), so this dialog and the Hosts page cannot
   * disagree about what an identity is called.
   */
  identityRows: IdentityRow[];
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

/**
 * The convert confirmation's reuse question, and its three states.
 *
 * `VaultKey | null` would be two of them. "We have not looked yet" has to render
 * differently from "we looked and the vault holds nothing like it": the offer is
 * a choice with a consequence in both directions, and blank space where a
 * question is about to appear reads as there being nothing to ask.
 *
 * `fingerprint` is the one the INSPECTION produced, carried beside the record
 * rather than read back off `key.fingerprint` at the point of use. It is what
 * the offer claims - "the body this host stores hashes to this, and that record
 * says the same" - and `convertHostToVault` re-checks the claim against the
 * record it resolves. Read back off the record, that comparison would be the
 * record against itself and would assert nothing.
 */
type ReuseOffer =
  | { kind: "checking" }
  | { kind: "none" }
  | { kind: "candidate"; key: VaultKey; fingerprint: string };

const NO_REUSE_OFFER: ReuseOffer = { kind: "none" };

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

export function HostEditorDialog({
  target,
  onClose,
  onSaved,
  identityRows,
}: HostEditorDialogProps): ReactNode {
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
   * A DIFFERENT FACT from `sshTouched`, not a second copy of it - the rule that
   * there be exactly one such record is about the touched mark, which is still
   * one cell read by both the seed and the save. `touched` says the user edited
   * the field; this says the field was showing a stored value while they did,
   * and only that makes emptying it an instruction to delete something. Without
   * it, one character typed and backspaced before the read landed sent `""` down
   * to the store, which is its CLEAR instruction, and the keychain account went
   * with it.
   *
   * A ref for the same reason `sshTouched` is one: it is written after the seed's
   * await and read by the save, and neither renders from it.
   */
  const sshSeeded = useRef<SshSecretSeeded>(NOTHING_SEEDED);
  /**
   * Whether the user has asked this host to forget the key material it still
   * stores under an auth mode that cannot use it - IN THE DRAFT.
   *
   * STATE rather than a ref, unlike the two above, and for the opposite reason:
   * those two exist because they are read after the keychain seed's await, so a
   * captured value would be the one from before the user could type. This one is
   * RENDERED - the row's own button disappears once it is pressed, which is the
   * only feedback there is that anything happened - and nothing writes it across
   * an await.
   *
   * An intent rather than a write, exactly as {@link forgetPin} is: Save turns it
   * into `sshSecretsForSave`'s clear and Cancel discards it by unmounting. Cleared
   * in four places, each one a route by which the field it is about could come
   * back on screen or the accounts it names could change underneath it - the load
   * effect (a different row), {@link patchSshCred} (a switch back to key auth),
   * {@link applyCredentialChange} (the accounts moved or were deleted) and the
   * save's own stale-stamp recovery (the auth mode is re-seeded from the record).
   */
  const [forgetKey, setForgetKey] = useState(false);
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
  /**
   * The ONE refusal `save` produces about the private key body, kept apart from
   * `error` above so it can render inside the key field rather than in the
   * generic line at the bottom of the form.
   *
   * The split is the sentence's own doing: it tells the user to enter the
   * passphrase BELOW, and the passphrase input sits directly under the key
   * field - the vault key editor once rendered the same sentence under its
   * description field and that was a hand-tested defect. Everything else the
   * same `try` can fail with - a store refusal, a keychain error, a key the
   * backend cannot read at all - is about the form or about the whole record,
   * so it still lands at the bottom.
   */
  const [keyRefusal, setKeyRefusal] = useState<string | null>(null);
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
  /**
   * The credential picker's own value: one of the two sentinels from
   * `credentialChoice.ts`, or `identityChoice(id)` for one specific identity.
   *
   * Reset to `currentCredentialChoice(host)` in the load effect - in EITHER
   * mode, so a leftover choice from the previous row cannot leak into this one
   * - and again after every successful credential change, or the picker would
   * keep showing the value it just applied instead of what is now true.
   */
  const [choice, setChoice] = useState(CREDENTIAL_CHOICE_INLINE);
  /**
   * The change `credentialChangeFor` reported for `choice` at the moment
   * "Change credential" was pressed, waiting on the confirmation below.
   *
   * Create mode's picker is UNCONFIRMED:
   * `credentialChangeFor` answers `{kind:"none"}` for every create-mode choice
   * because `existing` is null, so this is only ever set from the edit-mode
   * button - there is no create-mode branch that opens it.
   */
  const [pendingChange, setPendingChange] = useState<CredentialChange | null>(null);
  /** The identity name offered in the convert confirmation - editable there,
   *  because `${user}@${host}` is a poor name for a credential about to be
   *  shared across every host that binds to it. */
  const [convertName, setConvertName] = useState("");
  /**
   * The vault key that already holds the private key a convert is about to move
   * in, as of the moment the confirmation opened.
   *
   * The lookup runs on the way INTO the confirmation, not inside
   * `applyCredentialChange`, because the answer is a question for the user and
   * the confirmation is the only place there is to ask it.
   */
  const [reuseOffer, setReuseOffer] = useState<ReuseOffer>(NO_REUSE_OFFER);
  /**
   * Whether the user took that offer.
   *
   * `false` on every open, and that default is the whole of the fallback: the
   * lookup is asynchronous and the Confirm button is deliberately not gated on
   * it, so a confirmation answered before the answer arrives mints a new key -
   * which is what every convert did before this existed.
   */
  const [reuseExistingKey, setReuseExistingKey] = useState(false);
  /**
   * Which lookup's answer is still wanted. The confirmation can be opened,
   * cancelled and reopened faster than `ssh_key_inspect` and the vault read
   * behind it return, and an answer from the previous open describes a key body
   * that may no longer be the one being converted - the same race the vault key
   * editor's inspection counter exists for.
   */
  const reuseGeneration = useRef(0);
  const [changing, setChanging] = useState(false);

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
    // A refusal names the key body of the row this editor was pointed away
    // from, and nothing about the next one.
    setKeyRefusal(null);
    setSaving(false);
    setTest({ kind: "idle" });
    // Per row, or the last row's typing would suppress this one's seed - and the
    // last row's seed would license clearing this one's secret.
    sshTouched.current = NO_SSH_SECRETS_TOUCHED;
    sshSeeded.current = NOTHING_SEEDED;
    // Per row for the same reason: the intent names the accounts of the row this
    // editor was pointed away from, and carrying it onto the next one would
    // delete a key nothing on screen has said a word about.
    setForgetKey(false);
    setExisting(null);
    setReady(false);
    setMode(target.mode);
    // A confirmation left open from the row this editor was just pointed away
    // from must not survive onto the new one - and neither may a reuse lookup
    // still in flight for it, which is what moving the generation on discards.
    setPendingChange(null);
    setConvertName("");
    reuseGeneration.current += 1;
    setReuseOffer(NO_REUSE_OFFER);
    setReuseExistingKey(false);

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
        // The create arm returns before the `currentCredentialChoice(host)`
        // reset below is reached, so it gets its own: a choice left over from a
        // previous EDIT sitting must not leak into a new host.
        setChoice(CREDENTIAL_CHOICE_INLINE);
        setReady(true);
        return;
      }

      const host = allHosts.find((h) => h.id === target.hostId);
      if (!host) {
        setError("That host no longer exists - it was deleted in another window.");
        return;
      }
      setExisting(host);
      setChoice(currentCredentialChoice(host));
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

  /**
   * The identity this row is bound to - the STORED binding in edit mode, the
   * draft picker's own choice in create mode.
   *
   * In EDIT mode this is the stored record's binding and nothing else. A draft
   * value here would let a stale picker rebuild a bound host's credential
   * inside `save()`, silently detaching a vault binding - so `save()` itself is
   * unchanged by this widening and stays ignorant of `choice` entirely.
   *
   * In CREATE mode there is no stored record, so the draft choice is the only
   * source there is: `save()`'s three `boundIdentity ?` ternaries build the
   * binding from it with NO CHANGE TO `save()` AT ALL, which is why
   * `scripts/host-editor-verify.ts` section [4] stays green.
   *
   * The test is `mode === "create"`, deliberately NOT `!existing`: the load
   * effect resets `existing` to `null` before its own fetch, so `existing` is
   * transiently null in edit mode too, and a `!existing` gate would let a
   * leftover `choice` from a previous sitting drive this during that window.
   */
  const boundIdentity =
    mode === "create"
      ? identityIdFromChoice(choice)
      : existing && existing.credential.kind === "identity"
        ? existing.credential.identityId
        : null;
  /** `boundIdentity`'s NAME, resolved here because this dialog is the only
   *  thing that holds `identityRows` - the credential sections take it as a
   *  prop rather than reading the vault themselves. */
  const boundIdentityName = boundIdentity
    ? identityRows.find((row) => row.identity.id === boundIdentity)?.identity.name
    : undefined;
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
  // Whether the stored record holds a private key BODY, in the same shape and
  // with the same guards, and here for the same reason plus one: what "leave this
  // blank" produces is the opposite on the two sides of it, AND under key auth a
  // blank body is also the one route that deletes the stored key. Off the record
  // rather than off the draft, because the draft's key body is blank both when
  // nothing is stored and while the keychain read is in flight - the same
  // confusion `sshSeeded` exists to keep out of the save.
  //
  // `hasPrivateKey` alone: `hasKeyPassphrase` is a different account, one this
  // field neither seeds from nor clears, and folding it in would put the
  // key-is-stored sentence on a record with no key body. See the
  // `hasStoredPrivateKey` prop in `editor/SshCredentialSection.tsx`.
  const hasStoredSshPrivateKey =
    !!existing &&
    existing.protocol === "ssh" &&
    existing.credential.kind === "inline" &&
    existing.credential.hasPrivateKey;
  /**
   * The key material the SSH section may offer to forget, or `[]` for no row.
   *
   * Off the STORED record, never the draft: the draft's key body is what the
   * keychain seed put there when the dialog opened, so a blank one means "the
   * read has not landed" just as often as it means "there is nothing stored",
   * and that is the same confusion `sshSeeded` exists to keep out of the save.
   * `hostKeySecretNames` answers `[]` for a vault-bound row and for an RDP row,
   * so neither needs a test here - a bound host owns no accounts of its own, and
   * an RDP host never held key material.
   *
   * The two conditions this DOES carry are about another surface having promised
   * something about the same accounts. A pending convert moves them and a pending
   * bind deletes them, both saying so in their own confirmation, and `changing` is
   * that write in flight; two surfaces promising something about one secret is how
   * the two come to say different things. Create mode falls out of `existing`
   * being null, which is also the honest answer: there is nothing stored yet.
   */
  const forgettableKeySecrets =
    existing && pendingChange === null && !changing ? hostKeySecretNames(existing) : [];
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

  // The credential picker's options. Each identity option carries the id in
  // `search` too, not only in `label` - `Combobox.tsx:27-29` and
  // `IdentityEditorDialog.tsx:152-155` already hold key options to the same
  // rule, because two like-named identities must not collapse into one entry.
  const identityOptions: ComboboxOption[] = identityRows.map((row) => ({
    value: identityChoice(row.identity.id),
    label: row.identity.name,
    hint: row.identity.username,
    search: `${row.identity.name} ${row.identity.id} ${row.identity.username}`,
  }));
  // `CREDENTIAL_CHOICE_NEW_IDENTITY` is EDIT MODE ONLY: a new host stores no
  // credentials to move, so offering to convert one would be a dead affordance.
  const credentialOptions: ComboboxOption[] = [
    {
      value: CREDENTIAL_CHOICE_INLINE,
      label: "This host's own credentials",
      search: "own inline credentials",
    },
    ...(mode === "edit"
      ? [
          {
            value: CREDENTIAL_CHOICE_NEW_IDENTITY,
            label: "New shared identity from these credentials…",
            search: "new shared identity convert vault",
          },
        ]
      : []),
    ...identityOptions,
  ];
  // `{kind:"none"}` for every create-mode choice, because `credentialChangeFor`
  // reads `existing`, which is null there - so the description and the "Change
  // credential" button below render for neither create mode nor an unchanged
  // edit-mode choice, with no mode test of their own.
  const credentialChange = credentialChangeFor(existing, choice);

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
    // A refusal from the LAST save describes the (body, passphrase) pair as it
    // stood then, and either edit makes it stale - exactly the staleness the
    // section's own `invalidateInspection` retires its inspection panel for, at
    // the same two inputs. Kept here rather than handed down as a callback
    // because the state is the dialog's and every edit already arrives here.
    if (patch.privateKey !== undefined || patch.keyPassphrase !== undefined) setKeyRefusal(null);
    // Switching back to key auth RETRACTS a forget intent, and this is the one
    // place that can see it happen. From this moment the key textarea is on
    // screen, seeded with the stored body, and the field itself is the route to
    // clearing it - so an intent left set would delete the very body the user is
    // now looking at and editing, without the row that promised it being
    // rendered anywhere. The other two modes keep it: neither shows a key field,
    // so the row is still there saying what Save will do. `forgetPin` retires a
    // stale Test result for the same class of reason.
    if (patch.authMode === "key") setForgetKey(false);
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

  /**
   * Forget the key material this host stores but cannot use - IN THE DRAFT, on
   * exactly the terms {@link forgetPin} spells out. Save applies it through
   * `sshSecretsForSave`, and Cancel discards it by unmounting this dialog.
   *
   * The gap it closes: an SSH host that authenticated with a private key and now
   * authenticates with a password keeps that key in the secret store for good.
   * The record is honest about holding it and nothing releases it - an auth-mode
   * change is not a protocol change, so the store still NAMES all three accounts
   * and correctly declines to release any of them - and the export enumerates
   * every field the protocol owns, so the stale key travels in every backup file.
   * The one route that ever removed it is the key textarea, which is rendered
   * only under key auth: the route disappears at exactly the moment it becomes
   * the thing the user wants.
   *
   * `existing` is not an operand here, and nothing needs it to be: this sets a
   * draft flag, and the row that calls it renders only from the stored record's
   * own flags, so an unsaved host cannot reach it.
   */
  const forgetSshKey = () => setForgetKey(true);

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
      // dialled (a cancelled dialog must not leave a FOREIGN machine's
      // fingerprint on a record, because the next real connect aborts as a
      // MISMATCH and that reads as an attack). The gate was sound and
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
      // disposes of it. The question - does a pin survive Cancel, and should it -
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
    setKeyRefusal(null);
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    const port = Number.parseInt(shared.port, 10);
    setSaving(true);
    try {
      // Inspected HERE, before anything is built, rather than read off the
      // section's own panel: this reads both fields at the moment the record is
      // written, so there is no generation to compare and no way for a panel
      // describing an older (body, passphrase) pair to decide a save. The same
      // call, the same refusal and the same order as the vault key editor's own
      // save, with `encryptedKeyRefusal` IMPORTED rather than restated - a
      // second copy of that policy is how two surfaces come to disagree at the
      // next key-format finding, and this editor had no policy at all until
      // now.
      //
      // All four conjuncts are load-bearing, none is a belt: a vault-bound row
      // stores no key of its own (`secrets` is `{}` below) and can still hold a
      // body typed before the picker was pointed at an identity; a blank body
      // is the state `validateSshCredential` now deliberately lets through; and
      // the refusal renders inside the key field, which is mounted only under
      // key auth - raising it under password auth would be a Save that appears
      // to do nothing at all.
      //
      // Reached by: pick Private key, paste an encrypted key, leave the
      // passphrase blank, press Save. What the backend cannot read at all - a
      // public key, a DSA key, a SEC1 key, a wrong passphrase - is a rejection
      // rather than a refusal, and lands in the `catch` below with the
      // backend's own sentence.
      if (
        protocol === "ssh" &&
        !boundIdentity &&
        sshCred.authMode === "key" &&
        sshCred.privateKey.trim() !== ""
      ) {
        const info = await inspectSshKey(sshCred.privateKey, sshCred.keyPassphrase || undefined);
        const refusal = encryptedKeyRefusal(info.encrypted, sshCred.keyPassphrase);
        if (refusal) {
          // Not `setError`, and a RETURN rather than a warning: the sentence
          // names the field below this one, and a key stored without its
          // passphrase can never be used while nothing on the saved record
          // tells it apart from a key that has none.
          setKeyRefusal(refusal);
          return;
        }
      }
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
      // ANOTHER host reaches a save, and how the other protocol's fields ride
      // along on a record that has no business carrying them.
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
        // `forgetKey` is the fourth argument and an EXPLICIT one: it forces both
        // key fields to the store's clear whatever the touched and seeded records
        // say, because the field it is about is not rendered in the auth mode
        // that wants it gone and therefore cannot be touched. Faking it by
        // marking those two fields touched and seeded would break the invariant
        // that licenses every other clear - see `sshSecretsForSave`.
        secrets = boundIdentity
          ? {}
          : sshSecretsForSave(sshCred, sshTouched.current, sshSeeded.current, forgetKey);
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
        // Through `describeKeyError`, which strips a leading `ssh: ` and leaves
        // everything else alone - right for both sources this branch now has.
        // A rejected inspection carries that prefix and is rendered inside a
        // field already labelled as an SSH private key, where it is noise; a
        // store refusal ("hosts: ...") or a keychain error does not carry it
        // and is untouched. The message itself is never rewritten: every dead
        // end the backend classifies has its own sentence naming what to do
        // next, and paraphrasing one here would put a second copy of that
        // wording in the tree. Its return type is the whole `KeyInspectState`
        // union rather than the error arm alone, so the `kind` test below is a
        // narrowing the function itself never fails - not a branch this code
        // can reach.
        const described = describeKeyError(e);
        setError(described.kind === "error" ? described.message : String(e));
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
        if (fresh) {
          setExisting(fresh);
          // The one draft value this recovery does drop, and it has to: the arm
          // below re-seeds `authMode` from `fresh`, so a record that is now on
          // key auth would put the key textarea back on screen with the intent
          // still set - the second press of Save would then delete the body the
          // user is looking at, with the row that promised it nowhere in the
          // form. Dropped in the safe direction: nothing has been deleted, the
          // row renders again from `fresh`'s own flags with its button back, and
          // its note still says what pressing it does.
          setForgetKey(false);
          // The most common way this refusal is reached now is the
          // credential picker above, on ANOTHER open editor for the same host:
          // this form loaded a row BOUND to an identity, that binding was
          // detached in the meantime, and `boundIdentity` recomputes off
          // `fresh` and goes null the instant it does. A form that loaded a
          // bound row never had an editable user/username field to seed the
          // draft from - it was blank the whole time, under
          // `VaultBindingPanel` - so pressing Save again would write that
          // blank draft as the record's plain `user`/`authMode` (or
          // `username`/`domain`), silently overwriting the real values
          // `fresh` just copied from the identity. Re-seeding those two
          // fields from `fresh` closes it. The secret fields are written ""
          // alongside them rather than left as whatever the blank draft
          // already held, because nothing here has read them and a stale
          // value must not be implied as current.
          if (existing?.credential.kind !== "inline" && fresh.credential.kind === "inline") {
            if (isSshHost(fresh)) {
              const cred = fresh.credential;
              if (cred.kind === "inline") {
                setSshCred({
                  user: cred.user,
                  authMode: cred.authMode,
                  password: "",
                  privateKey: "",
                  keyPassphrase: "",
                });
              }
            } else if (isRdpHost(fresh)) {
              const cred = fresh.credential;
              if (cred.kind === "inline") {
                setRdpCred({ username: cred.username, domain: cred.domain ?? "", password: "" });
              }
            }
          }
        }
        setError(
          `${e.message} Your edits are still here, and the credential shown below is now the ` +
            `current one - review it and press Save again.`,
        );
      }
    } finally {
      setSaving(false);
    }
  };

  /** The identity name the convert confirmation opens with - editable there,
   *  never sent as-is when the field is left blank. */
  const defaultConvertName = () =>
    `${(sshCred.user || rdpCred.username).trim()}@${shared.host.trim()}`;

  /**
   * Ask, on the way into the convert confirmation, whether the vault already
   * holds the private key this convert would move in.
   *
   * WHY IT IS HERE AND NOT IN `applyCredentialChange`. Reuse hands the new
   * identity a `VaultKey` the user did not pick, whose name, description and
   * passphrase belong to an earlier import, and getting that wrong is silent -
   * the connect works, using someone else's record. So it is the user's
   * decision, and the confirmation is the only place to put it. That means the
   * lookup has to have happened before Confirm is pressed.
   *
   * IT DOES NOT GATE CONFIRM. An answer that has not arrived leaves the offer at
   * "checking" and `reuseExistingKey` at false, so the convert mints a new key -
   * today's behaviour, unchanged. Blocking the button on an inspection that may
   * fail would trade a correct-but-duplicated key for a stuck confirmation.
   *
   * THE BODY IS INSPECTED A SECOND TIME here; `applyCredentialChange` keeps its
   * own inspection for the facts it stores on a key it mints. Deliberately not
   * shared: this one runs before the user has answered and may be superseded or
   * discarded, while the facts written onto a new record have to come from the
   * body as it stands when the write happens.
   *
   * A BODY THE BACKEND CANNOT READ IS NOT AN ERROR. `vaultKeyFactsFrom` reports
   * no fingerprint for a container it could not open - a PuTTY or PKCS#8 key
   * whose passphrase has not been entered - and no fingerprint means no
   * candidate, never a failure. Same degradation as the `facts = {}` arm below,
   * for the same reason: a cosmetic lookup must not fail the convert.
   *
   * AND IT IS GATED THE WAY THE MINTED RECORD'S FACTS ARE, on the same two refs
   * and for the same reason: what a convert moves is the STORED account, so an
   * offer made over a body the user typed over the seed names a vault record
   * that has nothing to do with this host - and taking that offer copies
   * nothing while step 8 releases the host's own key. The gate USED TO BE
   * `protocol !== "ssh" || !sshCred.privateKey.trim()`, which is why that path
   * was reachable by pasting a second key the vault already held over the seeded
   * one. Neither ref says it alone: `sshSeeded` says the keychain read put a
   * value the user could SEE into the field, `sshTouched` says they have not
   * changed it since. Seeded alone accepts a body typed over the seed; untouched
   * alone accepts a field that is empty or stale only because the read has not
   * landed.
   *
   * A GATE THAT FAILS PUBLISHES NO OFFER, which is what an absent offer already
   * meant: the convert mints a new key with no facts on it, the honest answer
   * for a body this dialog cannot vouch for.
   */
  const offerKeyReuse = async () => {
    const generation = ++reuseGeneration.current;
    setReuseExistingKey(false);
    let candidate: { key: VaultKey; fingerprint: string } | null = null;
    if (
      protocol === "ssh" &&
      sshSeeded.current.privateKey &&
      !sshTouched.current.privateKey &&
      sshCred.privateKey.trim()
    ) {
      setReuseOffer({ kind: "checking" });
      try {
        const facts = vaultKeyFactsFrom(
          await inspectSshKey(sshCred.privateKey, sshCred.keyPassphrase || undefined),
        );
        const key = reusableVaultKey(await listKeys(), facts);
        // `facts.fingerprint` is what the match was made ON, so it is what the
        // offer carries. It is non-blank whenever `key` is non-null - a blank or
        // absent one matches nothing, on either side - and the second operand is
        // what tells the type checker so rather than a claim of its own.
        candidate = key && facts.fingerprint ? { key, fingerprint: facts.fingerprint } : null;
      } catch {
        candidate = null;
      }
    }
    if (reuseGeneration.current !== generation) return;
    setReuseOffer(
      candidate
        ? { kind: "candidate", key: candidate.key, fingerprint: candidate.fingerprint }
        : NO_REUSE_OFFER,
    );
  };

  /**
   * The credential picker's confirmed action: convert this host's own
   * credentials into a new identity, bind to an existing one, or detach back
   * to inline. One function, so there is exactly one call site for each of
   * `credentialMove.ts`'s three writes and exactly one place that refreshes
   * `existing` from what a write actually returned.
   *
   * `setExisting` is ALWAYS given the record the write returned, never one
   * built here. Without it, the very next Save in the same sitting would send
   * `credentialStamp(existing)` from BEFORE this action and be refused against
   * this editor's own write - `save()` itself is not touched by any of this, so
   * it is the only thing standing between a completed action and a refusal that
   * reads as this editor arguing with itself.
   *
   * `choice` is reset from the SAME record for the same reason: leaving it
   * would show the picker on a value the row no longer has.
   */
  const applyCredentialChange = async (change: CredentialChange) => {
    if (!existing) return;
    setPendingChange(null);
    setError(null);
    // Every arm here changes which accounts this host owns - convert moves them,
    // bind deletes them, detach copies an identity's secrets into fresh ones - so
    // a forget intent recorded before it names accounts that are no longer the
    // ones it was about. Detach is the one that would bite: it leaves the row
    // inline again with a private key just copied in, and a stale intent would
    // delete that copy on the next Save. Cleared before the write rather than
    // after it, so a write that fails drops the intent too: nothing has been
    // deleted, and the row is still on screen to be pressed again.
    setForgetKey(false);
    setChanging(true);
    try {
      if (change.kind === "convert") {
        // The offer the user chose to take, or null for "mint a new record".
        // Read from the offer rather than from the checkbox alone, so a ticked
        // box over an offer that has since been replaced cannot name a record
        // the user never saw. The whole offer and not its `key`, because the
        // fingerprint it matched on travels to the write with it.
        const reused = reuseExistingKey && reuseOffer.kind === "candidate" ? reuseOffer : null;
        // The metadata a newly minted `VaultKey` records, and it is inspected
        // ONLY from a body that is still the STORED one.
        //
        // WHAT TRAVELS IS THE STORED ACCOUNT. `convertHostToVault` copies from
        // the host's own keychain accounts, so a fingerprint, public half and
        // type read out of a body the user has edited would describe one key
        // while the record holds another. That record then hands the user a
        // copyable public key that will never open the server, anchors its own
        // change stamp on a false fingerprint, and offers itself for reuse to the
        // next host that really does hold the key it names - and reuse RELEASES
        // that host's own copy. All three fields are optional and the vault's key
        // card renders an unknown-type state for an absent one, so leaving them
        // off is honest where stamping them is not.
        //
        // BOTH REFS, and neither one says it alone. `sshSeeded` says the keychain
        // read put a value the user could SEE into the field; `sshTouched` says
        // whether they have changed it since. Seeded alone still accepts a body
        // typed over the seed; untouched alone accepts a field that is empty or
        // stale only because the read has not landed.
        //
        // The PASSPHRASE is deliberately not gated, and it is a different
        // question: a fingerprint is a hash of the public half, which
        // `ssh_key_inspect` reads out of the key body alone - an OpenSSH
        // container keeps it in cleartext even while sealed. A wrong passphrase
        // does not yield different facts, it yields a rejection, which the
        // `catch` below already degrades to no facts at all.
        //
        // Skipped entirely when a key is being reused: nothing is written to
        // that record, so there are no facts to put on it.
        let facts: VaultKeyFacts = {};
        if (
          !reused &&
          protocol === "ssh" &&
          sshSeeded.current.privateKey &&
          !sshTouched.current.privateKey &&
          sshCred.privateKey.trim()
        ) {
          try {
            facts = vaultKeyFactsFrom(
              await inspectSshKey(sshCred.privateKey, sshCred.keyPassphrase || undefined),
            );
          } catch {
            // Cosmetic only: the secret itself still travels by account move,
            // and a failed inspection must not fail the convert over it.
            facts = {};
          }
        }
        // No `authMode`: `convertHostToVault` derives it from the STORED record
        // instead of taking it from here. This dialog used to pass the draft's
        // radio, which could disagree with what the record actually holds - and
        // that disagreement produced two defects, one stranding a plaintext
        // password per press and one orphaning the host's only private key.
        // The four identity fields left are the ones the user may have
        // edited, and none of them carries an invariant against the accounts
        // being moved. `facts` is on the record's side of that same rule, which
        // is what the gate above enforces - it describes the material that
        // travels, so it may only be read from a body that IS that material.
        const result = await convertHostToVault({
          host: existing,
          identity: {
            name: convertName.trim() || defaultConvertName(),
            username: (sshCred.user || rdpCred.username).trim(),
            domain: protocol === "rdp" ? rdpCred.domain.trim() : "",
            description: "",
          },
          key:
            protocol !== "ssh"
              ? null
              : reused
                ? { reuseKeyId: reused.key.id, fingerprint: reused.fingerprint }
                : { name: `${shared.name.trim()} key`, facts },
        });
        setExisting(result.host);
        setChoice(currentCredentialChoice(result.host));
      } else if (change.kind === "bind") {
        const saved = await bindHostToIdentity({ host: existing, identityId: change.identityId });
        setExisting(saved);
        setChoice(currentCredentialChoice(saved));
      } else if (change.kind === "detach") {
        // No `identityRows` lookup any more: `detachHostFromVault` no longer
        // takes an `inline` argument to build, so there is nothing here left
        // to build it FROM. It derives the non-secret fields itself, from the
        // same identity it re-reads for the secrets - see its own doc for why
        // that removed a caller-vs-record disagreement rather than merely
        // guarding one.
        const result = await detachHostFromVault({ host: existing });
        // Non-secret fields only, seeded from what the write RETURNED - the
        // same rule this function's header states for `setExisting`, applied
        // one level down. `sshTouched`/`sshSeeded` deliberately stay as they
        // are - seeding them would license a later blank Save to clear the
        // secrets `detachHostFromVault` just copied (the rule
        // `sshSecretsForSave` in `editor/sshSecrets.ts` enforces).
        if (result.host.protocol === "ssh" && result.host.credential.kind === "inline") {
          setSshCred({
            user: result.host.credential.user,
            authMode: result.host.credential.authMode,
            password: "",
            privateKey: "",
            keyPassphrase: "",
          });
        } else if (result.host.protocol === "rdp" && result.host.credential.kind === "inline") {
          setRdpCred({
            username: result.host.credential.username,
            domain: result.host.credential.domain ?? "",
            password: "",
          });
        }
        setExisting(result.host);
        setChoice(currentCredentialChoice(result.host));
        if (result.warning) setError(result.warning);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setChanging(false);
    }
  };

  const protocolLabel = protocol === "ssh" ? "SSH" : "RDP";
  const busy = saving || !ready || changing;
  // The protocol is only known once the record has loaded, so until then the
  // title says less rather than naming the protocol of whatever row was open
  // before this one.
  const title = mode === "create" ? "New host" : ready ? `Edit ${protocolLabel} host` : "Edit host";

  // Radix keeps `AlertDialogContent` mounted for its ~100ms exit animation
  // (`VaultPage.tsx:197-216` found this first, over its own delete confirm), so
  // a body reading `pendingChange` directly would render an empty title and
  // description while the dialog fades out. `shownChange` is the same record,
  // held past the moment `pendingChange` clears, and exists ONLY to answer
  // "what does the dialog show" - `open` below and `applyCredentialChange`'s own
  // argument still key off `pendingChange` itself.
  const lastChangeRef = useRef<CredentialChange | null>(null);
  if (pendingChange) lastChangeRef.current = pendingChange;
  const shownChange = pendingChange ?? lastChangeRef.current ?? { kind: "none" as const };
  const shownIdentityName =
    shownChange.kind === "bind" || shownChange.kind === "detach"
      ? identityRows.find((row) => row.identity.id === shownChange.identityId)?.identity.name
      : undefined;
  const shownOwnedSecrets = existing ? hostOwnedSecretNames(existing) : [];

  return (
    <>
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
            {!ready && !error ? (
              <p className="text-muted-foreground text-[11px]">Loading…</p>
            ) : null}
            {ready ? (
              <>
                <Field label="Protocol">
                  {mode === "create" ? (
                    <div className="flex gap-1">
                      <ToggleButton
                        active={protocol === "ssh"}
                        onClick={() => changeProtocol("ssh")}
                      >
                        SSH
                      </ToggleButton>
                      <ToggleButton
                        active={protocol === "rdp"}
                        onClick={() => changeProtocol("rdp")}
                      >
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

                {/* Renders in BOTH modes - only the options differ,
                  not the picker's presence. `credentialOptions` already omits
                  `CREDENTIAL_CHOICE_NEW_IDENTITY` outside edit mode, and
                  `credentialChangeFor` already answers `{kind:"none"}` for
                  every create-mode choice, so the description and button below
                  need no mode test of their own. */}
                <Field label="Credential">
                  <Combobox
                    options={credentialOptions}
                    value={choice}
                    onChange={setChoice}
                    searchPlaceholder="Search identities…"
                    emptyLabel="No identities found."
                  />
                  {credentialChange.kind !== "none" ? (
                    <div className="border-border/60 bg-muted/30 flex items-center justify-between gap-2 rounded-md border px-2 py-1.5">
                      <span className="text-muted-foreground text-[10.5px]">
                        {credentialChangeTitle(credentialChange)}
                      </span>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 shrink-0 px-2 text-[11px]"
                        disabled={changing}
                        onClick={() => {
                          if (credentialChange.kind === "convert") {
                            setConvertName(defaultConvertName());
                            void offerKeyReuse();
                          }
                          setPendingChange(credentialChange);
                        }}
                      >
                        Change credential
                      </Button>
                    </div>
                  ) : null}
                </Field>

                {protocol === "ssh" ? (
                  <SshCredentialSection
                    boundIdentity={boundIdentity}
                    identityName={boundIdentityName}
                    value={sshCred}
                    onChange={patchSshCred}
                    hasStoredPassword={hasStoredSshPassword}
                    hasStoredPrivateKey={hasStoredSshPrivateKey}
                    keyRefusal={keyRefusal}
                    forgettableKeySecrets={forgettableKeySecrets}
                    forgetKey={forgetKey}
                    onForgetKey={forgetSshKey}
                  />
                ) : (
                  <RdpCredentialSection
                    boundIdentity={boundIdentity}
                    identityName={boundIdentityName}
                    value={rdpCred}
                    onChange={(patch) => setRdpCred((d) => ({ ...d, ...patch }))}
                    hasStoredPassword={hasStoredRdpPassword}
                  />
                )}

                {protocol === "ssh" ? (
                  <SshOptions
                    hosts={sshHosts}
                    proxyJumpId={proxyJumpId}
                    onChange={setProxyJumpId}
                  />
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
                    label={
                      protocol === "ssh" ? "Recorded server key" : "Recorded server certificate"
                    }
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

      <AlertDialog
        open={pendingChange !== null}
        onOpenChange={(open) => {
          if (!open) setPendingChange(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{credentialChangeTitle(shownChange)}</AlertDialogTitle>
            <AlertDialogDescription>
              {credentialChangeNote(shownChange, shownIdentityName, shownOwnedSecrets)}
            </AlertDialogDescription>
          </AlertDialogHeader>
          {/* `shownChange`, never `pendingChange`: Radix keeps this content
            mounted through its exit animation, and a body reading the cleared
            value renders blank while the dialog fades. */}
          {shownChange.kind === "convert" ? (
            <div className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <label htmlFor="convert-identity-name" className="text-[11px] font-medium">
                  Identity name
                </label>
                <Input
                  id="convert-identity-name"
                  value={convertName}
                  onChange={(e) => setConvertName(e.target.value)}
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
              </div>
              {reuseOffer.kind === "checking" ? (
                <span className="text-muted-foreground text-[10.5px]">
                  Checking whether the vault already holds this key…
                </span>
              ) : reuseOffer.kind === "candidate" ? (
                <div className="flex flex-col gap-1">
                  <label className="flex items-start gap-2 text-[11px]">
                    <Checkbox
                      checked={reuseExistingKey}
                      onCheckedChange={(checked) => setReuseExistingKey(checked === true)}
                      className="mt-0.5"
                    />
                    <span>
                      {`The vault already holds this private key as "${reuseOffer.key.name}" — use that record instead of adding a second one.`}
                    </span>
                  </label>
                  <span className="text-muted-foreground text-[10.5px]">
                    {reuseExistingKey
                      ? `The new identity points at "${reuseOffer.key.name}" exactly as it stands: its name, its description and its passphrase are left alone, and nothing from this host is written onto it. The fingerprints match, so the key body is the same one — but a re-encrypted copy of one key can carry a different passphrase, and writing this host's over it would stop every other identity using that record from opening it. This host's own key and key passphrase are released once the move succeeds, and the vault still holds the key itself.`
                      : `Left unticked, a second record is created holding another copy of the same private key, with the name and passphrase this host has now.`}
                  </span>
                </div>
              ) : null}
            </div>
          ) : null}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={changing}
              onClick={() => {
                if (pendingChange) void applyCredentialChange(pendingChange);
              }}
            >
              {changing ? "Working…" : "Confirm"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
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
