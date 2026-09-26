# Known limits

Accepted limits: weighed and kept on purpose, or deferred until a named
trigger. One entry each: what, where (file and symbol), and what would
change it. Code that carries a limit points back here; retire the entry in
the same change that lifts it.

## Not supported

- **RDP**: audio, device and drive redirection, files over the clipboard,
  RD Gateway, Kerberos (NTLM only), multi-monitor, `.rdp` import, 9+
  sessions. `src-tauri/src/modules/rdp/mod.rs` (module docs,
  `MAX_RDP_SESSIONS`), `session.rs` (`NoNetworkClient`).
- **SFTP**: download to local disk, folder upload, opening files over
  16 MiB or not UTF-8, uploads over 256 MiB.
  `src-tauri/src/modules/ssh/sftp.rs` (`MAX_SFTP_READ_BYTES`,
  `MAX_UPLOAD_BYTES`).
- **SSH**: `ssh-rsa` (SHA-1) host keys. `src-tauri/src/modules/ssh/session.rs`
  (`HOST_KEY_ALGOS`).
- **Forwards**: binding `-L` or `-D` to anything but `127.0.0.1`; SOCKS5
  auth or anything but CONNECT. `src-tauri/src/modules/ssh/session.rs`
  (`open_forward`, `open_socks`).
- **Import**: `ssh_config` stanzas using `ProxyCommand`, `Include`, `Match`
  or wildcard `Host`; PuTTY sessions with a proxy or a non-SSH protocol.
  `src/modules/backup/sshConfigImport.ts`, `puttyRegImport.ts`.

## SSH sessions

- **Shared session hits OpenSSH's `MaxSessions` cap.** Every tab shares one
  channel-bearing session per host; past OpenSSH's default `MaxSessions`
  (10) the next tab's channel open fails and retries (unverified against a
  real server at the limit). `src/modules/ssh/tunnel.ts`
  (`openShellForConnection`). Changes when: a user hits the limit.
- **A host edit reaches its terminals only once the old session releases.**
  New tabs join the host's live session dialled at open time; pre-flight
  can show a new endpoint while the shell still rides the old one until
  every reference lets go. `src/modules/ssh/tunnel.ts` (`sessionFor`).
  Changes when: a report of an edit not applying.

## Forwards

- **`-R`/`-D` rules do not autostart with their host.** `startWithHost`
  only dials a `-L` shape; `-R` needs a server bind and `-D` a SOCKS5
  listener, so both are skipped with a banner (still startable from Port
  Forwarding). `src/modules/forwards/autostart.ts` (`startHostForwards`).
  Changes when: `AutostartDeps` gains a second dial shape.
- **`RuntimeDeps` cannot drive a `-R`/`-D` Start or Stop through a fake.**
  `-L` goes through fakeable `RuntimeDeps.openForward`/`closeForward`;
  `-R`/`-D` call `ssh/tunnel.ts` directly, needing a real Tauri bridge to
  test. `src/modules/forwards/controller.ts` (`startTypedRule`). Changes
  when: `RuntimeDeps` gains matching keys.
- **A `-R` rule's routing registry is keyed by port alone.**
  `remote_forwards` maps a bound server port to its target, dropping the
  bind address; sound while a server binds one port only once.
  `src-tauri/src/modules/ssh/session.rs` (`RemoteForwardTargets`). Changes
  when: one port binds on two addresses in a session.
- **A `startWithApp` rule's mid-session drop does not re-enter the backoff
  ladder.** The ladder covers only the initial bind and its retries;
  `dropSession` has no subscriber, so a post-bind drop leaves the rule
  stale-"Running" until a manual Stop/Start. `src/modules/ssh/tunnel.ts`
  (`dropSession`). Changes when: `tunnel.ts` gains a drop subscription.
- **A remote edit landing mid-retry re-dials the OLD endpoints.**
  `attemptForwardAutostart` reuses the same rule object across backoff
  rungs; a sync landing that only rewrites (not deletes) the record never
  cancels a pending wait. `src/modules/forwards/controller.ts`
  (`attemptForwardAutostart`). Changes when: landing-side release grows a
  rewrite case.
- **A local forward-bind conflict walks the ladder before parking.**
  `ssh_forward_open`/`ssh_remote_forward_open`/`ssh_socks_open` reject
  with a bare `String`, so a bind conflict and a dead session are
  indistinguishable; the ladder runs all 5 retries either way.
  `src/modules/forwards/controller.ts` (`attemptForwardAutostart`).
  Changes when: those commands gain a structured error like
  `SshConnectError`.

## RDP

- **EGFX/H.264 is unreachable from the pinned connector.** Painting stays
  RemoteFX/raw-bitmap; the pinned `ironrdp-connector` (`=0.9.0`) never
  sets the graphics-pipeline capability bit and exposes no field to.
  `src-tauri/src/modules/rdp/session.rs` (`build_config`),
  `src-tauri/Cargo.toml`. Changes when: a published connector exposes the
  field AND the russh/picky pin conflict resolves.
- **A panic in an RDP session kills the app.** The session task has no
  `catch_unwind` boundary, and it would not help anyway: the release
  profile sets `panic = "abort"`, leaving nothing to unwind.
  `src-tauri/src/modules/rdp/session.rs` (`connect`),
  `src-tauri/Cargo.toml`. Changes when: the release profile accepts
  unwinding tables.
- **A copy made without leaving the RDP pane is never advertised.** Host
  clipboard is read only on pane focus edge, so a write made while focus
  stays is picked up only at the next edge. `src/modules/rdp/RdpPane.tsx`,
  `src-tauri/src/modules/rdp/session.rs` (`RdpSession::clipboard_focus`).
  Changes when: a native clipboard-change listener exists.
- **A remote-to-host paste is one round trip behind.** Remote clipboard is
  fetched on blur, so pasting in the same window right after gets the
  previous content. `src-tauri/src/modules/rdp/session.rs`
  (`RdpSession::clipboard_focus`). Changes when: a report of a stale
  paste in ordinary use.
- **A large clipboard transfer head-of-line blocks the RDP graphics
  path.** The outbound frame is one `write_all` on the same task that
  serves frames, up to `MAX_CLIPBOARD_BYTES` (32 MiB); the desktop stalls
  during a large copy. `src-tauri/src/modules/rdp/session.rs` (`run`,
  `Wake::Clipboard`). Changes when: a measured stall matters.
- **The connector's `Credentials` holds the RDP password unscrubbed.**
  `Credentials::UsernamePassword.password` is a plain `String`;
  `build_config` copies it in and it is dropped unscrubbed, unlike the
  rest of the chain. `src-tauri/src/modules/rdp/session.rs`
  (`build_config`). Changes when: `ironrdp-connector` ships a zeroizing
  password type.

## Known Hosts

- **The Known Hosts Forget button has no "every device" option.** It
  revokes a pin on this device only; `DEVICE_LOCAL_FIELDS` already strips
  `pins` from every synced record, so there is nothing else to revoke.
  `src/modules/hosts/KnownHostsPage.tsx`, `src/modules/sync/envelope.ts` /
  `src-tauri/src/modules/sync/model.rs`. Changes when: pins become synced
  content.
- **No check mounts `KnownHostsPage`, so its Forget wiring is
  source-pinned only.** `forgetPin` and the page's rail-view wiring are
  proven separately; no check renders the button, labels, or empty state.
  `src/modules/hosts/KnownHostsPage.tsx`. Changes when: a component test
  runner can mount a rail view.

## Host groups

- **A group's name is unique across the whole tree, not per-parent.**
  `sameName` compares an incoming name against every other group
  regardless of nesting. Nesting gave no reason to scope it: the host
  editor's group picker lists groups by flat name, so same-named siblings
  would be indistinguishable there anyway. `src/modules/hosts/store.ts`
  (`sameName`, `upsertGroup`). Changes when: a request for same-named
  siblings under different parents, which also needs the picker to show
  a parent path.
- **A reparent or rename on two devices resolves last-write-wins, blind
  to the other record it changed.** `merge` treats `parentId` as opaque
  and cannot see it names another group, so a merge can land a cycle;
  `buildGroupTree` resolves any dangling/cyclic `parentId` to root at
  read time. `src/modules/hosts/groupTree.ts` (`buildGroupTree`),
  `src/modules/hosts/store.ts` (`applyRemote`). Changes when: `merge`
  gains cross-record awareness.
- **Importing a pre-nesting backup moves every group it names back to
  root.** A pre-`parentId` backup's rows are indistinguishable from
  ordinary root groups, so import flattens nesting and clears any live
  `defaultIdentityId` the same way. `src/modules/backup/file.ts`
  (`orderGroupWrites`, `mergeGroups`). Changes when: the backup format
  can record "not written by this build".

## Host tags

- **A tag has no managed record, so renaming or deleting one everywhere
  is not one action.** `HostBase.tags` is free-form strings per host;
  there is no `HostTag` record, so a retype or delete never reaches
  another host wearing the same tag. `src/modules/hosts/types.ts`
  (`HostBase.tags`, `normalizeHostTags`). Changes when: a request for a
  managed, rename/delete-everywhere tag list.

## Backup and import

- **The import dialog's busy gate is source-pinned, never exercised.** No
  check mounts a component, so nothing asserts Escape/Cancel does nothing
  mid-write, or that `ImportSummary.problems` actually renders.
  `scripts/backup-verify.ts` (`[dialog source]`), `BackupDialog`. Changes
  when: a component test runner can mount the dialog mid-write.
- **One defensive guard in `summarize` cannot be mutated.** Widening the
  guard attaching a per-protocol split to the last host clause changes no
  output and reddens no check (measured); recorded as a limit, not
  coverage. `src/modules/backup/summary.ts` (`summarize`). Changes when:
  the split gains a second attachment point.
- **Termius import is not offered.** Host import supports
  `~/.ssh/config` and PuTTY only; Termius's export format is unverified
  since no real sample was obtainable.
  `src/modules/hosts/page/HostsBackupActions.tsx` ("Import from..." menu).
  Changes when: a real Termius export sample becomes available.
- **An `ssh_config`/PuTTY import is not idempotent across repeat runs.**
  Unlike a `.tervia-backup` row's stable id, an `ssh_config`/`.reg` row
  mints a fresh id every parse, so re-importing duplicates every record.
  `src/modules/backup/foreignImport.ts` (`previewSshConfigImport`,
  `previewPuttyImport`). Changes when: a user reports repeat-import
  duplication as a real problem.
- **The line-range file reader still refuses a BOM'd UTF-16 file
  `fs_read_file` now decodes.** `classify_bytes` gained a BOM-aware
  decode; the line-range reader's own null-byte sniff has no BOM check
  and streams assuming UTF-8. `src-tauri/src/modules/fs/file.rs`
  (`fs_read_file_portion_inner`, `classify_bytes`). Changes when: a
  request to open a UTF-16 file slice through the line-range reader.

## Cross-device sync

- **Sync's on/off switch is enforced in TypeScript only.** "Sync off
  means no network" is checked before `sync_pull`/`sync_push` are called,
  never inside them. `src/modules/sync/scheduler.ts` (`runPull`,
  `runPush`, `config.enabled`). Changes when: a second caller of those
  commands appears outside `scheduler.ts`.
- **A retired device's published tombstones are never pruned.** The
  prune removes a remote tombstone only when THIS device published it, so
  a wiped or reinstalled device's tombstones stay forever (small,
  harmless). `src-tauri/src/modules/sync/engine.rs` (`pull`,
  `envelope.device == device`). Changes when: a device registry exists.
- **A legacy PEM key keeps a dropped fingerprint until next opened.**
  `merge` drops a stripped key's fingerprint; apply restores it by
  inspecting the body, but a legacy PEM/PuTTY body only answers
  "encrypted" without its passphrase. `src/modules/sync/scheduler.ts`
  (`rederive`), `src/modules/vault/keyInspect.ts` (`vaultKeyFactsFrom`).
  Changes when: a passphrase cache exists.
- **Stripping key bodies from the remote only holds once every device
  stops carrying them.** `merge` never merges the secrets component, so a
  device still holding a body republishes it on its next reconcile; the
  purge is per-fleet wearing a per-device button.
  `src-tauri/src/modules/sync/engine.rs` (`purge_secrets`). Changes when:
  a device registry exists.
- **Deleting a key body on one device does not stick while another still
  holds it.** `hasPrivateKey` travels as a record field; a device still
  holding the body corrects the flag back to `true` on landing, so the
  clearing device's record then fails to connect with a "missing secret"
  message. `src/modules/sync/scheduler.ts` (`rederive`),
  `src-tauri/src/modules/sync/model.rs` (`DEVICE_LOCAL_FIELDS`). Changes
  when: `hasPrivateKey` becomes per-device.
- **Two devices configuring one empty prefix at once can strand a root
  key.** `sync_configure` writes a fresh root key unconditionally when
  none exists; a race between two devices lets the second overwrite the
  first. `src-tauri/src/modules/sync/engine.rs` (`sync_configure`).
  Changes when: a create-if-absent verb exists on `SyncProvider`.

## Tombstones and record stamps

- **A device offline longer than 90 days can resurrect a deleted
  record.** A tombstone drops at 90 days; a device unsynced that long
  never saw it and republishes the record on its next push. An expired
  remote tombstone is skipped, and an untouched local record past the
  window is reported as stale, not deleted. Deliberate exception: an empty
  remote listing lifts the stale rule and publishes everything (a fresh
  prefix never held the records), so a remote whose deletes have all
  expired gets refilled. `src/lib/tombstones.ts` (`TOMBSTONE_TTL_MS`),
  `src-tauri/src/modules/sync/engine.rs` (`pull`, `remote_is_empty`).
  Changes when: a device registry can say when each device last pulled.
- **A mistyped WebDAV prefix presents as a fresh remote and takes a copy
  of the inventory.** A 404 maps to an empty listing (needed for a
  genuinely fresh prefix), so a wrong-but-answering prefix looks fresh
  and receives the whole inventory under a new keyfile.
  `src-tauri/src/modules/sync/providers/webdav.rs` (`classify_list`).
  Changes when: settings gains a confirmation before minting a keyfile.
- **Expired tombstone bytes are never reclaimed in a store with no
  further deletes.** Pruning is filter-on-read plus prune-on-write only;
  nothing prunes at load time. `src/lib/tombstones.ts`
  (`livingTombstones`). Changes when: any store gains a load-time
  maintenance pass.
- **A landed record can sit with a reference that has not arrived yet.**
  `applyRemote` accepts a landing naming a record this device lacks
  rather than refusing it, since refusing would lose every other landing
  in the same queued write. `src/lib/tombstones.ts` (`landingRefusal`),
  `src/modules/hosts/store.ts` (`assertReferences`). Changes when: a
  dangling reference is neither visible nor recoverable.
- **A landed delete runs none of the in-use refusals a local delete
  runs.** `applyRemote` drops the record and releases its keychain
  accounts unconditionally; the released secret cannot be put back.
  Accepted because refusing is worse: the record stays alive locally, gets
  pushed, and the delete resurrects on every device.
  `src/modules/hosts/store.ts` (`applyRemote`),
  `src/modules/vault/refs.ts` (`identitiesUsingKey`). Changes when: a
  report of a secret lost this way, or a pull can hold a landing without
  republishing it.
- **A landed edit does not restart the forward it is running.** A landed
  DELETE releases the running forward before the apply; a landed EDIT
  rewrites the rule while its old forward keeps running.
  `src/modules/forwards/store.ts` (`applyRemote`),
  `src/modules/sync/scheduler.ts` (`release`). Changes when: a report of
  a rule whose row and running forward disagree.
- **A vault record's last-connected stamp is not restored by backup
  import, and a forward-only tunnel sets none.** Import drops
  `lastConnectedAt`; a forward-only tunnel (including under RDP) stamps
  neither its bastion nor identity. `src/modules/vault/store.ts`
  (`markIdentityConnected`), `src/modules/hosts/store.ts`
  (`markConnected`). Changes when: a forward counts as a use of its
  bastion.

## Store files and recovery

- **The `.bak` snapshot protects against a torn file, never a save that
  wrote the wrong thing.** Any valid JSON object reads `"ok"`, so a bug
  persisting a valid-but-wrong value overwrites the last good snapshot
  too. No shape check belongs at this layer: each store owns its own
  integrity rules, and a sync pull goes through the store's `applyRemote`
  like any other write. `src/lib/recoveredStore.ts` (`commit`),
  `src/lib/storeRecovery.ts` (`inspect`). Changes when: a store gains a
  shape check cheap enough to run before snapshotting.
- **An atomic store write is durable against a crash, not power loss
  right after the rename.** `write_staged` never fsyncs the parent
  directory, so a cut in that window can leave the target naming its
  previous contents. `src-tauri/src/modules/fs/atomic.rs`
  (`write_staged`). Changes when: a store's loss of one committed write
  is unacceptable.
- **A restore rolls the file back and leaves the keychain where it is.**
  Recovery replaces a store file with its older snapshot; nothing
  reconciles it against the current keychain, and the recovery toast
  states the divergence without checking anything.
  `src/lib/storeRecovery.ts` (`recover`),
  `src/app/lib/recoveryNotices.ts` (`recoveryToast`). Changes when: a
  report of a host offering a key it no longer holds.
- **A store file this app cannot read is inert until it can.**
  `fs_read_file` refuses an oversized or unopenable file; the recovery
  pass leaves it alone rather than restoring a snapshot, so the store
  loads empty until the condition clears. Same for an unreadable `.bak`:
  it is never replaced. `src/lib/fileKeyValueStore.ts`
  (`createFileKeyValueStore`, `refused`), `src/lib/storeRecovery.ts`
  (`tauriStoreFileIo.read`). Changes when: a store legitimately grows
  past the size limit.

## Keychain and secrets

- **The orphan sweep cannot see a legacy Windows credential, and on
  macOS it can see another install's.** Windows lists the DPAPI store
  only; macOS addresses the shared login keychain by a bare service
  string, so a dev build's sweep can offer to delete a release install's
  accounts (confirm dialog is the only safeguard).
  `src-tauri/src/modules/secrets.rs` (`secrets_list`,
  `keychain_accounts`). Changes when: a report of either case happening.
- **A preference write costs a whole-file replacement.**
  `tervia-settings.json` lost its 200 ms autosave debounce when it moved
  to `createRecoveredStore`; a held zoom shortcut can move megabytes per
  keypress. `src/modules/settings/store.ts` (`writePref`). Changes when:
  a measured stall while dragging a slider or holding a shortcut.
- **Clearing the key textarea removes the key body and strands its
  passphrase.** Saving an emptied body deletes that account but leaves
  the passphrase field, and its account, untouched; the row that could
  clean it up only renders in auth modes with no key field.
  `src/modules/hosts/editor/sshSecrets.ts` (`sshSecretsForSave`),
  `src/modules/hosts/editor/SshCredentialSection.tsx` (`ForgetKeyRow`).
  Changes when: a user report of a stranded passphrase.

## Vault keys

- **A `hardware`-kind key is proven through a throwaway ssh-agent, never
  a real FIDO2 token.** No hardware token exists in the test environment,
  so a physical touch prompt and CTAP-specific errors are unexercised.
  `src-tauri/src/modules/ssh/session.rs`
  (`hardware_kind_authenticates_only_through_the_matching_agent_identity`).
  Changes when: a FIDO2 token becomes available in the test environment.
- **A build without the hardware exemption still strips a hardware
  key's fingerprint during cross-version sync.** `merge` exempts
  `kind: "hardware"` from the fingerprint-drop rule; a device on an
  older build without it still strips and republishes the loss.
  `src-tauri/src/modules/sync/model.rs` (`merge`). Changes when: every
  device in the sync group runs a build with the exemption.
- **RSA certificates are unverified against a live OpenSSH server.**
  Unverified. A parsed RSA certificate maps to
  `ssh-rsa-cert-v01@openssh.com`, refused by OpenSSH 8.8+ default config,
  but the e2e cert test only exercises Ed25519.
  `src-tauri/src/modules/ssh/session.rs` (`authenticate_hop`). Changes
  when: a user reports a refused RSA certificate.
- **An older build editing a cert or hardware key silently rebuilds it
  as a plain PEM key.** An older build's draft type has no
  `kind`/`certificate` fields, so saving there silently strips them with
  no refusal. `src/modules/vault/editor/draft.ts` (`keyRecordFrom`,
  `keyDraftFrom`). Changes when: every device in the sync group runs a
  build that knows `kind`/`certificate`.

## Credential moves (hosts and vault)

- **Convert reads no keychain, so a key rotated in place mid-edit is
  mis-described on the mint path and lost on the reuse path.**
  `convertHostToVault` stamps the minted record from facts the caller
  already inspected and never re-reads the keychain, so it cannot see the
  account rotate under an open editor. `src/modules/hosts/credentialMove.ts`
  (`reusableVaultKey`). Changes when: the convert path can read the
  keychain without an OS access prompt.

## Vault editors

- **Nothing pins where a vault editor's message renders.** Deleting the
  JSX that renders a message leaves the vault verify scripts green; only
  `tsc`'s `noUnusedLocals` catches it, and only when a binding is
  stranded. `src/modules/vault/editor/KeyEditorDialog.tsx`,
  `IdentityEditorDialog.tsx`. Changes when: a component test runner can
  mount a dialog and assert on rendered text.

## Workspaces

- **A workspace file still names a leaf's host `sshConnectionId`.** In
  memory the field is `hostId`; on disk it stays the older key, mapped on
  every save/restore to avoid stranding every earlier workspace file.
  `src/modules/workspaces/store.ts` (`SavedTerminalLeaf`),
  `src/modules/workspaces/serialize.ts` (`leafToSaved`, `savedToNode`).
  Changes when: a workspace-file migration pass lands for some other
  reason.

## Shared UI

- **A shared row/box layout is duplicated between the SSH credential
  section and the host editor, and only one copy is checked.**
  `ForgetKeyRow` and `PinnedKeyRow` hand-roll the same card shape; only
  `ForgetKeyRow` is pinned by a verify script.
  `src/modules/hosts/editor/SshCredentialSection.tsx` (`ForgetKeyRow`),
  `src/modules/hosts/HostEditorDialog.tsx` (`PinnedKeyRow`).
  Changes when: a third card needs the same shape.
- **The command palette's `#` mode finds a saved host but cannot create
  one, and no check sees how it builds its rows.** `#` ranks saved hosts
  via `rankHosts`/`searchRows` but offers no ad-hoc create path on a
  miss, and no component check mounts it.
  `src/modules/commandPalette/CommandPalette.tsx` (`HostResults`,
  `rankedHosts`). Changes when: a request for the header's create path
  from the palette.

## Verify suite

- **Exact-text anchors in verify scripts do not survive a reformat.**
  Some `scripts/*-verify.ts` checks pin exact substrings rather than a
  structural check, so a Prettier reformat can break the pin though the
  guarded code is unchanged; dormant while `printWidth` is fixed. Accepted
  as a class: a check that reddens on correct code gets weakened by whoever
  hits it first, which is worse than no check. Measured, not estimated: set
  `printWidth` to 60 in a copy of the tree, run `pnpm format` then
  `pnpm verify`, and 69 checks fail across nine scripts
  (`host-editor-verify` 26, `key-inspect-verify` 10, seven others 33);
  widening to 120 instead costs four. Re-measure before sizing a job.
  Changes when: this repo's `printWidth` changes, or a Prettier major
  rewraps calls or template literals.
- **Thirty-nine positive checks still read raw source, where a comment
  can satisfy them.** A check for text present is satisfied by a leftover
  `// was: ...` comment; nineteen were converted to read the AST,
  thirty-nine remain across ten scripts. `scripts/lib/ast.ts`
  (`namedImportsFrom`, `callsFunction`, `importSpecifiersOf`). Changes
  when: a check in this class is observed passing over a deletion.
- **A utility class can hide a field that every reachability check calls
  visible.** The identity editor's Password-field check covers four
  hiding paths but not a utility class name on `className`, since that
  vocabulary is open-ended. `scripts/vault-editor-verify.ts` (section
  11), `scripts/lib/ast.ts` (`expressionReachesName`). Changes when: a
  rendered-DOM harness exists.
- **Thirty-eight partial file spellings in comments are counted, not
  resolved.** A comment citing a file by an ambiguous spelling is bounded
  by a ratchet count rather than a per-site failure, since every spelling
  does name a file that exists. `scripts/citation-format-verify.ts`
  (`PARTIAL_PATH_CEILING`). Changes when: a spelling is found to have
  sent a reader to the wrong candidate.
