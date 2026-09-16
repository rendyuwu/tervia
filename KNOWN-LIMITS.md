# KNOWN-LIMITS.md

A place for an accepted state to live where a clone of this repository can
reach it. Some behaviours here are not defects: they were weighed and kept on
purpose. Some are deferrals whose trigger has not fired yet. Either way, a
planning document outside this repository is not a place a contributor with
just the clone can go - so it does not belong there, and it goes here instead.
A source comment may cite this file by name.

**An entry is three things and no more:**

1. **What is accepted** - the state, in plain terms.
2. **Which file and symbol carries it** - so a reader can go and look.
3. **The trigger that would change the answer** - a named condition, not
   "later".

No row ids from a planning document, no section number of a document that is
not in this repository, no dates, no commit hashes, no `/tmp` paths. Citing
one here would put the exact problem this file exists to remove back inside
its own solution.

Group entries under a `##` heading by area. Add new ones at the end of their
group.

## Vault editors

### The vault editors refuse a moved record and offer no recovery

**Accepted state.** When another window has changed a key or identity
underneath an open `KeyEditorDialog`/`IdentityEditorDialog`, the save is
refused and the user is told to close and reopen the editor; anything already
typed has to be entered again. This is deliberately different from the host
editor, which refreshes its stored record on the equivalent refusal and lets
the user press Save a second time.

**Carried by.** The `VaultRecordChangedError` branch of `save`'s catch arm in
`KeyEditorDialog.tsx` and in `IdentityEditorDialog.tsx`. The asymmetry with
the host editor traces to what each comparison actually answers:
`credentialStamp` (`hosts/types.ts`) answers whether a host's credential
_binding_ moved, which a refresh can safely re-seed a stale form against;
`vaultKeyStamp` and `vaultIdentityStamp` (`vault/types.ts`) answer whether the
_secret material itself_ moved. Refreshing there would hand the stale form a
record whose next Save writes the user's draft over a body or a password
another window just stored - the very thing the stamp fired to refuse.

**Trigger.** A user report of the retyping cost. That trigger used to wait on
how often two windows of this app edit one record at the same moment, which is
rare; it no longer does. `applyRemote` in `src/modules/vault/store.ts` lands
another DEVICE's records into the same store, so a key or an identity can move
underneath an open editor with nothing on this machine having touched it. Or a
vault editor gaining a field whose content exists nowhere but the form - a key
the dialog generates rather than one picked from a file is the case, and
neither editor has one today: the key body comes from a file that is still on
disk, and everything else is typed.

### Nothing pins where a vault editor's message renders

**Accepted state.** Deleting the JSX that renders a message computed by
`KeyEditorDialog.tsx` or `IdentityEditorDialog.tsx` leaves the vault verify
scripts green. Only `tsc`'s `noUnusedLocals` catches it, and only when the
deletion strands a binding that had exactly one other reader - a render moved
behind a second reader, or routed through a helper `tsc` cannot see the single
use through, passes every gate in the suite.

**Carried by.** No file - this is an absence. The vault editors' own verify
script checks that a message is computed correctly and that its wording holds
a property; it does not check that the rendered tree ever shows it.

**Trigger.** A component test runner existing in this repository (one able to
mount a dialog and assert on rendered text).

## Credential moves (hosts and vault)

### Convert reads no keychain, so a key rotated in place mid-edit is mis-described on the mint path and lost on the reuse path

**Accepted state.** `convertHostToVault` copies the host's stored
private-key account onto the record it mints and stamps that record with the
`facts` its caller inspected. It reads no secret of its own, so it cannot
compare the two. The caller's inspection is gated - `HostEditorDialog.tsx`'s
`applyCredentialChange` for the facts it stamps, `offerKeyReuse` for the offer
it makes - on the key body on screen being the one the keychain read put there
and not having been edited since. What that gate cannot see is the stored
account changing under it: a second window, or another process, rotating this
host's private key in place between the editor opening and the convert. The
seed read key A; the account now holds key B.

The two arms then pay differently. On the mint arm, `copyMoves` writes B onto
a record stamped with A's fingerprint, public half and type - a record that
describes one key while holding another, whose copyable public half will never
open the server, and which `reusableVaultKey` will offer to the next host that
genuinely holds A. On the reuse arm it costs more: the offer and the write both
match honestly on A, nothing is copied, and the host write releases an account
holding B, which existed nowhere else.

Nothing on the host record detects either - `hasPrivateKey` stays true through
an in-place rotation - so only a second keychain read could, and the convert
path deliberately takes none: `secrets_get` can stop on an OS access prompt on
macOS, and a read at confirm time would put one in front of a user who has
already answered.

**Carried by.** `scripts/credential-move-verify.ts` group `[10e]` measures what
a mis-described record costs and names this as what its two producer gates and
its own belt leave open. `credentialMove.ts`'s `reusableVaultKey` and
pre-check 4 each state what they do and do not assert.

**Trigger.** A keychain read the convert path can make without an OS access
prompt, or any change that lets this app notice a host's stored secret changing
underneath an open editor.

## Verify suite

### Exact-text anchors in verify scripts do not survive a reformat

**Accepted state.** A number of the checks under `scripts/*-verify.ts` are
line-shaped: an exact substring or an exact-argument text compare rather than
a structural (compiler API) check, and Prettier deciding to wrap a call
differently, or a `printWidth` change, breaks the pin even though the code it
guards is unchanged. The actual risk is the class, not any one location: a
check that reddens on correct code gets weakened by whichever contributor
hits it first, which is a worse outcome than the check never existing.
Dormant today because this repository's Prettier `printWidth` is fixed.
Rewriting them now, before anything forces the question, buys nothing.

Sixty-nine checks across nine of the fifty-eight scripts, measured rather
than estimated: set `printWidth` to 60 in a COPY of this tree, run
`pnpm format` and then `pnpm verify`, and `host-editor-verify` loses 26,
`key-inspect-verify` 10, `hosts-header-narrow-verify` 9,
`backup-import-verify` 8, `hosts-error-toast-verify` 6, `rdp-lifetime-verify`
4, `vault-editor-verify` 3, `ssh-retry-verify` 2 and `theme-verify` 1. The
suite loses exactly 69 `ok` lines with it, so no script stopped early and hid
more. Re-measure before sizing a job off that number, because direction and
magnitude both move it: widening to 120 instead costs four checks, all in
`hosts-header-narrow-verify`, and nothing anywhere else.

**Carried by.** Those nine scripts, and two of them say so where a reader
would find it. `scripts/host-editor-verify.ts` names its own affected
sections and its own figure, in a comment beside its own reformat control;
`scripts/key-inspect-verify.ts` names one of its two affected sections, and
no figure. The other seven say nothing about their casualties.

A reformat comment is not evidence of a casualty, and usually it is the
opposite. Eight scripts carry one, and every one of the eight documents a pin
that SURVIVES a reformat - bounded to a regex, whitespace-normalised, or moved
onto the AST - because a comment gets written where somebody fixed something.
Four of the eight have no casualty at all: `scripts/backup-verify.ts`,
`scripts/credential-move-verify.ts`, `scripts/forward-autostart-verify.ts` and
`scripts/forwards-shell-verify.ts` each measure zero, and an earlier version of
this entry named the first two as carriers. The other four are in the nine, and
only `host-editor-verify` and `key-inspect-verify` go on to name what they
lose; `backup-import-verify` and `vault-editor-verify` document only the pin
they hardened, which is what makes their comments the easiest to misread.

**Trigger.** A change to this repository's `printWidth`, or a Prettier major
version that changes how it wraps a call or a template literal.

### Thirty-nine positive checks still read raw source, where a comment can satisfy them

**Accepted state.** A positive source-text check — "this text is present" —
run over a file whose comments have not been stripped is satisfied by a comment
containing that text. Delete the thing, leave a `// was: ...` behind, and the
check that exists to catch the deletion passes. Most of the suite strips first,
for exactly this reason, and every script that strips a `.tsx` now proves its
stripper with two assertions.

Measured, not estimated: fifty-eight positive checks read a raw (unstripped)
variable. Nineteen of them were the same shape — an import, or a call — and
were converted to read the declaration or the call expression off the AST,
which is a form no comment can spell. Thirty-nine remain, and they are spread
across ten scripts: `key-inspect-verify` 9, `modal-shortcut-verify` 8,
`hosts-search-verify` 8, `host-editor-verify` 4, `toast-verify` 3,
`scrollbar-consistency-verify` 2, `recovery-notice-verify` 2, and one each in
`forward-rules-verify`, `forward-autostart-verify` and `clipboard-read-verify`.

The thirty-nine are not one shape. They pin a regex against a CSS rule, an
exact statement inside a component, a `role` attribute, a keyframe name — each
needs its own structural rewrite rather than a lookup, which is why they were
not done alongside the nineteen. Two things bound the exposure. The NEGATIVE
half of each pair is safe over raw text: prose reddens an absence check, which
costs a round and not a defect. And a check going green off a comment needs
somebody to both delete the code and leave the exact text behind, which is a
narrower accident than it sounds.

**Carried by.** The ten scripts named above. `scripts/lib/ast.ts` carries
`namedImportsFrom`, `callsFunction` and `importSpecifiersOf`, which are the
three forms the nineteen were converted to and the tools any further conversion
would use.

**Trigger.** A check in this class observed passing over a deletion — at which
point the whole class is worth converting rather than the one site — or a
script in the list gaining a new positive raw-source check, which should be
written structurally instead of added to the count.

### A utility class can hide a field that every reachability check calls visible

**Accepted state.** The check that the identity editor's Password field
renders in every auth mode answers four questions about it: no ancestor
conditional reaches `authMode` (following a local `const` one hop, so an
indirect boolean does not launder it), it is rendered by the dialog itself
rather than by a wrapper component, it carries no `hidden` or `style`
attribute that reaches `authMode`, and nothing inside its own children is
conditional on the mode. Each of those four was watched fail against the
mutation that expresses it.

A fifth way to hide it is not covered and is not going to be:

```tsx
<Field label="Password" className={draft.authMode === "password" ? "" : "hidden"}>
```

The field renders, its subtree is unconditional, no ancestor decides anything,
and the row is invisible. Refusing it means deciding which class names hide,
which is an enumeration of a utility framework's vocabulary — open-ended,
silently wrong the first time a class is renamed or a variant is added, and
worse than no check, because a list that looks exhaustive is read as one. The
same applies to any `style` value computed somewhere this cannot follow.

The four checks that exist are worth having anyway: they close the four ways
this actually gets broken by a well-meant edit, and the class-name form is the
one nobody reaches for by accident.

**Carried by.** Section 11 of `scripts/vault-editor-verify.ts`, which names
`className` in its own comment as the arm it deliberately does not have, and
`expressionReachesName` in `scripts/lib/ast.ts`, which is the indirection walk
the other four arms share.

**Trigger.** A rendered-DOM harness in this suite — there is none today, which
is the reason every check here is structural — or this repository adopting a
single named utility for hiding that a check could pin by that one name.

### Thirty-eight partial file spellings in comments are counted, not resolved

**Accepted state.** A comment may cite a file by a spelling that matches more
than one file in the tree, and the citation check bounds how many such
spellings exist rather than failing on each one. Thirty-eight sites across
twelve files are in that state today. They are cited from `scripts/`, naming a
bare file under `src/` whose directory shares no prefix with the citing script,
so nearest-module resolution cannot break the tie; the worst carries sixteen
candidates. Every one names a file that does exist, and a reader resolves each
from the citing script's own subject, so none is a defect.

The bound is a ratchet: reducing the count never reddens the check, adding a
spelling does, and the failure message carries the new number and prints the
full list. That was chosen over a per-site failure because a per-site rule would
have commissioned thirty-eight edits across twelve files for zero defects found,
which is a cost with nothing on the other side. Without any bound the class goes
back to being invisible, which is how it got to thirty-eight.

**Carried by.** `PARTIAL_PATH_CEILING` and the `partial-path` detector in
`scripts/citation-format-verify.ts`, whose docblock records the measurement.
Resolution itself is `commentRangesOf` plus the nearest-module step, which
already dissolved twenty-nine of an original sixty-seven, and that step is why
the relative-path class became checkable at all.

**Trigger.** Two, and the second matters more than it looks.

1. The first time a partial spelling is found to have sent a reader to the
   wrong one of its candidates. That is the moment the class stops being
   harmless and a per-site failure earns its cost. The check cannot detect it:
   it answers whether a spelling names something, never whether it named the
   right thing, so this arrives as a human finding in review and not as a gate.
2. Any request to RAISE the number rather than lower it. A ceiling is only
   doing its job while it falls. A raise means somebody added an ambiguous
   citation instead of disambiguating one, and at that point this entry should
   be re-decided rather than the constant bumped. Without that clause a ratchet
   becomes a rubber stamp, which is the ordinary way a bounded-count exemption
   dies.

The mechanical end state is not a trigger but a target: when the count reaches
zero, `partial-path` joins the kinds that must be zero and the constant is
deleted.

## Backup and import

### The import dialog's busy gate is source-pinned, never exercised

**Accepted state.** Nothing in the check suite mounts a component, so no check
asserts that pressing Escape - or clicking outside, or the `X`, or Cancel -
mid-write actually does nothing. Nor does anything assert that the refusal
reasons are rendered at all: the data reaching `ImportSummary.problems` is
pinned by value, the JSX that draws it is not, so a future edit could drop the
list from the markup with every check green. Both are hand-test territory.

**Carried by.** `scripts/backup-verify.ts`'s `[dialog source]` sections, which
assert that `BackupDialog`'s Root `onOpenChange` reads `busy` and returns
before forwarding, that the close button is hidden while busy, and that the
footer Cancel is disabled.

**Trigger.** A component test runner existing in this repository, able to mount
the dialog and dismiss it while a write is in flight.

### One guard in `summarize` cannot be mutated

**Accepted state.** The guard attaching the per-protocol split to the last host
clause is defensive only: an empty list of host clauses implies an empty split,
and the write it would then make goes to a property the spread never reads.
Widening the guard so it always fires changes no output and reddens nothing -
measured, not assumed. No fixture can distinguish the two, so this is recorded
as a limit rather than counted as coverage. The direction that matters, the
guard never firing so the split is lost, reddens five checks.

**Carried by.** `summarize` in `src/modules/backup/summary.ts`, and the clause
fixtures in `scripts/backup-verify.ts`.

**Trigger.** The split gaining a second attachment point, or a host clause that
can be produced without a host count.

## Shared UI

### A shared row/box layout is duplicated between the SSH credential section and the host editor, and only one copy is checked

**Accepted state.** `ForgetKeyRow` (in `SshCredentialSection.tsx`) and
`PinnedKeyRow` (in `HostEditorDialog.tsx`) each hand-roll the same card shape
(a `Field`, a bordered muted box, a small outline button, a footnote) rather
than sharing one component. `ForgetKeyRow`'s own doc comment states the
decision and the reason: the two hold different content (a fingerprint
against a list of accounts) and have different empty states, so a shared
shell was priced and declined. Only `ForgetKeyRow` is pinned by a verify
script today; `PinnedKeyRow`'s copy of the shape is not.

**Carried by.** `ForgetKeyRow`'s doc comment in `SshCredentialSection.tsx`,
which names the decision and its reason.

**Trigger.** A third card needing the same shape - at that point the cost
calculus in the doc comment is no longer about two call sites and should be
re-run.

## Keychain and secrets

### An orphaned keychain account cannot be enumerated

**Accepted state.** A secret can exist at `<id>::<field>` in the OS
keychain/DPAPI/store with nothing in `tervia-hosts.json` or
`tervia-vault.json` naming it any more. Nothing in the app can list it to find
out: the registered secret commands are `secrets_get`, `secrets_set`,
`secrets_delete`, `secrets_get_all` and `secrets_copy`, and `secrets_get_all`
takes the accounts to fetch rather than enumerating what exists - there is no
`secrets_list`, so a sweep for orphans cannot be written from the frontend at
all. It is an extra, inert copy rather than a lost secret: nothing names it,
so nothing reads it, writes it, or would sync it either.

**Carried by.** `src-tauri/src/modules/secrets.rs`, which is the whole
registered secret-command surface.

**Trigger.** A `secrets_list` command being added for another reason, or a
user reporting keychain clutter.

### Clearing the key textarea removes the key body and strands its passphrase

**Accepted state.** Under key auth, clearing a seeded private key body and
saving sends an empty body and deletes that account, but the key passphrase
field is untouched, so it is omitted from the save and its account survives.
What is left is a passphrase that opens nothing. It is NOT the orphan above,
and the difference is the whole of what is accepted here: `hasKeyPassphrase`
stays true on the host record, so `tervia-hosts.json` still names the account
and `hostKeySecretNames` in `editor/credentialChoice.ts` still enumerates it.
What it is instead is unreachable from the screen that made it - the row
offering to forget stored key material renders only in the auth modes that
have no key field, so the user has to switch to password or agent auth before
anything offers to clean it up.

**Carried by.** `sshSecretsForSave` in `src/modules/hosts/editor/sshSecrets.ts`,
whose rule that both key fields go down together holds for the explicit forget
override and not for the textarea route, and `ForgetKeyRow`'s placement in
`SshCredentialSection.tsx`.

**Trigger.** A user report of a host still offering to forget a key passphrase
after its key was removed - the "Stored key material" row is what shows it, and
only once that host is on password or agent auth, so the report arrives from
someone who switched modes for an unrelated reason. Or the key passphrase input
gaining a visible stored/empty state: it is masked today and looks identical
either way, which is why the help copy under the textarea deliberately does not
mention the leftover - the advice could not be acted on from that screen.

## Store files and recovery

### The `.bak` snapshot protects against a torn file, never against a save that wrote the wrong thing

**Accepted state.** `createRecoveredStore`'s `commit` saves the store and then
snapshots the file that save produced, and `snapshotStoreFile` copies whenever
`inspect` calls the primary `"ok"` - which any JSON object satisfies, an empty
one included. So a bug that persists a valid but wrong value (an emptied host
list, a rule list missing a row) is written to the primary and then copied
straight over the last good snapshot, and the recovery pass on the next launch
finds an `"ok"` primary and correctly leaves it alone. What the snapshot covers
is exactly the class where the bytes stop being a usable JSON object: a torn or
truncated write, a nul-filled file, a hand edit that breaks the syntax, a read
that comes back as garbage. It has never covered content, and the wording of a
recovery toast should not be read as claiming otherwise.

Worth stating because the obvious inference runs the wrong way: making the write
atomic removes the torn-file class but leaves this one untouched, so it is not a
reason the snapshot could be retired. It is the reason the snapshot's scope is
narrower than "the store is protected".

No content guard belongs at this layer without teaching it what each store's
shape means, and each store layer already owns its own integrity rules -
`persist` in `hosts/store.ts` writes what its caller assembled, deliberately,
because the rules deciding whether that value is legal live above it.

**Carried by.** `commit` in `src/lib/recoveredStore.ts`, which orders the save
before `snapshotAfterSave`, and `inspect` in `src/lib/storeRecovery.ts`, whose
`"ok"` means "parses as a non-array object" and nothing more.

**Trigger.** A store gaining a shape check cheap enough for the recovery layer
to run before it snapshots - a row count that must not fall to zero in a single
write is the obvious candidate - or a report of a store that emptied itself and
took its snapshot down with it.

### An atomic store write is durable against a crash, not against power loss in the moment after the rename

**Accepted state.** `atomic_write` stages into a sibling temp, `sync_all`s it,
drops the handle and renames over the target. It does not then fsync the parent
directory, so a power cut in the window after the rename returns and before the
directory entry is durable can leave the target naming its previous contents.
That loses the update; it does not tear the file, and what is on disk afterwards
is the last good version rather than a half-written one - which is why this is
recorded as a bound on the guarantee rather than as a corruption path the `.bak`
has to cover. Adding the directory fsync would cost every editor buffer save the
same latency to close a window measured in microseconds.

**Carried by.** `write_staged` in `src-tauri/src/modules/fs/atomic.rs`, whose
`sync_all` is on the staging handle only.

**Trigger.** A store whose loss of a single committed write is not acceptable -
one holding a secret's only record rather than a copy of it - or a report of a
store reverting one edit after an unclean shutdown.

### A restore rolls the file back and leaves the keychain where it is

**Accepted state.** Recovery replaces a store file with its snapshot, which is
metadata as of the last process start. The OS keychain is written atomically and
is therefore current. Nothing reconciles the two, and nothing can: the registered
secret commands take the accounts to fetch rather than enumerating what exists,
so the app cannot ask what it still holds. What comes back is a record whose
`hasPrivateKey`, `hasPassphrase`, `hasPassword` and `hasKeyPassphrase` may name a
secret that has since been deleted, and whose `fingerprint` may name a PEM the
account no longer holds. None of those is read back and re-derived **on this
path**.

That qualifier is narrower than it used to be, and the narrowing is real rather
than a wording change. `rederive` in `src/modules/sync/scheduler.ts` does read a
vault key's stored body back and re-derive its fingerprint — but only for a key
a pull just landed, and only when the landed record and this device's keychain
disagree. A restore triggers no pull, so nothing here reaches that path: what
came back is a file, not a landing. A device that also syncs will have the vault
half corrected by its next pull as a side effect, which is a happy accident and
not a recovery mechanism — the accepted state below is what holds for a device
that does not.

The whole of what is done about it is that the recovery toast says so. It states
that stored passwords and keys did not come back with the file; it does not claim
the app checked anything, because it did not.

**Carried by.** `recover` in `src/lib/storeRecovery.ts`, whose own comment states
the divergence, and `recoveryToast` in `src/app/lib/recoveryNotices.ts`, which is
where the sentence lives. `reusableVaultKey` in
`src/modules/hosts/credentialMove.ts` is what would act on a stale one: it binds
on the first fingerprint match.

**Trigger.** A keychain enumeration existing (there is no `secrets_list`), or a
user report of a host offering a key it does not hold after a recovery toast.

### `tervia-settings.json` is the one store file with no recovery in front of it

**Accepted state.** Five of the six store files go through
`createRecoveredStore`: a corruption check before the first read, a `.bak`
snapshot after every commit, and a whole-file atomic write.
`tervia-settings.json` does not. It is read and written by `tauri-plugin-store`
directly, whose save is an in-place truncate and whose load error on a file it
cannot parse is swallowed - so a torn or nul-filled file comes back as an empty
store and the next save writes that emptiness over it. The worst case is a
settings reset: the store holds no secret, and every field in it can be set again
from the settings page.

It stayed on the plugin for one reason. It is the only store depending on
`LazyStore.onChange`, the plugin's cross-window `store://change` broadcast, which
the recovered family does not use; and `writePref` pairs that broadcast with a
`SELF_LABEL` dedupe of its own mirrored event, so the writing window handles the
change exactly once. Converting means rewriting that dedupe in a second webview,
which is a change with no durability payoff proportional to it.

**Carried by.** The `LazyStore` at `src/modules/settings/store.ts` and its
`onChange` subscription, which is what a conversion would have to replace. The
module header of `src/lib/storeRecovery.ts` names this file as the one still on
the plugin.

**Trigger.** The settings store gaining a field that cannot be re-entered from
the UI, or `LazyStore.onChange` no longer being needed there.

### A store file this app cannot read is inert until it can

**Accepted state.** A whole-file write can only be as good as the read it is
built on, so a store whose file could not be read refuses to save rather than
write a file assembled from an empty cache - which would destroy exactly the
file it never got to see. Two reads land there. `fs_read_file` refuses a file
above its size limit and reports `toolarge`; and it rejects for a file that is
present and will not open (a lock during an update handoff, a Windows sharing
violation, EACCES, a descriptor limit). The recovery pass leaves both alone for
the same reason - unknown contents may be perfectly good ones - so neither has a
snapshot restored over it either.

The consequence is that such a store is inert while the condition lasts: it loads
as empty and every mutation fails with a refusal naming the reason. That is the
accepted cost. No store in this app approaches the size limit today, and an
unopenable file is expected to clear on its own or to need a human.

The same rule covers the `.bak`, and there the accepted state is the other way
round: a snapshot this app could not read is never REPLACED, so a store whose
`.bak` is unreadable takes no new snapshot until that clears, and a crash in the
meantime falls back to whatever that older `.bak` holds. Replacing it instead
would destroy the only surviving copy whenever the primary is absent or torn -
which is exactly the state a snapshot exists for. Nothing latches: the decision
is taken per pass from a fresh read, so the first commit after the condition
clears snapshots normally.

**The user may not hear about it, and that is the part accepted rather than
fixed.** A refused pass does put a note in the recovery slot, but two things
stand between that and a toast. A good primary beside an unreadable `.bak` gets
no launch notice at all - `recover` returns as soon as the primary reads `"ok"`
and never looks at the snapshot. And the note lands too late for its own
commit's drain: `commit` runs the broadcast and the snapshot pass concurrently,
the broadcast is one IPC against the snapshot's three, so the drain the event
fires finds the slot still empty and the note is picked up by the NEXT commit's
drain. A session that makes one edit and quits is therefore never told the
safety net stopped being refreshed. Draining after the snapshot pass instead
would fix it and would put every cross-window update behind a file copy, which
is the worse trade.

The same shape covers the writes that follow. A store layer sees a rejected
`save()` and logs it; there is no per-store toast, so a profile in this state is
quiet while each edit fails.

One classification is done by wording, not by a type: `fs_read_file` rejects for
both "no such file" and "would not open", so the distinction is drawn from the
`(os error N)` suffix Rust appends to an OS error - 2 and 3 mean absent,
everything else means unreadable. An error that carries no such suffix is read as
unreadable, which is the safe direction: a first run misread that way costs a
default that is not written until the first real change, where the reverse costs
the file.

**Carried by.** `createFileKeyValueStore` in `src/lib/fileKeyValueStore.ts`,
whose `refused` flag holds the verdict; `tauriStoreFileIo.read` in
`src/lib/storeRecovery.ts`, which does the classification; and the
`[whole-file]` group in `scripts/vault-resolve-verify.ts` and the `[unreadable]`
group in `scripts/workspace-store-verify.ts`, which pin both halves.

**Trigger.** A store file that legitimately grows past the limit - the workspace
file is the only plausible candidate, since it holds a tab tree per workspace -
or `fs_read_file` gaining a distinct not-found result, which would retire the
string match.

## Window sizing

### A profile that quits maximized keeps a below-floor size, once per session

**Accepted state.** The configured size floor is re-applied after the
window-state plugin has restored a saved size, but deliberately not while the
window is maximized or fullscreen: a programmatic resize would drag it out of
that state, so the clamp returns early and leaves the floor to the next time
the window is sized normally. A profile that quit maximized therefore comes
back maximized carrying a restored size below the floor, and the first
un-maximize of the session shows a window under it. This does not settle on the
next launch. The restore is maximized again, the clamp declines again, and the
symptom recurs once per session until the user resizes past the floor by hand,
which is the only thing that writes a compliant size back for the plugin to
save. The cost is one under-floor window per session, against an
unmaximize/clamp/re-maximize dance at startup, which is exactly the fighting
with the plugin that the early return exists to avoid.

**Carried by.** `enforce_configured_min_size` in `src-tauri/src/lib.rs`, whose
early return on a maximized or fullscreen window is this accepted behaviour and
whose doc comment states the mechanism, and `min_size_correction` in the same
file, which is the decision the clamp delegates to and the half that has tests
in front of it.

**Trigger.** A report of a window that cannot be resized back up, or
`tauri-plugin-window-state` gaining a saved-size update while maximized - which
would keep the below-floor size from being saved in the first place, and retire
the clamp's need to correct one.

## Tombstones and record stamps

### A device offline longer than 90 days can resurrect a record deleted while it was away

**Accepted state.** A delete leaves a tombstone, and a tombstone is dropped once
it is 90 days old. A device that has not synced for longer than that has never
seen the tombstone and still holds the record, so its next push re-creates
something the user deleted. The window is a guess about how long a device can
plausibly be away, and it is a guess in both directions: shorter reclaims space
sooner and resurrects more, longer resurrects less and keeps a growing list of
deletes nobody will ever consult again. Against that, the alternative is keeping
every tombstone forever, which makes the file grow without bound for a store
whose whole content is a few dozen rows.

A remote tombstone past the window widens this by one step, and it is the same
guess seen from the other side: the pull in `src-tauri/src/modules/sync/engine.rs`
does not hand an expired tombstone to the apply path at all — landing it would
write a row every read then filters straight back out, once per pull, for the
life of the bucket. So a local record nobody has touched for longer than the
window, against a remote delete older than the window, is reported as a
divergence for the user to resolve rather than deleted. That is the direction a
local record with no remote object at all already takes, and for the same
reason: an absence and an expiry are both inferences, and acting on either
destroys data.

**Carried by.** `TOMBSTONE_TTL_MS` in `src/lib/tombstones.ts`, which is the
window, `livingTombstones` in the same file, which applies it on this side, and
the `expired` clause in `pull` in `src-tauri/src/modules/sync/engine.rs`, which
applies it to the remote's copy.

**Trigger.** A device registry that can say when each device last pulled. The
window can then be derived from the oldest live device rather than guessed, and
this entry retires rather than being re-tuned.

### Expired tombstone bytes are never reclaimed in a store that sees no further deletes

**Accepted state.** Pruning is filter-on-read plus prune-on-write: a read never
returns an expired tombstone, and every write of the tombstones key persists the
already-filtered list. Nothing prunes at load time, so a store whose last delete
was a year ago still holds that row on disk - invisible to every reader, and
reclaimed only by the next delete or the next upsert that clears a tombstone. The
alternative considered was a load-time pass, which `RecoveredStoreIo` has no hook
for and which would cost a store write, a `.bak` snapshot and a cross-window
changed event on every launch where anything happened to expire. What is given up
is bytes in a file nobody writes to again, which is where it matters least.

**Carried by.** `livingTombstones` in `src/lib/tombstones.ts`, which filters on
read, and `withTombstone` and `withoutTombstone` in the same file, which are the
only things that compact the stored list. All three name this file back.

**Trigger.** Any store gaining a load-time maintenance pass for some other
reason. The pruning can ride it at no extra cost, and this entry retires.

### A landed record can sit with a reference that has not arrived yet

**Accepted state.** `applyRemote` applies a landing whose `hostId`, `keyId` or
`groupId` names a record this device does not hold, rather than refusing it. The
order of a pull is an artifact of a listing rather than of what the other device
holds, so a rule arriving before its host is ordinary - and the alternative is
worse than the gap: the reference guards `throw`, and a throw from inside the
single queued write an apply runs as would lose every other landing in the same
set.

**Carried by.** `landingRefusal` in `src/lib/tombstones.ts`, whose five
conditions are the whole refusal set and deliberately exclude every reference
guard, and the `applyRemote` doc on each of the three stores. `assertReferences`
in `src/modules/hosts/store.ts` already accepts the analogous case for a missing
group, and says why: the member renders as ungrouped, which is visible and
recoverable. Hosts and groups are applied before rules within one pull, so the
ordinary case resolves in one pass.

**Trigger.** A reference whose dangling state is neither visible nor
recoverable, one that makes a record unopenable rather than oddly rendered.
That would need a per-pull deferral pass, which is a different shape from a
refusal.

### A landed delete runs none of the in-use refusals a local delete runs

**Accepted state.** `deleteKey` refuses while an identity still names the key,
`deleteIdentity` refuses while a host still binds it, and `deleteHost` refuses
while another row jumps or tunnels through it. `applyRemote` runs none of the
three: it drops the record and releases the keychain accounts it owned. So a
holder this device has created and not yet pushed does not stop a delete another
device published, and the released secret cannot be put back - this layer never
reads one to hold a copy.

Accepted because refusing is worse in the direction that matters. The other
device decided the delete against the inventory it could see; a refusal here
leaves the record alive locally, and a live record is pushed, so one user's
delete would resurrect on every device that still has a holder. The holder that
remains is the state the local refusals describe as recoverable: an identity
naming a key that is gone, or a row whose jump host vanished.

**Carried by.** The `applyRemote` doc on each of the three stores, which states
it beside the two cascades that are deliberately not re-run. The local refusals
are `identitiesUsingKey` in `src/modules/vault/refs.ts`, the `hostRefs` argument
to `deleteIdentity`, and the `VaultInUseError` branch of `deleteHost` in
`src/modules/hosts/store.ts`.

**Trigger.** A report of a secret lost this way, or the pull gaining a place to
put a refusal that does not republish the record - a per-object quarantine that
holds the landing without reviving what it names.

### A landed delete drops a forward rule without stopping the forward it is running

**Accepted state.** Every user-reachable write route in the forwards store is
sequenced behind a release of the running forward; `applyRemote` is the fourth
write route and is not, so a landed delete can remove a rule record while its
tunnel is still bound to a local port. The tunnel then runs with nothing naming
it until the app is restarted.

The store cannot close this itself: the runtime lives in
`src/modules/forwards/controller.ts`, which imports the store, so a store that
called back into it would close the cycle every port in that module exists to
keep open. The release belongs to whatever calls `applyRemote`, ahead of the
apply, which is how `HostsPage.tsx` sequences the same pair for `deleteHost`.

**Carried by.** The pinned member set in `scripts/forwards-shell-verify.ts`,
which names `applyRemote` as a write route the release claim does not cover, and
the `applyRemote` doc in `src/modules/forwards/store.ts`.

**Trigger — fired, and narrowed rather than retired.** The first caller of
`applyRemote` is the sync scheduler, and it does sequence the release: `release`
in `src/modules/sync/scheduler.ts` runs `releaseRule` for every rule a landed
DELETE is about to remove, before the apply, through an injected port so the
module stays loadable without a Tauri runtime. `scripts/sync-scheduler-verify.ts`
pins both the release and its order against the commit.

What remains is narrower and is what this entry now describes: a landed EDIT is
not released. Another device renaming a rule, or changing its endpoints, lands
over a record whose tunnel is still bound to the old ones — the rule row then
describes something other than what is running. Releasing there was rejected
because the common case is cosmetic and the cost is dropping a tunnel the user
is working over. The trigger for closing it is a report of a rule whose row and
running forward disagree, or an edit path that can change `localPort` from
another device.

## Cross-device sync

### Sync's on/off switch is enforced in TypeScript only

**Accepted state.** "Sync off means no network" is checked before either Rust
command is reached, never inside them. `sync_pull` and `sync_push` will run
against a configured session whenever they are called, so a future caller that
did not consult the config would sync for a user who never turned it on.

**Carried by.** The `config.enabled` guard in `runPull` and `runPush` in
`src/modules/sync/scheduler.ts`, and the absence of any enabled flag on
`SyncState` in `src-tauri/src/modules/sync/engine.rs`. The first check in
`scripts/sync-scheduler-verify.ts` asserts the zero on a counting command port,
so the guard cannot quietly stop existing.

In `runPush` the guard sits after the dirty set is taken and cleared, not
before, and that order is deliberate: marks accumulated while sync was off
describe an inventory the remote has never seen, and the pull that follows
turning it on publishes all of it anyway — so holding them would only make that
first push describe itself twice, while a set that grew for months would be
carried forever for nothing.

A Rust-side duplicate was rejected rather than overlooked: the flag lives in the
same store file as the rest of the configuration, which is a TypeScript store,
so Rust would have to either read that file itself or be told the flag on every
call — and a flag passed in by the caller is not a gate, it is the same guard
one layer further from where the decision is.

**Trigger.** A second caller of `sync_pull` or `sync_push` from outside
`src/modules/sync/scheduler.ts`. At that point the gate belongs where both
callers pass through, which is the session itself.

### A tombstone published by a device that has since been retired is never pruned

**Accepted state.** The prune removes a remote tombstone object only when this
device published it. A device that is wiped, lost or reinstalled leaves its
tombstone objects on the remote with nobody left who will delete them, so they
accumulate for the life of the bucket. They are small and harmless — every other
device reads them, finds them expired, and ignores them — but nothing reclaims
the bytes.

**Carried by.** The `envelope.device == device` clause in `pull` in
`src-tauri/src/modules/sync/engine.rs`, and the test there that asserts another
device's expired tombstone survives the prune.

A bucket that refuses DELETE outright — read-only credentials, an object lock, a
lifecycle policy — reaches the same state by a different road, and the prune
tolerates it rather than failing: a refused delete is not counted and the pull
carries on, because making the first expired tombstone abort the whole reconcile
would cost every landing and every push over an object whose only cost is the
bytes it occupies.

The clause is what makes the prune safe at all, which is why the residue is
accepted rather than traded away: a device whose clock runs a hundred days fast
would otherwise delete every remote tombstone on its first pull, and every other
device would then re-push any record edited inside the window. A wrong clock
locally skews one device's view; a wrong clock pruning globally rewrites
everybody's.

**Trigger.** A device registry — the same trigger the 90-day resurrection entry
above already names, so the two retire together.

### A legacy PEM key keeps a dropped fingerprint until it is next opened

**Accepted state.** The merge drops a key record's `fingerprint` whenever the
winning envelope's own record claims no private key, because that layer has no
keychain and a fingerprint carried forward could describe a body nobody holds.
The apply path puts it back by inspecting the body this device stores — and for
an `openssh-key-v1` body that works with no passphrase, so the ordinary case
fires no prompt during a background pull. A legacy PEM or PuTTY body cannot be
read at all without its passphrase, so for those the inspection answers only
"this is encrypted" and the record is left with its presence flag corrected and
its fingerprint still absent. The key works; the row shows no fingerprint until
the user next opens it with the passphrase in hand.

**Carried by.** `rederive` in `src/modules/sync/scheduler.ts`, which writes
whatever the inspection answered and states the flag from the body existing
rather than from reading it, and `vaultKeyFactsFrom` in
`src/modules/vault/keyInspect.ts`, whose sealed-container branch answers
`encrypted` and nothing else by decision.

Prompting for the passphrase was rejected rather than overlooked: this runs
inside a background pull, on a device the user may not be looking at, over
however many keys one pull landed. A dialog there is a modal nobody asked for,
at a moment nobody chose.

**Trigger.** A report of a key showing no fingerprint after a sync, or a
passphrase cache existing — with one, the inspection can be retried for free at
the moment the user opens the key anyway.

### Stripping key bodies from the remote only holds once every device has stopped carrying them

**Accepted state.** The purge rewrites every remote object so it no longer
carries a private key body. A device that still has carrying on then holds the
only copy of what was stripped, and `merge` never merges the `secrets`
component — the winner's rides along and the loser's is discarded — so that
device's next reconcile finds its own copy wins on that component and publishes
the body straight back. One pull is enough. The purge is therefore a per-fleet
operation wearing a per-device button, and the settings section says so beside
the button rather than leaving the user to discover it.

**Carried by.** `purge_secrets` in `src-tauri/src/modules/sync/engine.rs`, which
rewrites and does not gate on anything fleet-wide because it cannot see the
fleet, and the note in the purge block of
`src/settings/sections/SyncSection.tsx`.

Making the purge refuse until every device has opted out was rejected: there is
no device registry, so the only thing that could answer "has every device
stopped" is a guess, and a guess that refuses is worse than a sentence that
explains.

**Trigger.** A device registry — the same trigger the retired-device tombstone
entry names — or a report of bodies reappearing after a purge.

### Deleting a key body on one device does not stick while another device still holds it

**Accepted state.** `hasPrivateKey` is a field on the record, not a per-device
fact, so it travels. A user who clears a key's body on one device publishes
`hasPrivateKey: false`; a second device that still holds that body lands the
record, sees the disagreement with its own keychain, corrects the flag back to
`true` and publishes the correction — which the first device then lands. The
body really is gone on the first device, and its record now claims one it does
not hold, so a connect through that key fails there with a message about a
missing secret rather than about a deleted one. Clearing the body on every
device settles it.

This converges rather than oscillating: the correction is made only by a device
that holds the body, and a device holding none re-derives nothing, so the
exchange is one round and stops.

**Carried by.** `rederive` in `src/modules/sync/scheduler.ts`, and the absence
of `hasPrivateKey` from `DEVICE_LOCAL_FIELDS` in
`src-tauri/src/modules/sync/model.rs`.

The alternative dispositions are both worse and were rejected rather than
missed. Honouring the remote's `false` would have one device's delete destroy a
private key on another, which is the data loss the whole apply path is built
around refusing. Correcting the fingerprint without the flag leaves the record
claiming no body, so the merge drops the fingerprint again on the next pull and
the re-derivation repeats — a store write per pull, for the life of the record.

**Trigger.** `hasPrivateKey` becoming a per-device fact, which needs the
records to carry presence per device rather than once — or a report of a key
that will not connect after a body was deleted elsewhere.

### Two devices configuring one empty prefix at the same moment can strand a root key

**Accepted state.** `sync_configure` reads the keyfile and writes a fresh one
when there is none. The write is unconditional, so two devices that both find
the prefix empty both mint a root key and both write it: the second overwrites
the first, and the device that lost is left holding a root key nothing on the
remote was ever sealed under. Its own pushes seal under a key no other device
can open, and it cannot open theirs. Recovery is to re-enter the passphrase on
the losing device, which re-reads the winning keyfile.

The window is the round trip between the read and the write, on a prefix that
has never been synced — so it needs two devices set up within seconds of each
other against the same fresh bucket, and it cannot recur once a keyfile exists.

**Carried by.** The `None` arm of the keyfile read in `sync_configure` in
`src-tauri/src/modules/sync/engine.rs`, whose comment states the residue.

A conditional create was the obvious fix and is not available: `put` on
`SyncProvider` takes an etag to match, which no absent object can satisfy, and
there is no create-if-absent verb on the port at all. Adding one means adding a
sixth verb every backend has to implement, for a race that costs one re-entry
and cannot happen twice.

**Trigger.** A create-if-absent verb existing on `SyncProvider` for another
reason, or a report of two devices set up simultaneously failing to see each
other.
