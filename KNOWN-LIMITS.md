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

**Trigger.** A vault editor gaining a field whose content exists nowhere but
the form - a key the dialog generates rather than one picked from a file is
the case, and neither editor has one today: the key body comes from a file
that is still on disk, and everything else is typed. Or a user report of the
retyping cost, which does not wait on a new field.

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
account no longer holds. None of those is ever read back and re-derived.

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
