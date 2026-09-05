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
