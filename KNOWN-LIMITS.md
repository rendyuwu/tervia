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

**Trigger.** A vault editor gaining a draft expensive enough to retype that
losing it outweighs the overwrite risk, or a user report of the retyping
cost.

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

### Convert reads no keychain, so a concurrent key rotation can mis-describe a minted key

<!-- Heading created for this sub-wave's hand-off; the body is owed by the
     task that owns the convert path and is confirming its exact residual
     shape against the tree. Fill in the three parts above this comment,
     then delete the comment. -->

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

**Carried by.** `scripts/host-editor-verify.ts` documents which of its own
sections this affects, in a comment beside its own reformat control.
`scripts/credential-move-verify.ts`, `scripts/backup-verify.ts` and
`scripts/vault-editor-verify.ts` each carry more pins of the same shape,
documented the same way near where they live.

**Trigger.** A change to this repository's `printWidth`, or a Prettier major
version that changes how it wraps a call or a template literal.

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
