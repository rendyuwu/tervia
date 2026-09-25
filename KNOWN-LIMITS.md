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

## Vault keys

### A `hardware`-kind key is proven through a throwaway ssh-agent, never a real FIDO2 token

**Accepted state.** No hardware FIDO2/U2F token exists in the environment this
repository's checks run in. The end-to-end proof that a `hardware`-kind vault
entry authenticates through `authenticate_agent` restricted to one ssh-agent
identity (`hardware_kind_authenticates_only_through_the_matching_agent_identity`)
loads an ordinary generated key into a throwaway `ssh-agent` rather than a real
`sk-ssh-ed25519@openssh.com` identity. The path it proves - agent
authentication restricted to one fingerprint - is identical either way, since
Tervia never sees the private material behind a fingerprint regardless of what
holds it. What is NOT exercised is a physical touch prompt, or a CTAP-specific
error (device absent, touch timeout, PIN required) surfacing through this
path: those errors reach `authenticate_agent` as an ordinary ssh-agent
transport failure today, indistinguishable from any other signing error.

**Carried by.** `hardware_kind_authenticates_only_through_the_matching_agent_identity`'s
own doc comment in `src-tauri/src/modules/ssh/session.rs`, which names the
substitution.

**Trigger.** A FIDO2 token becoming available in the environment these checks
run in, or CTAP-specific error handling being added to `authenticate_agent`'s
path.

### A build without the hardware exemption still strips a hardware key's fingerprint during cross-version sync

**Accepted state.** `sync/model.rs`'s `merge` now exempts `kind: "hardware"`
from the rule that drops `fingerprint` whenever a record's own
`hasPrivateKey` is false - a hardware key's `fingerprint` is its only
identifying fact and is never backed by a keychain body, so stripping it is
unrecoverable (`rederive` in `src/modules/sync/scheduler.ts` restores a
fingerprint from a keychain read, and a hardware key has none). A syncing
device running a build from BEFORE this exemption still applies the old,
unexempted rule: on any merge where that older build's copy is chosen as the
winner, the fingerprint is stripped and republished to every device,
including ones already running the fix. Two syncing builds do not
negotiate a shared rule - each merges with whatever rule its own binary
carries.

**Carried by.** The exemption itself, `merge` in
`src-tauri/src/modules/sync/model.rs`, and its own doc comment naming the
hardware case explicitly.

**Trigger.** Every device in a sync group running a build with the
exemption - at that point no copy of the old, unexempted rule is left to
strip it, and this entry can be removed.

### RSA certificates are unverified against a live OpenSSH server

**Accepted state.** [INFERENCE] A `cert`-kind vault entry's certificate can
be built over any algorithm `ssh_key_classify`/`ssh_key_inspect` accept,
RSA included, and `authenticate_hop`'s certificate branch calls
`Handle::authenticate_openssh_cert` with no hash-algorithm parameter -
unlike the plain-key branch's `PrivateKeyWithHashAlg::new(.., Some(HashAlg::Sha256))`.
For a parsed RSA certificate the pinned fork's own
`Algorithm::to_certificate_type` maps to `ssh-rsa-cert-v01@openssh.com`,
which OpenSSH 8.8 and later refuse under their default
`PubkeyAcceptedAlgorithms` (the same SHA-1-signature retirement
`HOST_KEY_ALGOS`'s own doc comment in `src-tauri/src/modules/ssh/session.rs`
names for the plain-key case). The cert e2e test
(`cert_authenticates_against_a_real_sshd_trusting_only_the_ca`) signs and
dials with an Ed25519 certificate only, so this is read off the crate's
source rather than exercised against a live server.

**Carried by.** `authenticate_hop`'s certificate branch in
`src-tauri/src/modules/ssh/session.rs`, which calls
`authenticate_openssh_cert` with no hash algorithm.

**Trigger.** A `russh` release whose `authenticate_openssh_cert` (or its
certificate-signing path) becomes hash-algorithm-aware, or a user report of
a refused RSA certificate against a default-configured OpenSSH server -
either resolves this entry, the first by fixing the gap and the second by
confirming it and turning this into a named refusal in `save` instead.

### An older build editing a cert or hardware key silently rebuilds it as a plain PEM key

**Accepted state.** `keyRecordFrom` (`src/modules/vault/editor/draft.ts`)
builds the saved record entirely from the draft it is handed; an older
build's `KeyDraft`/`keyRecordFrom` has no `kind`/`certificate` fields at
all. If a user opens a `cert`- or `hardware`-kind record in an OLDER build
of the key editor and presses Save, the older build's `keyDraftFrom` never
read the new fields into its draft, so its `keyRecordFrom` writes a fresh
object with no `kind` and no certificate - a working key becomes a
body-less (or signing-key-only) PEM record, silently, with no refusal
anywhere in that build's own code to catch it. Sync then propagates the
result on the usual last-write-wins terms: a newer device that pulls it
inherits the stripped record.

This build itself is not silent about the reverse direction: an unknown
future `kind` this build does not recognise is refused at save time
(`validateKeyDraft`'s exhaustive switch, called inside `save`'s `try` so
the refusal reaches the form rather than becoming an unhandled promise
rejection) and renders no kind badge on the Vault page
(`page/KeyCard.tsx`).

**Carried by.** `keyRecordFrom` and `keyDraftFrom` in
`src/modules/vault/editor/draft.ts`, which together are the whole of what
an older build's editor would need to preserve the new fields and do not
exist in a build before this branch.

**Trigger.** Every device in a sync group running a build that knows
`kind`, `certificate` and the parsed cert facts - at that point no older
editor is left to strip them on save, and this entry can be removed.

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

### Termius import is not offered, because no confirmed export format exists to parse

**Accepted state.** Host import from `~/.ssh/config`, Termius, and PuTTY
exports was requested with Termius's own export format left `[unverified]` -
no real export sample was obtainable while implementing the other two, so
rather than guess at an unconfirmed shape, this app ships the other two
sources only - Termius has no picker entry, no parser, and no menu item.

**Carried by.** `HostsBackupActions.tsx`'s "Import from..." menu, which lists
exactly the two confirmed sources; the symbol to extend once a sample exists
is that menu plus a new sibling of `sshConfigImport.ts`/`puttyRegImport.ts`.

**Trigger.** A real Termius export sample becomes available to write a parser
against.

### An ssh_config/PuTTY import is not idempotent across repeat runs

**Accepted state.** A `.tervia-backup` row carries a stable `id` that
round-trips, so re-importing the same backup updates the same records. An
`ssh_config`/`.reg` row carries no such id - every host, key and identity gets
a freshly minted id on every parse - so importing the same file twice creates
a second, independent set of records rather than merging into the first.
Nothing this import was asked to do requires repeat-import merging, and
the fields this format offers (an alias, a resolved `IdentityFile` path) were
never designed to be a stable identity across machines, so merging on either
would be inventing a guarantee the source format does not make.

**Carried by.** `previewSshConfigImport`/`previewPuttyImport` in
`src/modules/backup/foreignImport.ts`, which mint every id fresh from the
parsed rows rather than reusing one from a prior import.

**Trigger.** A user-reported case where re-importing an unchanged
`ssh_config`/`.reg` file duplicating every host is a real workflow problem,
not a one-off - at which point a stable identity key (alias, or resolved
`IdentityFile` path) would need to be chosen and merge semantics designed
around it.

### The line-range file reader still refuses a BOM'd UTF-16 file `fs_read_file` now decodes

**Accepted state.** `classify_bytes` gained a BOM-aware UTF-16LE/BE decode
ahead of its null-byte sniff, so `fs_read_file` now reads a PuTTY `.reg`
export (or any other BOM'd Windows-authored text file) as text.
`fs_read_file_portion_inner` - the AI read tool's line-range reader - still
refuses the same bytes as `Binary`: its own null-byte sniff has no BOM check
at all. Not part of this import's acceptance boxes - the importer calls only
`fs_read_file` - and not a two-line fix either. `fs_read_file_portion_inner`
is byte-oriented (`BufReader::read_line` line by line, assuming each line is
valid UTF-8 on its own), so decoding UTF-16 would mean buffering and decoding
the whole file into a `String` first and then re-deriving the
offset/limit/`total_lines` slicing against it - a second, parallel
line-splitting path, not a peephole added to the existing streaming loop.

**Carried by.** `fs_read_file_portion_inner` and `classify_bytes` in
`src-tauri/src/modules/fs/file.rs` - the two commands' now-diverging verdict
on the same byte-for-byte input.

**Trigger.** A user or an AI tool asking to open a slice of a UTF-16 file
through the line-range reader specifically, or a decision to give
`fs_read_file_portion_inner` its own buffered UTF-16 decode path rather than
its current streamed one.

## Host groups

### A group's name is unique across the whole tree, not per-parent

**Accepted state.** `upsertGroup`'s collision check (`sameName`) compares an
incoming group's name against every OTHER group's, regardless of nesting -
two groups named "Servers" cannot coexist even when they sit under different
parents. Nesting itself gave no reason to scope the check per-parent: the
host editor's group picker (`Combobox` in `HostEditorDialog.tsx`) already
lists every group by its flat name, with no parent path shown, so two
same-named siblings would be indistinguishable there regardless of where the
uniqueness rule is enforced.

**Carried by.** `sameName` and the collision check in `upsertGroup`
(`src/modules/hosts/store.ts`).

**Trigger.** A request for same-named siblings under different parents -
which would also need the host editor's group `Combobox` to grow a
disambiguating path label, since "Servers" alone would no longer say which
one a host is being filed under.

### A reparent or a rename of the same group on two devices resolves last-write-wins, with no awareness of the OTHER record it changed

**Accepted state.** `HostGroup.parentId` travels as an ordinary, opaque field
on the group record - the same wire path `groupId` already proved carries an
unparsed value untouched (`model.rs`'s
`a_field_this_module_has_no_rules_for_survives_the_whole_trip`). `merge` in
`model.rs` resolves two copies of ONE record by timestamp and content only; it
has no notion that a `parentId` names another record, so it cannot detect that
a merge just landed a cycle two devices each built independently while
believing the tree was still acyclic, or that a group's parent was deleted on
one device between the two devices' last sync. Nothing is lost - a dangling or
cyclic `parentId` still renders and files hosts correctly - because
`groupTree.ts`'s `buildGroupTree` resolves the read side of exactly this case
to root: only the group whose OWN parent is missing or itself sits on the
cycle, never a descendant further down an otherwise-valid chain, which keeps
its place and its hosts. `applyRemote` (`src/modules/hosts/store.ts`) lands a
group landing with no reference check of its own, by design: a per-write
refusal on a landing would drop a record another device already holds.
`upsertGroup` leaves a landed bad edge alone too, for the same reason: it
validates a `parentId` only when a LOCAL write actually changes that edge, so
a rename or a sub-group creation elsewhere in the tree is never refused for a
chain this device did not create.

**Carried by.** `groupTree.ts`'s `buildGroupTree`/`effectiveParents` (the read
side), and `src/modules/hosts/store.ts`'s `applyRemote` (the landing side,
which runs no cycle check on purpose) and `upsertGroup` (the local-write
side, which checks only a changing edge).

**Trigger.** Cross-record awareness added to `merge` in `model.rs` - at which
point a landed cycle could be refused or resolved at merge time instead of
being tolerated at every later read.

### Importing a pre-nesting backup moves every group it names back to root

**Accepted state.** `orderGroupWrites`'s "file wins" rule rewrites every
incoming group's `parentId` to what `effectiveParents` resolves over the
combined `existing ∪ incoming` universe before any row is written. A backup
written before `HostGroup.parentId` existed carries no `parentId` field at
all on any of its rows, which is indistinguishable on the wire from an
ordinary root group - so importing one flattens every group it names back to
root, even one that is currently nested locally. Not fixable in code: there
is no way to tell "absent because pre-nesting" from "absent because root"
once the field has been read.

The same "file wins" replace, in `mergeGroups` this time, does the identical
thing to `defaultIdentityId`: a group matched by id AND name is taken from
the file WHOLE, so a backup written before this field existed - or one
where the default was simply never set - clears a live local default with
nothing. `resolveGroupDefaults` dropping a file default as dangling
(WRITE 3, against the identities that actually landed) has the same effect:
the drop overwrites whatever local default the group had, even a live one.
Not fixable for the same reason as the `parentId` case: there is no way to
tell "absent because the file predates the field" from "absent because the
group genuinely has no default" once the field has been read.

**Carried by.** `orderGroupWrites`, `mergeGroups`, `resolveGroupDefaults` and
`sanitizeGroup` in `src/modules/backup/file.ts`.

**Trigger.** A versioned backup format that can record "this group's parent
field / default identity was not written by this build" as distinct from
"this group is a root / has no default" - at which point an old file could
keep the local nesting or default instead of overwriting it.

## Host tags

### A tag has no managed record, so renaming or deleting one everywhere is not one action

**Accepted state.** `HostBase.tags` is free-form strings, normalised per host by
`normalizeHostTags` - there is no `HostTag` record the way `HostGroup` is one, and
so no place carrying a single spelling, a rename, or a delete that would reach
every host wearing that tag at once. Retyping "prod" to "production" on one host
leaves every other host still saying "prod"; deleting it from one host leaves it
on the rest. This is the group-record integrity work `HostGroup`'s collision
check, rename and delete-cascade already do, deliberately not built for tags:
adding, removing, filtering and searching a tag on a host is what was asked
for, not managing tags as records in their own right.

**Carried by.** `HostBase.tags` and `normalizeHostTags`
(`src/modules/hosts/types.ts`).

**Trigger.** A request for a managed tag list with rename-everywhere or
delete-everywhere, carrying the same collision/rename/delete-cascade work
`HostGroup` and `store.ts`'s `upsertGroup`/`deleteGroup` already do for groups.

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

### The command palette's `#` mode finds a saved host but cannot create one, and no check sees how it builds its rows

**Accepted state.** `#` in the Command Palette ranks saved hosts with the same
`rankHosts` over `searchRows` the header quick-connect uses. A query that
matches no saved host only shows "No matching host": the header's ad-hoc path,
where a parseable `user@host` opens the host editor prefilled, is not offered
there. Separately, `[two surfaces]` in `hosts-search-verify.ts` reads only
`HeaderQuickConnect.tsx` and `HostsPage.tsx`, so a palette that stopped calling
`searchRows` and mapped hosts by hand would drift from the header with no check
failing. Nothing in the suite mounts a component, so the palette's rows cannot
be checked by rendering them.

**Carried by.** `HostResults`' doc comment and the `rankedHosts` memo in
`CommandPalette.tsx`.

**Trigger.** A request for the header's create path from the palette: reuse
`parseAdHocTarget` and `requestHostEditor` as `HeaderQuickConnect`'s
`handleKeyDown` does, behind an `onOpenHostsPage` prop like the header's. For
the unchecked row assembly: a component-test harness landing, at which point
the palette's rows can be checked by rendering.

## Keychain and secrets

### The orphan sweep cannot see a legacy Windows credential, and on macOS it can see another install's

**Accepted state.** `secrets_list` enumerates the accounts stored under one
service, and the Vault page's unreferenced-entry sweep subtracts every account
the app's records name from what it answers. Two gaps in that enumeration are
accepted rather than closed.

On Windows it lists the DPAPI file store only. `legacy_keyring_get` still reads
pre-migration Credential Manager entries as a fallback, and the `keyring` crate
has no listing API, so a password-only credential written by an earlier build is
invisible to the sweep - it can still be read and used, and still cannot be
found by looking.

On macOS the enumeration is not scoped to one install, and that is the sharper
half. Linux and Windows resolve their store under `app_local_data_dir()`, so a
dev build and a release build cannot see each other's secrets at all. macOS
addresses the shared login keychain by a bare service string, so a dev build's
sweep enumerates a release install's `tervia-hosts::…` accounts, finds them in no
record of its own `.dev` store file, and offers to delete them. The confirm
dialog is the whole of what stands between that and a real loss, which is why
the sweep asks rather than running unattended.

**Carried by.** `secrets_list` and `keychain_accounts` in
`src-tauri/src/modules/secrets.rs`, and the confirm dialog in
`src/modules/vault/VaultPage.tsx`.

**Trigger.** A report of a dev build offering to delete a release install's
secrets, or a user finding a pre-migration Windows credential the sweep never
listed.

### A preference write costs a whole-file replacement

**Accepted state.** `tervia-settings.json` now goes through
`createRecoveredStore` like the other five store files, which means it lost the
200 ms autosave debounce the plugin store gave it: `src/lib/fileKeyValueStore.ts`
states that its replacement has no autosave, debounce or retry by design. Each
`writePref` is one whole-map `fs_write_file`, plus `snapshotAfterSave`'s read
and copy, plus two `emit`s. The map can legitimately hold two sound data URLs of
up to `MAX_SOUND_DATA_URL_LEN` characters each - roughly 1.5 MB apiece - so a
held Ctrl+= moves megabytes per keypress. Durability over throughput is the
trade this was made for; the number is what belongs on the record.

**Carried by.** `writePref` in `src/modules/settings/store.ts`, which commits
inside the port's write queue, and `commit` in `src/lib/recoveredStore.ts`.

**Trigger.** A measured stall while dragging a settings slider or holding a zoom
shortcut. The fix is a debounce at the setter, not in the store layer.

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

**Trigger.** A user report of a host offering a key it does not hold after a
recovery toast. The enumeration half of this is no longer pending - `secrets_list`
exists, and the Vault page's unreferenced-entry sweep uses it - but that names
accounts no record claims, which is the opposite direction and cannot tell that a
record naming a live account is stale.

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

**A remote holding no objects at all is the exception, and it is deliberate.**
The stale rule above reads "no object for this record" as "deleted elsewhere,
tombstone expired", and that reading needs a remote that once held the record.
A prefix with zero objects in it has never held any of them — a keyfile minted
seconds ago, a second provider being set up — and applying the rule there
withheld the entire inventory from the remote it had just been pointed at,
reporting nothing pending and no error while three quarters of the records were
absent. So `pull` lifts the rule when the listing comes back empty and every
local record is published. The cost is the resurrection above at its widest: a
remote whose records were all deleted more than 90 days ago, whose tombstones
have all been pruned, and a device that was away throughout, will refill it. The
user can delete again; the alternative was a sync that silently does not sync.

**Carried by.** `TOMBSTONE_TTL_MS` in `src/lib/tombstones.ts`, which is the
window, `livingTombstones` in the same file, which applies it on this side, the
`expired` clause in `pull` in `src-tauri/src/modules/sync/engine.rs`, which
applies it to the remote's copy, and `remote_is_empty` in the same function,
which is the exception.

**Trigger.** A device registry that can say when each device last pulled. The
window can then be derived from the oldest live device rather than guessed, and
this entry retires rather than being re-tuned.

### A mistyped WebDAV prefix presents as a fresh remote and takes a copy of the inventory

**Accepted state.** `classify_list` in
`src-tauri/src/modules/sync/providers/webdav.rs` maps a 404 to an empty listing,
because a prefix whose collections have not been created yet is exactly the
fresh-remote case and the first push is what creates them. Combined with the
empty-listing exception above, a prefix typed wrongly — under a base path the
server still answers on — therefore reads as a new remote and receives the whole
inventory, sealed, under a keyfile minted for it. Nothing is deleted and nothing
leaves the user's own server; the cost is a second copy in a place they did not
mean, and a second sync root that does not converge with the first. It is the
same typo hazard as a prefix that mints an unwanted keyfile, one step wider.

**Carried by.** `classify_list` in `providers/webdav.rs`, and `remote_is_empty`
in `pull` in `src-tauri/src/modules/sync/engine.rs`.

**Trigger.** A confirmation in the settings surface when a Save is about to mint
a keyfile at a prefix that holds none — which is the same prompt this and the
unwanted-keyfile hazard both want, and is worth building once.

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
naming a key that is gone, a row whose jump host vanished, or a group naming a
deleted identity as its default.

**Carried by.** The `applyRemote` doc on each of the three stores, which states
it beside the two cascades that are deliberately not re-run. The local refusals
are `identitiesUsingKey` in `src/modules/vault/refs.ts`, the `hostRefs` argument
to `deleteIdentity`, and the `VaultInUseError` branch of `deleteHost` in
`src/modules/hosts/store.ts`. A group's own dangling default is the read-time
tolerance in `defaultIdentityFor` (`src/modules/hosts/groupTree.ts`), which
skips it and falls through to a live ancestor's rather than surfacing it as a
holder to recover.

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

### A vault record's last-connected stamp is not restored by a backup import, and a forward-only tunnel sets none

**Accepted state.** A backup export seals the raw identity and key records, so
it carries their `lastConnectedAt`. The import drops it, and the vault store
never takes the stamp from a caller, so an identity or key the import creates
starts with no recency. One this device already holds keeps its own stamp, and a
restored host keeps its own too. A forward-only tunnel - including the SSH
tunnel under an RDP host - stamps neither its bastion host nor that host's
identity.

Accepted because the stamp is this device's history, not record content: it
orders the Vault page and labels its cards, and nothing connects differently
without it. The next connect through each identity puts it back.

**Carried by.** `markIdentityConnected` and the four record literals in
`src/modules/vault/store.ts` that carry `existing?.lastConnectedAt`;
`sanitizeIdentity` and `sanitizeKey` in `src/modules/backup/file.ts`; and
`markConnected` in `src/modules/hosts/store.ts`, which `src/modules/ssh/tunnel.ts`
never calls.

**Trigger.** A user asking a restored vault to keep its recency, or a forward
being counted as a use of its bastion.

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

## RDP

### EGFX/H.264 cannot be reached from the pinned connector, and moving the pins does not change that

**Accepted state.** An RDP desktop is painted from RemoteFX and raw bitmap
updates. The Graphics Pipeline Extension, and with it H.264, is not used, and
adding the channel handler would not change that. A server opens the graphics
channel only when the client sets the graphics-pipeline bit in the early
capability flags of its client core data; the pinned connector never sets that
bit, and its configuration struct exposes no field that would
(`ironrdp-connector` 0.9.0, `Config`). A handler would sit registered on a
channel nothing ever opens.

**Carried by.** The connector configuration `build_config` returns, and the
static-channel registration beside it in `src-tauri/src/modules/rdp/session.rs`,
which registers a `DrdynvcClient` carrying only `DisplayControlClient`. The bit
itself is defined, and unused, by the pinned PDU crate (`ironrdp-pdu` 0.8.0,
`ClientEarlyCapabilityFlags`).

Worth stating precisely, because the obvious next move is the wrong one. The
newest PUBLISHED connector does not set the bit either, so bumping the ironrdp
pins one minor - the expensive change whose resolution constraints the comment
block in `src-tauri/Cargo.toml` works out - buys nothing here. The field that
would set it exists only on IronRDP's main branch, and as a breaking change, so
it can only arrive in a connector minor that has not been released
(IronRDP #1237).

**Trigger.** A published connector whose configuration carries the
graphics-pipeline early-capability field. That same release also has to move
picky off the candidate version this repository's russh pin cannot co-resolve
with, or the pins still cannot move and the field cannot be reached; the comment
block in `src-tauri/Cargo.toml` is where that half is worked out. Both
conditions, not either.

When both hold, the handler is an addition rather than a port: the EGFX client
crate is a dynamic-channel processor, so it registers beside
`DisplayControlClient` on the existing `DrdynvcClient`, and it hands a consumer
RGBA rectangles that `FrameBatcher` in `src-tauri/src/modules/rdp/frame.rs`
already coalesces and ships. Its H.264 decoder is a trait the consumer supplies,
and the compile-from-C-source option for that decoder is already ruled out: it
needs NASM on Windows, which is the exact dependency the `ironrdp-tls`
rustls-ring feature and the russh ring feature both exist to avoid. Loading a
prebuilt library at runtime is the only option compatible with the pins above.

### A panic in an RDP session kills the app, because the release profile cannot unwind

**Accepted state.** The session task has no `catch_unwind` boundary, so a panic
anywhere in the active-stage loop - a decoder, a PDU parser, an arithmetic
overflow - takes the whole process down, every other tab with it. Adding the
boundary would change nothing while `[profile.release] panic = "abort"` stands
(`src-tauri/Cargo.toml`): under abort there is no unwinding to catch, so the
`catch_unwind` is dead code in exactly the build that matters.

**Carried by.** `panic = "abort"` in `src-tauri/Cargo.toml`, and the session
task spawned in `connect` in `src-tauri/src/modules/rdp/session.rs`.

The module avoids the usual sources rather than relying on the boundary it does
not have. Its production code contains no `as` numeric cast, and it does not
use `DecodedImage::data_for_rect`, which underflows at height 0 and slices out
of bounds past the framebuffer (`ironrdp-session` 0.10.0, `image.rs`). What is
left is the decode path inside the dependency, and that one is unlinted: the
crate sets `#![allow(clippy::arithmetic_side_effects)]` at its root, marked
`FIXME: remove`. The clipboard callbacks in
`src-tauri/src/modules/rdp/cliprdr.rs` now parse hostile server input on that
same task: a `FormatDataResponse`'s length and its DIB headers are both
attacker-chosen, and both are capped and decoded through
`ironrdp-cliprdr-format`, which returns errors rather than panicking - but they
sit inside this boundary's absence like everything else on the loop.

**Trigger.** A decision to accept unwinding tables in the release binary. That
is one profile line plus an `AssertUnwindSafe(...).catch_unwind()` around `run`,
emitting `error` then `disconnected` and leaving the janitor to evict the id -
everything the panic would unwind past is dropped with the session, and
`lock_or_recover` already recovers a poisoned guard, so there is no half-state
to reason about. Until then a parser panic takes every tab with it.

### A copy made without leaving the RDP pane is never advertised

**Accepted state.** The host clipboard is read on a pane focus EDGE and nowhere
else, so a global-hotkey clipboard manager - or any other application that
writes the clipboard while the pane still holds focus - changes it with nothing
to notice. A paste inside the remote then serves whatever the last focus-in
saw. The next focus edge picks it up, so the content is late rather than lost.

**Carried by.** The focus effect in `src/modules/rdp/RdpPane.tsx` and
`RdpSession::clipboard_focus` in `src-tauri/src/modules/rdp/session.rs`.

**Trigger.** A native clipboard-change listener that does not cost three
per-platform backends. There is no Tauri clipboard event
(tauri-apps/tauri#5746, closed not-planned), and polling buys an X11 round trip
per tick for a signal that is idle almost always - so this waits on an upstream
notification API, not on effort here.

### A remote-to-host paste is one round trip behind

**Accepted state.** The remote's clipboard is fetched on blur, so a user who
switches away and pastes inside that same window gets the previous clipboard
content. Text is kilobytes and the window is one PDU round trip, so this is
small; it is not zero, and a large image makes it visible.

**Carried by.** The `SendInitiatePaste` send in `RdpSession::clipboard_focus`
(`src-tauri/src/modules/rdp/session.rs`).

**Trigger.** A report of a paste landing stale in ordinary use. The fix is to
fetch eagerly from `on_remote_copy` in
`src-tauri/src/modules/rdp/cliprdr.rs` - the same single call site - which
costs every copy made inside the remote on the wire whether or not anybody
pastes it, which in a remote desktop is most of them.

### A large clipboard transfer head-of-line blocks the RDP graphics path

**Accepted state.** `ironrdp-svc` fragments outbound SVC data itself, so
chunking is not ours - but the resulting `ResponseFrame` is still one
`framed.write_all(..).await` on the task that also serves frames, up to
`MAX_CLIPBOARD_BYTES` (32 MiB) per transfer, and the same on inbound
reassembly. The desktop visibly stalls for the duration of a large image copy.

**Carried by.** The `Wake::Clipboard` arm and the `for output in outputs`
write in `run` (`src-tauri/src/modules/rdp/session.rs`).

**Trigger.** A measured stall long enough to matter in ordinary use. Fixing it
means moving clipboard writes off the session task, which is a second writer on
the same `Framed` - and `write_all` is not cancel-safe, so that is a structural
change rather than a line.

### The connector's `Credentials` holds the RDP password as an unscrubbed `String`

**Accepted state.** `ironrdp_connector::Credentials::UsernamePassword` declares
`password: String` with no `Zeroize` bound and no constructor that would take
one, so `build_config` copies the plaintext into the connector's `Config`, where
it lives for the whole connect and is dropped unscrubbed. Everything from
CredSSP outward is already safe - `sspi::AuthIdentity.password` is a
`Secret<String>` and `Secret<T>` is `ZeroizeOnDrop` - and Tervia's own copy is a
`Zeroizing<String>`, so this one field is the whole gap.

**Carried by.** `build_config` and `connect` in
`src-tauri/src/modules/rdp/session.rs`.

**Trigger.** An `ironrdp-connector` release whose `Credentials::UsernamePassword`
carries a zeroizing password type; the pinned `=0.9.0` in
`src-tauri/Cargo.toml` moves with it.

## Workspaces

### A workspace file still names a leaf's host `sshConnectionId`

**Accepted state.** In memory a terminal or editor leaf's saved-host
reference is `hostId`. On disk it is still written and read under the older
key `sshConnectionId`, mapped between the two spellings on every save and
restore. Renaming the on-disk key too would need a read-time fallback kept
forever (every workspace file written by an earlier build carries the old
key) and risks a downgraded build reading a renamed key and restoring a
remote editor leaf as a LOCAL one - the exact hazard
`isUnrestorableEditorLeaf` exists to prevent. Zero migration, zero data risk,
at the cost of one name mismatch between memory and disk.

**Carried by.** `SavedTerminalLeaf` and `SavedEditorLeaf` in
`src/modules/workspaces/store.ts`, and the `leafToSaved` / `savedToNode`
mapping in `src/modules/workspaces/serialize.ts`.

**Trigger.** A workspace-file migration pass landing for some other reason -
at that point the saved key can move to `hostId` alongside it.

## SSH sessions

### Every tab to one host is a channel on one session, so the server's `MaxSessions` caps concurrent tabs

**Accepted state.** Every terminal tab to a saved host opens one more shell
channel on that host's single session, shared with its forwards and RDP panes.
OpenSSH's `MaxSessions` (default 10) counts every session channel on one
connection, the SFTP subsystem and each `ssh_git` exec included, so past it the
next tab's `ssh_shell_open` fails with "ssh: open channel failed", walks the
reconnect ladder and parks. [INFERENCE] Not exercised against a server at the
limit.

**Carried by.** The `ponytail:` comment above `openShellForConnection` in
`src/modules/ssh/tunnel.ts`.

**Trigger.** A user reaching the limit. The upgrade is to dial a dedicated
session for the tab when the shared one refuses the channel.

### A host edit reaches its terminals only once every reference to the old session is released

**Accepted state.** A new tab, or a reconnect where only the shell ended, joins
the host's live session, which was dialled with the user, port, credential and
jump chain in force at dial time. The terminal's pre-flight still re-reads the
host for its banner and route, so after an edit those can name the new endpoint
while the shell rides the old session. Once every tab, forward and RDP pane on
the host lets go, the next open re-dials with the edit.

**Carried by.** `sessionFor` in `src/modules/ssh/tunnel.ts`, which keys the
shared session by connection id alone.

**Trigger.** A report of an edit that did not seem to apply. The fix is to
compare the dial inputs in `sessionFor` and refuse to join on a mismatch.

## Forwards

### `-R`/`-D` rules do not autostart with their host

**Accepted state.** `startWithHost` brings a `-L` rule up on the terminal's
shared live SSH session through `AutostartDeps.openForward`, which binds a LOCAL
listener and speaks a fixed `(id, localPort, remoteHost, remotePort)` shape.
Neither a `-R` rule (which needs `Handle::tcpip_forward` on the SERVER, not a
local bind) nor a `-D` rule (which needs a SOCKS5 listener, not a fixed dial
target) fits that shape, so `startHostForwards` skips a rule carrying either
type with a banner rather than forcing it through a call that does not mean
what it asks for. Such a rule still starts from the Port Forwarding page.

**Carried by.** `typedAutostartSkippedBanner` and the `if (rule.type)` guard
at the top of `startHostForwards`'s loop, both in
`src/modules/forwards/autostart.ts`.

**Trigger.** `AutostartDeps` growing a second dial shape (or one call each for
`-R`/`-D`) that the terminal's shared session can drive the same way it
drives `-L`'s today.

### `RuntimeDeps` cannot drive a `-R`/`-D` Start or Stop through a fake

**Accepted state.** `controller.ts`'s `startRule`/`stopRule` read `-L`'s dial
through `RuntimeDeps.openForward`/`closeForward`, which a check can replace
with a fake with no Tauri bridge - see that file's own header. `-R`/`-D` ride
a separate branch (`startTypedRule`, and one `if`/`else` in `stopRule`'s close
call) that calls `@/modules/ssh/tunnel`'s `openRemoteForwardForConnection`/
`openSocksForConnection` directly, because nothing in this codebase drives
either type through a fake yet. A check exercising `-R`/`-D` `startRule`/
`stopRule` behaviour today would need the real Tauri bridge.

**Carried by.** `startTypedRule` in `src/modules/forwards/controller.ts`, and
the type it does NOT add to `RuntimeDeps`.

**Trigger.** A test needing to drive a `-R`/`-D` Start/Stop without a live
Tauri bridge - at that point `RuntimeDeps` gains the matching keys the way it
already has `openForward`/`closeForward`.

### A `-R` rule's routing registry is keyed by port alone, not `(address, port)`

**Accepted state.** `SshSession`'s `remote_forwards` registry
(`src-tauri/src/modules/ssh/session.rs`) maps a bound SERVER port straight to
the local target it dials, dropping the bind address `tcpip_forward` was
asked for. This is sound today: a server can bind one port only once, so once
`open_remote_forward` has the port it actually bound, that port is already a
unique key - the compound key would add a dimension nothing currently needs.
It would stop being sound only for a server that can bind the SAME port on
two different addresses at once and route by address, which is not how
`GatewayPorts no`'s ordinary loopback-only posture behaves.

**Carried by.** `RemoteForwardTargets`'s own doc comment in
`src-tauri/src/modules/ssh/session.rs`, directly above the type alias.

**Trigger.** A server-side forwarding mode this app starts supporting where
one port is legitimately bound on more than one address within a single
session.

### A `startWithApp` rule's mid-session drop does not re-enter the backoff ladder

**Accepted state.** `controller.ts`'s `startForwardAutostart`
ladders a `startWithApp` rule's INITIAL bind failure, and any retry's own
failure, but not a session that drops AFTER a successful bind. `ssh/tunnel.ts`'s
`dropSession` is the single function both a deliberate release
(`releaseSession` at zero refs, e.g. a manual Stop of the last rule on a host)
and an unexpected drop (`dialSession`'s `onClosed`) call, and nothing
subscribes to it. The two are already told apart upstream: `ssh_open`'s janitor
sends the session channel's `disconnected` only for a connection that ended on
its own, never after `ssh_close`, because `ssh_close` removes the id before the
janitor looks. What is missing is the subscriber. A `startWithApp` rule whose
bastion drops mid-session stays "Running" (stale) until a manual Stop/Start,
the same status quo every OTHER page-started rule already has - this does not
regress it.

**Carried by.** `dropSession` in `src/modules/ssh/tunnel.ts`, which has no
subscriber-notification hook today.

**Trigger.** `tunnel.ts` gaining a per-connection drop subscription, fed from
`onClosed`, that a check can prove - at that point `startForwardAutostart` can
subscribe per `hostId` and re-enter the ladder on a genuine drop.

### A remote edit landing while its retry is pending re-dials the OLD endpoints

**Accepted state.** `attemptForwardAutostart` deliberately reuses the SAME
`rule` object across every rung of its own backoff ladder (`controller.ts`'s
"REUSES THE SAME `rule` OBJECT" doc on that function) - a Stop, Delete or
Save cancels the ladder outright (`pageMustStopFirst`'s `forwardRetries.has`
check), but a sync LANDING that only _rewrites_ the rule's record does not:
`sync/scheduler.ts`'s landing-side `release` hands `releaseRule` only
DELETED landings, so an edit that lands elsewhere - a renamed target, a
changed port - never reaches the cancel at all. If that edit lands during
one of the ladder's waits (up to 30 s), the timer that fires next still
dials the OLD endpoints captured when the ladder started. The row then
reads `Running` for the NEW record, and its Stop names a key nothing is
stored under - the same leak P0-1 fixed for Delete and Edit, arriving
through the sync door instead of a click. The window is narrow (a landing
has to arrive during an in-flight wait, not merely at any point after the
edit), and the same class of leak already exists on the base for a page-
`running` rule a landing rewrites, so this is not a new hazard, only a new
way to reach an old one.

**Carried by.** `attemptForwardAutostart` in
`src/modules/forwards/controller.ts`, which has no subscription to a sync
landing to cancel itself against.

**Trigger.** `sync/scheduler.ts`'s landing-side release growing a REWRITE
case (not only a delete) that cancels a rule's pending retry the same way
`stopRule` already does - at that point this entry can close alongside the
mid-session-drop one above, since both need the same kind of landing
subscription.

### A local forward-bind conflict walks the ladder before parking

**Accepted state.** `controller.ts`'s backoff ladder classifies a
Start failure through `classifySshConnectFailure`, which files anything that
is not `SshLocalConnectError`/`SshAuthRejectedError` as `"transport"`
(retry-eligible). `ssh_open`'s own rejection is structured
(`SshConnectError { kind, message }`, `src-tauri/src/modules/ssh/session.rs`)
and wrapped into one of those two classes by `sshConnectErrorFrom`
(`src/modules/ssh/bridge.ts`) before it reaches the classifier.
`ssh_forward_open`/`ssh_remote_forward_open`/`ssh_socks_open`
(`src-tauri/src/modules/ssh/mod.rs`) do not: each rejects with a bare
`String`, so a LOCAL bind conflict (the port this rule pins is already taken
on this machine) and the session dying between the connect and the bind are
indistinguishable on the wire. The ladder is bounded and self-terminating -
the first attempt plus the ladder's 5 retries, then the row parks `failed`
with the last error - so a doomed pinned-port rule wastes that span once rather than
being recognised on the first attempt; it does not retry forever.

**Carried by.** `attemptForwardAutostart` in
`src/modules/forwards/controller.ts`, which has no third classification to
read this apart with.

**Trigger.** Giving `ssh_forward_open`/`ssh_remote_forward_open`/
`ssh_socks_open` a structured error boundary mirroring `SshConnectError` - a
Rust-side change, proportionate only once something besides this bounded
ladder needs the distinction too.

## Known Hosts

### The Known Hosts page's Forget button has no "every device" option

**Accepted state.** `KnownHostsPage.tsx`'s Forget button revokes a pin on
THIS device only, and offers no choice, because there is nothing else to
revoke: `DEVICE_LOCAL_FIELDS` (`src/modules/sync/envelope.ts`, mirrored in
`src-tauri/src/modules/sync/model.rs`) already strips `pins` from every
record before it leaves the device, so a pin never exists anywhere else to
be cleared. The page's own copy line says this rather than leaving a reader
to infer it from what the button does not offer.

**Carried by.** `KnownHostsPage.tsx`'s copy paragraph, and `DEVICE_LOCAL_FIELDS`
in `src/modules/sync/envelope.ts` / `src-tauri/src/modules/sync/model.rs`.

**Trigger.** Pins becoming synced content - at which point this entry and
the copy line both need to be re-decided together, not just the field list.

### Nothing mounts KnownHostsPage, so its Forget wiring and copy are source-pinned only

**Accepted state.** `scripts/hosts-store-verify.ts` proves `forgetPin` itself -
what it removes, what it leaves alone, its no-op cases - and
`scripts/rail-views-verify.ts` proves the page is wired in as a rail view.
Neither mounts `KnownHostsPage.tsx`, so nothing asserts that its Forget
button's `onClick` actually calls `forgetPin` with the row's own address, that
the accessible label really names the host and address on screen, or that the
empty-state and device-local copy render at all. The same gap the "Vault
editors" entry above already carries for a different page.

**Carried by.** `KnownHostsPage.tsx` itself - there is no file that checks it.

**Trigger.** A component test runner existing in this repository, able to
mount a rail view and assert on its rendered text and click handlers.
