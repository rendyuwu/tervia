/**
 * Self-check for the vault editors' pure layer.
 * Run: `pnpm verify vault-draft` (or `npx tsx scripts/vault-draft-verify.ts` to iterate).
 *
 * `src/modules/vault/editor/draft.ts` is pure - no React, no store, no Tauri,
 * no keychain read - which is the only reason this file can exist, the same
 * argument `vault-page-verify.ts`'s own header makes for `page/derive.ts`. It
 * is imported by both vault editor dialogs, `HostEditorDialog.tsx`,
 * `credentialMove.ts` and `editor/credentialChoice.ts`.
 *
 * Modelled on `vault-page-verify.ts`: same `canonical()` (JSON is key-order
 * sensitive and drops `undefined` keys, and both matter here - `keyId: undefined`
 * must read differently from a `want` that simply omits the key), same
 * `check`/`ok` pair, fixtures, numbered sections, and a mutation table at the
 * tail recording every mutation actually run against this file. Copied rather
 * than imported: there is no `scripts/lib`, and every script in this suite
 * duplicates these.
 *
 * Section 10 reaches OUTSIDE `draft.ts` - to `vault/types.ts`, `vault/refs.ts`,
 * `vault/keyInspect.ts` and `backup/file.ts` - and says why in its own comment.
 * All four are pure in the same sense `draft.ts` is, so nothing about that
 * section needs a runtime this file does not have.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { sanitizeKey } from "../src/modules/backup/file";
import {
  vaultKeyFactsFrom,
  type KeyInspectResult,
  type VaultKeyFacts,
} from "../src/modules/vault/keyInspect";
import { keyMissingSecret, keyNeedsPassphrase } from "../src/modules/vault/refs";
import {
  EMPTY_IDENTITY_DRAFT,
  EMPTY_KEY_DRAFT,
  encryptedKeyRefusal,
  identityPasswordHelp,
  identityRecordFrom,
  identitySecretsForSave,
  keyRecordFrom,
  keySecretsForSave,
  passphraseHelp,
  privateKeyHelp,
  validateIdentityDraft,
  validateKeyDraft,
  type IdentityDraft,
  type KeyDraft,
} from "../src/modules/vault/editor/draft";
import { vaultKeyStamp, type VaultKey } from "../src/modules/vault/types";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(join(root, p), "utf8");

let failed = 0;

/**
 * JSON with object keys SORTED, and `undefined` values kept. See
 * `vault-page-verify.ts`'s helper of the same name for the full reasoning:
 * `JSON.stringify` is key-order sensitive and drops `undefined` keys, and this
 * file cares about both.
 */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const body = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
      .join(",");
    return `{${body}}`;
  }
  return value === undefined ? "undefined" : JSON.stringify(value);
}

function check(label: string, got: unknown, want: unknown): void {
  const g = canonical(got);
  const w = canonical(want);
  if (g === w) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${g}, want ${w}`);
    failed++;
  }
}
function ok(label: string, cond: boolean): void {
  if (cond) console.log(`  ok: ${label}`);
  else {
    console.error(`  FAIL: ${label}`);
    failed++;
  }
}

// --- fixtures -------------------------------------------------------------

function identityDraft(over: Partial<IdentityDraft> = {}): IdentityDraft {
  return { ...EMPTY_IDENTITY_DRAFT, name: "rendy", username: "rendy", ...over };
}

function keyDraft(over: Partial<KeyDraft> = {}): KeyDraft {
  return { ...EMPTY_KEY_DRAFT, name: "id_ed25519", ...over };
}

function existingKey(over: Partial<VaultKey> = {}): VaultKey {
  return {
    id: "k-1",
    name: "id_ed25519",
    keyType: "rsa",
    fingerprint: "SHA256:old",
    publicKey: "ssh-rsa AAAAold",
    hasPrivateKey: true,
    hasPassphrase: true,
    ...over,
  };
}

function keyInspectResult(over: Partial<KeyInspectResult> = {}): KeyInspectResult {
  return {
    parsed: true,
    encrypted: false,
    keyType: "ssh-ed25519",
    fingerprint: "SHA256:x",
    publicKey: "ssh-ed25519 A",
    comment: null,
    ...over,
  };
}

// --- 1. vaultKeyFactsFrom, again from the other side -----------------------
console.log(
  "[1] vaultKeyFactsFrom - the present-with-undefined shape keyRecordFrom's spread depends on",
);
{
  check(
    "a parsed answer produces exactly the four keys, present, undefined included where absent",
    vaultKeyFactsFrom(keyInspectResult()),
    {
      keyType: "ed25519",
      fingerprint: "SHA256:x",
      publicKey: "ssh-ed25519 A",
      encrypted: false,
    },
  );
  // `encrypted: false` above is PRESENT, and this is the row that says so
  // rather than leaving it to `canonical`'s treatment of a missing key: absent
  // means "no inspection has answered this" on `VaultKey.encrypted`, and the
  // wholesale replace below is what would otherwise leave a stale `true`
  // standing over a body that is no longer encrypted.
  ok(
    "and the fourth key is present even when it is false, not omitted",
    "encrypted" in vaultKeyFactsFrom(keyInspectResult({ encrypted: false })),
  );
}

// --- 2. identityRecordFrom - the keyId rule, literal per row ----------------
console.log("\n[2] identityRecordFrom - keyId is written ONLY when authMode is 'key'");
{
  check(
    "key auth names the chosen key",
    identityRecordFrom("i-1", identityDraft({ authMode: "key", keyId: "k-1" })),
    {
      id: "i-1",
      name: "rendy",
      username: "rendy",
      domain: undefined,
      authMode: "key",
      hasPassword: false,
      keyId: "k-1",
      description: undefined,
    },
  );
  check(
    "password auth drops a key still sitting in the draft",
    identityRecordFrom("i-1", identityDraft({ authMode: "password", keyId: "k-1" })),
    {
      id: "i-1",
      name: "rendy",
      username: "rendy",
      domain: undefined,
      authMode: "password",
      hasPassword: false,
      keyId: undefined,
      description: undefined,
    },
  );
  check(
    "agent auth drops a key still sitting in the draft",
    identityRecordFrom("i-1", identityDraft({ authMode: "agent", keyId: "k-1" })),
    {
      id: "i-1",
      name: "rendy",
      username: "rendy",
      domain: undefined,
      authMode: "agent",
      hasPassword: false,
      keyId: undefined,
      description: undefined,
    },
  );
  check(
    "key auth with no key chosen writes keyId as the empty string - validateIdentityDraft refuses this before it is reached, asserted anyway so the two rules are not conflated",
    identityRecordFrom("i-1", identityDraft({ authMode: "key", keyId: "" })),
    {
      id: "i-1",
      name: "rendy",
      username: "rendy",
      domain: undefined,
      authMode: "key",
      hasPassword: false,
      keyId: "",
      description: undefined,
    },
  );

  check(
    "a whitespace-only domain becomes undefined, not a blank string",
    identityRecordFrom("i-1", identityDraft({ domain: "  " })).domain,
    undefined,
  );
  check(
    "the name is trimmed",
    identityRecordFrom("i-1", identityDraft({ name: "  a  " })).name,
    "a",
  );
  ok(
    "hasPassword is always false - it is a placeholder upsertIdentity overwrites",
    identityRecordFrom("i-1", identityDraft({ authMode: "key", keyId: "k-1" })).hasPassword ===
      false,
  );
}

// --- 2b. identityRecordFrom's ONE opt-out, "keep" ---------------------------
console.log('\n[2b] identityRecordFrom("keep") - the documented opt-out, and its default');
{
  // `"keep"` exists for exactly one caller: `convertHostToVault`
  // (`../../hosts/credentialMove.ts`), which mints a `VaultKey` out of a stored
  // host's PEM and then has to leave something naming it - `deleteKey`'s in-use
  // guard finds holders by `identity.keyId`, so a key nothing names is one Vault
  // page click from destroyed. That is worse than the off-spec record - a
  // password-auth identity that still names a key - so `"keep"` builds the
  // off-spec one.
  //
  // The opt-out lives HERE rather than as a hand-assembled `VaultIdentity` at
  // that call site, because this function is the single normaliser for that
  // rule and a second assembly is the drift it prevents.
  // `credential-move-verify.ts` sections 4 and 4b are where the caller's own use
  // of it is pinned; these rows are the rule itself.
  check(
    'password auth KEEPS the draft\'s key under "keep" - the exact row section 2 drops',
    identityRecordFrom("i-1", identityDraft({ authMode: "password", keyId: "k-1" }), "keep"),
    {
      id: "i-1",
      name: "rendy",
      username: "rendy",
      domain: undefined,
      authMode: "password",
      hasPassword: false,
      keyId: "k-1",
      description: undefined,
    },
  );
  check(
    'agent auth keeps it too under "keep"',
    identityRecordFrom("i-1", identityDraft({ authMode: "agent", keyId: "k-1" }), "keep").keyId,
    "k-1",
  );
  check(
    'key auth is unchanged by "keep" - it named the key either way',
    identityRecordFrom("i-1", identityDraft({ authMode: "key", keyId: "k-1" }), "keep").keyId,
    "k-1",
  );
  // The one place the two rules disagree in the OTHER direction. `"auth-mode"`
  // writes a blank `keyId` straight through on key auth (section 2's fourth row,
  // where `validateIdentityDraft` is the guard); `"keep"` cannot, because its
  // caller passes `keyId ?? ""` and an identity naming the empty string names
  // nothing - `upsertIdentity`'s dangling-key refusal reads `identity.keyId` as
  // falsy and lets it through, so the blank would persist onto the record.
  check(
    'a blank keyId becomes undefined under "keep", never the empty string',
    identityRecordFrom("i-1", identityDraft({ authMode: "password", keyId: "" }), "keep").keyId,
    undefined,
  );
  check(
    'and a blank keyId is still written through on key auth under "auth-mode" - the two rules are not conflated',
    identityRecordFrom("i-1", identityDraft({ authMode: "key", keyId: "" }), "auth-mode").keyId,
    "",
  );
  // THE DEFAULT IS THE SAFE ONE. A caller that says nothing gets the drop rule;
  // the opt-out has to be asked for by name. Checked as an equality between the
  // two-argument and the explicit three-argument call, so this cannot pass by
  // the default silently becoming "keep" - the row above would fail, and so
  // would this one.
  ok(
    'omitting the third argument is exactly "auth-mode", on the row where the two differ',
    canonical(identityRecordFrom("i-1", identityDraft({ authMode: "password", keyId: "k-1" }))) ===
      canonical(
        identityRecordFrom(
          "i-1",
          identityDraft({ authMode: "password", keyId: "k-1" }),
          "auth-mode",
        ),
      ),
  );
  check(
    "and that default drops the key, so the equality above is not between two copies of the opt-out",
    identityRecordFrom("i-1", identityDraft({ authMode: "password", keyId: "k-1" })).keyId,
    undefined,
  );
}

// --- 3. identitySecretsForSave ----------------------------------------------
console.log("\n[3] identitySecretsForSave - blank is omitted, never sent as a delete");
{
  check(
    "an empty password is omitted",
    identitySecretsForSave(identityDraft({ password: "" })),
    {},
  );
  check(
    "a whitespace-only password is also omitted",
    identitySecretsForSave(identityDraft({ password: "   " })),
    {},
  );
  check(
    "a typed password is sent",
    identitySecretsForSave(identityDraft({ password: "hunter2" })),
    { password: "hunter2" },
  );
  check(
    "sent untrimmed - writeSecret trims before it decides, so trimming again here would only move the decision",
    identitySecretsForSave(identityDraft({ password: " hunter2 " })),
    { password: " hunter2 " },
  );
}

// --- 4. validateIdentityDraft ------------------------------------------------
console.log("\n[4] validateIdentityDraft");
{
  check(
    "a blank name is refused",
    validateIdentityDraft(identityDraft({ name: "" })),
    "Name is required",
  );
  check(
    "a blank username is refused",
    validateIdentityDraft(identityDraft({ username: "" })),
    "Username is required",
  );
  check(
    "key auth with no key chosen is refused",
    validateIdentityDraft(identityDraft({ authMode: "key", keyId: "" })),
    "Choose a key for key authentication",
  );
  check(
    "key auth with a key chosen passes",
    validateIdentityDraft(identityDraft({ authMode: "key", keyId: "k-1" })),
    null,
  );
  check(
    "password auth with a blank password passes - the row that makes 'missingSecret' reachable",
    validateIdentityDraft(identityDraft({ authMode: "password", password: "" })),
    null,
  );
}

// --- 5. keyRecordFrom --------------------------------------------------------
console.log(
  "\n[5] keyRecordFrom - facts null carries the old facts forward, facts present replaces wholesale",
);
{
  const existing = existingKey();
  check(
    "facts === null carries all four existing facts forward unchanged",
    keyRecordFrom("k-1", keyDraft(), existing, null),
    {
      id: "k-1",
      name: "id_ed25519",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
      keyType: "rsa",
      fingerprint: "SHA256:old",
      publicKey: "ssh-rsa AAAAold",
      encrypted: undefined,
    },
  );
  // The carry-forward, on the fact a rename must not drop. A save that only
  // renames the key passes `facts === null`, and an `encrypted: true` lost
  // there turns "an inspection found this body encrypted" back into "nobody has
  // looked" - the record silently forgetting the one thing that says the stored
  // key needs a passphrase it does not have. Both directions, because carrying
  // only `true` would be a rule about a value rather than about the field.
  check(
    "an existing encrypted: true survives a facts === null save",
    keyRecordFrom("k-1", keyDraft(), existingKey({ encrypted: true }), null).encrypted,
    true,
  );
  check(
    "and so does an existing encrypted: false, rather than degrading to absent",
    keyRecordFrom("k-1", keyDraft(), existingKey({ encrypted: false }), null).encrypted,
    false,
  );

  const freshFacts = vaultKeyFactsFrom(keyInspectResult());
  check(
    "fresh facts over an existing key REPLACE all four wholesale",
    keyRecordFrom("k-1", keyDraft(), existing, freshFacts),
    {
      id: "k-1",
      name: "id_ed25519",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
      keyType: "ed25519",
      fingerprint: "SHA256:x",
      publicKey: "ssh-ed25519 A",
      encrypted: false,
    },
  );
  // The replace direction that matters: an encrypted body pasted over a key
  // recorded as unencrypted has to leave the record saying `true`.
  check(
    "a newly pasted ENCRYPTED body replaces a stored encrypted: false with true",
    keyRecordFrom(
      "k-1",
      keyDraft(),
      existingKey({ encrypted: false }),
      vaultKeyFactsFrom(keyInspectResult({ encrypted: true })),
    ).encrypted,
    true,
  );

  const sealedFacts = vaultKeyFactsFrom(keyInspectResult({ parsed: false, encrypted: true }));
  check(
    "a sealed container's facts over an existing key leave the other three ABSENT and carry the encryption fact",
    keyRecordFrom("k-1", keyDraft(), existing, sealedFacts),
    {
      id: "k-1",
      name: "id_ed25519",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
      encrypted: true,
    },
  );

  check(
    "a create (no existing key) with fresh facts writes the facts plus the two false placeholders",
    keyRecordFrom("k-2", keyDraft(), null, freshFacts),
    {
      id: "k-2",
      name: "id_ed25519",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
      keyType: "ed25519",
      fingerprint: "SHA256:x",
      publicKey: "ssh-ed25519 A",
      encrypted: false,
    },
  );
  // A create from a SEALED container: nothing to carry forward, so the record
  // says only what the container answered. `encrypted: true` with no
  // fingerprint is the honest shape, and it is the row `keyNeedsPassphrase`
  // then reads in section 10.
  check(
    "a create from a sealed container records the encryption fact and nothing else about the key",
    keyRecordFrom("k-2", keyDraft(), null, sealedFacts),
    {
      id: "k-2",
      name: "id_ed25519",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
      encrypted: true,
    },
  );
}

// --- 6. keySecretsForSave -----------------------------------------------------
console.log("\n[6] keySecretsForSave - the ONE place this editor sends a delete");
{
  check(
    "blank body + blank passphrase: nothing sent",
    keySecretsForSave(keyDraft({ privateKey: "", passphrase: "" })),
    {},
  );
  check(
    "blank body + typed passphrase: only the passphrase, the body is left alone",
    keySecretsForSave(keyDraft({ privateKey: "", passphrase: "p" })),
    { passphrase: "p" },
  );
  check(
    "typed body + typed passphrase: both",
    keySecretsForSave(keyDraft({ privateKey: "-----BEGIN...", passphrase: "p" })),
    { privateKey: "-----BEGIN...", passphrase: "p" },
  );
  check(
    'typed body + BLANK passphrase: the passphrase is sent as "" - the one deliberate delete, because a blank passphrase belongs to the new body, not a leave-alone',
    keySecretsForSave(keyDraft({ privateKey: "-----BEGIN...", passphrase: "" })),
    { privateKey: "-----BEGIN...", passphrase: "" },
  );
}

// --- 7. validateKeyDraft -------------------------------------------------------
console.log("\n[7] validateKeyDraft - a body is required on create, not on edit");
{
  check(
    "a blank name is refused on create",
    validateKeyDraft(keyDraft({ name: "" }), "create"),
    "Name is required",
  );
  check(
    "a blank name is refused on edit",
    validateKeyDraft(keyDraft({ name: "" }), "edit"),
    "Name is required",
  );
  check(
    "a blank body is refused on create",
    validateKeyDraft(keyDraft({ privateKey: "" }), "create"),
    "Paste or import a private key",
  );
  check(
    "a blank body passes on edit - it means keep the stored key",
    validateKeyDraft(keyDraft({ privateKey: "" }), "edit"),
    null,
  );
  check(
    "a body present on create passes",
    validateKeyDraft(keyDraft({ privateKey: "-----BEGIN..." }), "create"),
    null,
  );
}

// --- 8. purity and copy ---------------------------------------------------------
console.log(
  "\n[8] purity and copy - draft.ts stays pure, and its help copy names no protection claim",
);
{
  const draftSrc = read("src/modules/vault/editor/draft.ts");

  // An IMPORT-SPECIFIER parse, not a quoted-needle scan. The needle list this
  // replaced forbade the exact quoted text `"../store"`, `"../adapters"`,
  // `"../resolve"` and three `@/modules/vault/*` spellings - and
  // `import { findKey } from "../../vault/store";`, an executed evasion,
  // matches none of them: it resolves under this tsconfig
  // and the old check went green over it. Enumerating forbidden spellings
  // cannot close a class with infinitely many members (`../../vault/store`,
  // `../../../vault/store` from a nested file, `@/modules/vault/store`, ...);
  // collecting every import specifier the file actually has and asserting the
  // SET is exactly the two pure modules this file is allowed to depend on
  // does.
  const importSpecifiers = [...draftSrc.matchAll(/from\s*["']([^"']+)["']/g)]
    .map((m) => m[1])
    .sort();
  ok(
    `draft.ts's import specifiers are exactly ["../keyInspect", "../types"] - found ${JSON.stringify(importSpecifiers)}`,
    JSON.stringify(importSpecifiers) === JSON.stringify(["../keyInspect", "../types"]),
  );

  // Two ways impurity could arrive with no `from "..."` clause to catch above:
  // a bare Tauri invoke name, or a sibling module's helper name typed in
  // without an import (dead code, but still the smell this file's own header
  // forbids).
  for (const forbidden of ["secrets_get", "getHostSshSecrets"]) {
    ok(
      `draft.ts's raw source does not contain ${JSON.stringify(forbidden)}`,
      !draftSrc.includes(forbidden),
    );
  }

  // Six strings, enumerated by calling every branch of the three help
  // functions - the same shape `vault-page-verify.ts` uses for `deleteNote`.
  const helpStrings = [
    identityPasswordHelp(true),
    identityPasswordHelp(false),
    privateKeyHelp("create"),
    privateKeyHelp("edit"),
    passphraseHelp(true),
    passphraseHelp(false),
  ];
  for (const s of helpStrings) {
    ok(
      `${JSON.stringify(s)} makes no protection claim (safer/securely/more secure)`,
      !/\bsafer\b|\bsecurely\b|\bmore secure\b/i.test(s),
    );
    ok(
      `${JSON.stringify(s)} makes no protection claim (safe/verified/protected)`,
      !/\bsafe\b|\bverified\b|\bprotected\b/i.test(s),
    );
    ok(`${JSON.stringify(s)} does not name "OS keychain"`, !s.includes("OS keychain"));
    ok(
      `${JSON.stringify(s)} does not name "Credential Manager"`,
      !s.includes("Credential Manager"),
    );
  }

  // A fold with no counter-example passes for free: a function returning one
  // string for both branches would pass every wording check above without
  // saying anything. These three checks are that counter-example.
  ok(
    "identityPasswordHelp's two branches are distinct",
    identityPasswordHelp(true) !== identityPasswordHelp(false),
  );
  ok(
    "privateKeyHelp's two branches are distinct",
    privateKeyHelp("create") !== privateKeyHelp("edit"),
  );
  ok("passphraseHelp's two branches are distinct", passphraseHelp(true) !== passphraseHelp(false));
}

// --- 9. encryptedKeyRefusal --------------------------------------------------
console.log(
  "\n[9] encryptedKeyRefusal - refuses only an ENCRYPTED body saved with a BLANK (trimmed) passphrase",
);
{
  const REFUSAL =
    "This key file is encrypted and needs its passphrase. Enter it below and save again - a key" +
    " stored without it fails every connect, and the passphrase is the only thing that changes" +
    " that.";

  check("not encrypted + a blank passphrase: passes", encryptedKeyRefusal(false, ""), null);
  check(
    "not encrypted + a passphrase typed anyway: passes - encrypted is what this decides on",
    encryptedKeyRefusal(false, "hunter2"),
    null,
  );
  check("encrypted + a passphrase typed: passes", encryptedKeyRefusal(true, "hunter2"), null);
  check(
    "encrypted + a blank passphrase: refused, by value",
    encryptedKeyRefusal(true, ""),
    REFUSAL,
  );
  check(
    "encrypted + a WHITESPACE-ONLY passphrase: ALSO refused - writeSecret trims before it decides" +
      " (../store.ts:126), so an all-spaces passphrase is the same blank to the store, and this" +
      " function has to agree or a save could look successful while storing an unusable key",
    encryptedKeyRefusal(true, "   "),
    REFUSAL,
  );

  // THE MESSAGE MAY NOT DESCRIBE THE SAVED RECORD, and this is the check on
  // that rather than a note asking the next editor to remember it. TWO editors
  // render this one string and their records are different shapes: a `VaultKey`
  // carries `encrypted` and the key card reads it, while a host's
  // `SshInlineCredentials` has no such field and nothing on the Hosts page says
  // a word about the state. So a sentence about what "the record" or "the page"
  // can report is true on one surface and false on the other - which is exactly
  // how the previous wording ("nothing on the saved record can tell that apart
  // from a key that has none") became false on the vault side the moment
  // `VaultKey.encrypted` existed, while staying true on the host side.
  //
  // Nouns, not a paraphrase check: a claim needs something to make the claim
  // ABOUT, and these are the only names this app has for the two things that
  // differ between the surfaces.
  for (const noun of ["the saved record", "the record", "the Vault page", "the Hosts page"]) {
    ok(
      `the refusal makes no claim about ${JSON.stringify(noun)} - one string, two surfaces, and only one of them has the field`,
      !REFUSAL.toLowerCase().includes(noun.toLowerCase()),
    );
  }
  // And the claim it DOES make is the one that holds on both: the connect
  // fails. A counter-example to the negatives above, which a message reduced to
  // "Enter the passphrase." would otherwise satisfy for free.
  ok(
    "and it does say what is true on both surfaces - that the connect fails",
    /fails every connect/.test(REFUSAL),
  );
  // Refusing is not justified by the state being unrecoverable, and the message
  // must not imply it is: section 6's "blank body + typed passphrase" row is the
  // recovery, and it has always been there.
  ok(
    "and it does not claim the key is permanently unusable - typing a lone passphrase into the editor is a real repair (section 6)",
    !/\bcannot be used\b|\bpermanently\b|\bunusable\b/i.test(REFUSAL),
  );
}

// --- 10. VaultKey.encrypted, the rest of the way to a reader ------------------
console.log(
  "\n[10] VaultKey.encrypted - the stamp that notices it, the predicate that reads it, and the import that carries it",
);
{
  // GROUPED HERE rather than split three ways, and said out loud because the
  // placement is arguable: `vaultKeyStamp` belongs to
  // `vault-editor-verify.ts`, `keyNeedsPassphrase` to `vault-page-verify.ts`
  // beside `keyMissingSecret`, and `sanitizeKey` to `backup-verify.ts`. The
  // three rows below are one property - a field is worthless if any link
  // between the inspection above and a reader drops it - and sections 1 and 5
  // already carry the first two links, so the chain is checked end to end in
  // one place instead of asserted in four files that can each go green while
  // the chain is broken. Moving each row to its own suite later changes nothing
  // about the property; leaving the chain unchecked would. The convert-mint
  // rows at the tail are a fourth group and the least arguable of the four:
  // they call `keyRecordFrom`, which is this file's own subject, and what they
  // hold is which of its arms carries the answer the rest of the chain
  // delivers.

  const aKey = (over: Partial<VaultKey> = {}): VaultKey => ({
    id: "k-1",
    name: "id_ed25519",
    fingerprint: "SHA256:same",
    hasPrivateKey: true,
    hasPassphrase: false,
    ...over,
  });

  // THE STAMP. A re-encrypted - or decrypted - copy of one key keeps its
  // fingerprint, because the fingerprint is of the public half and a passphrase
  // change does not touch it. So `encrypted` is the only thing in the stamp that
  // can notice that swap, and these two records differ in NOTHING else.
  ok(
    "vaultKeyStamp distinguishes two records that differ only in encrypted",
    vaultKeyStamp(aKey({ encrypted: true })) !== vaultKeyStamp(aKey({ encrypted: false })),
  );
  // Three states, not two: absent is "no inspection has answered this", so the
  // first inspection of an imported key is itself a move in the record.
  ok(
    "and it distinguishes ABSENT from both of them - the first inspection of an imported key is a change",
    vaultKeyStamp(aKey()) !== vaultKeyStamp(aKey({ encrypted: false })) &&
      vaultKeyStamp(aKey()) !== vaultKeyStamp(aKey({ encrypted: true })),
  );
  ok(
    "the same key twice, as two separate objects, still stamps the same",
    vaultKeyStamp(aKey({ encrypted: true })) === vaultKeyStamp(aKey({ encrypted: true })),
  );
  // A hand-edited `tervia-vault.json` can put `null` or a string in a
  // `boolean | undefined` field - the store reads the file without
  // re-validating it - and both stamp as the NO-ANSWER character rather than as
  // `0`. `0` is the stronger claim that an inspection looked and found the body
  // unencrypted. This is the same `=== true` `keyNeedsPassphrase` tests two
  // groups below, pinned on both sides so one three-state field cannot drift
  // back to being read by two rules.
  ok(
    "vaultKeyStamp reads a non-boolean as no answer - the same stamp an absent field gets",
    vaultKeyStamp({ ...aKey(), encrypted: "yes" } as unknown as VaultKey) ===
      vaultKeyStamp(aKey()) &&
      vaultKeyStamp({ ...aKey(), encrypted: null } as unknown as VaultKey) ===
        vaultKeyStamp(aKey()),
  );
  ok(
    "and a null encrypted does NOT stamp as the inspected-and-unencrypted state",
    vaultKeyStamp({ ...aKey(), encrypted: null } as unknown as VaultKey) !==
      vaultKeyStamp(aKey({ encrypted: false })),
  );

  // THE PREDICATE. The absent row is the three-state decision: nothing has
  // established that this body is encrypted, so claiming it needs a passphrase
  // would be the record asserting an inspection it never had.
  ok(
    "keyNeedsPassphrase: encrypted with no passphrase stored -> true",
    keyNeedsPassphrase(aKey({ encrypted: true, hasPassphrase: false })) === true,
  );
  ok(
    "keyNeedsPassphrase: encrypted WITH a passphrase stored -> false",
    keyNeedsPassphrase(aKey({ encrypted: true, hasPassphrase: true })) === false,
  );
  ok(
    "keyNeedsPassphrase: encrypted false with no passphrase -> false, which is a key that simply has none",
    keyNeedsPassphrase(aKey({ encrypted: false, hasPassphrase: false })) === false,
  );
  ok(
    "keyNeedsPassphrase: encrypted ABSENT with no passphrase -> false, because nobody has looked",
    keyNeedsPassphrase(aKey({ hasPassphrase: false })) === false,
  );
  // The store reads `tervia-vault.json` without re-validating it, so a
  // hand-edited file can put a non-boolean in a `boolean | undefined` field.
  // `=== true` answers false; a truthiness test would answer true and put the
  // warning line on a record nothing established anything about.
  ok(
    "keyNeedsPassphrase: a non-boolean from a hand-edited store file -> false, not truthy",
    keyNeedsPassphrase({ ...aKey(), encrypted: "yes" } as unknown as VaultKey) === false,
  );

  // THE BODYLESS ROW, and no other fixture in this suite constructs it: `aKey`
  // defaults `hasPrivateKey: true`, so every row above describes a record that
  // HAS a body, which is why a predicate with no `hasPrivateKey` conjunct
  // shipped green. An import whose secret did not land is exactly this shape -
  // `sanitizeKey` forces both presence flags false and keeps the file's
  // `encrypted`, checked by value at the end of this section.
  const bodyless = aKey({ hasPrivateKey: false, encrypted: true, hasPassphrase: false });
  ok(
    "keyNeedsPassphrase: encrypted with NO stored body -> false, because there is no body a passphrase could unlock",
    keyNeedsPassphrase(bodyless) === false,
  );
  ok(
    "keyNeedsPassphrase: encrypted with no stored body but a passphrase stored anyway -> false as well",
    keyNeedsPassphrase(aKey({ hasPrivateKey: false, encrypted: true, hasPassphrase: true })) ===
      false,
  );
  // THE PAIR STATEMENT, which is the property rather than the two answers
  // beside each other: exactly ONE of the two predicates speaks for any row.
  // Without the conjunct both fire here, and the card then renders the
  // destructive "Missing private key" badge beside a sentence telling the user
  // the key fails every connect until its passphrase is entered in the editor -
  // an instruction that stores a passphrase, turns `keyNeedsPassphrase` false
  // and takes the warning away while the row still cannot authenticate.
  ok(
    "and keyMissingSecret is the one that speaks for the bodyless row - exactly one of the two, never both",
    keyMissingSecret(bodyless) === true && keyNeedsPassphrase(bodyless) === false,
  );
  // The other direction, so the row above cannot be satisfied by a predicate
  // that answers `false` for everything: the row WITH a body is
  // `keyNeedsPassphrase`'s, and `keyMissingSecret` stays out of it.
  const withBody = aKey({ encrypted: true, hasPassphrase: false });
  ok(
    "and the encrypted row that DOES hold a body is keyNeedsPassphrase's alone - again exactly one",
    keyNeedsPassphrase(withBody) === true && keyMissingSecret(withBody) === false,
  );

  // The sibling is NOT widened. It feeds `identityMissingSecret`, and an
  // encrypted key whose passphrase is missing has a private half - reporting it
  // as missing one would swap a false statement for a different false statement.
  ok(
    "keyMissingSecret still reads only hasPrivateKey - an encrypted key with no passphrase is not a key with no private half",
    keyMissingSecret(aKey({ encrypted: true, hasPassphrase: false })) === false,
  );

  // THE IMPORT. `sanitizeKey` performs no inspection, so it may only report
  // what the file literally says - three states, the same shape `sanitizeRule`
  // gives `startWithHost`, and the line the field's survival across an
  // export/import round trip rests on.
  const fileRow = (over: Record<string, unknown> = {}) => ({
    id: "k-1",
    name: "laptop",
    ...over,
  });
  check(
    "sanitizeKey preserves encrypted: true from the file",
    sanitizeKey(fileRow({ encrypted: true }))?.encrypted,
    true,
  );
  check(
    "sanitizeKey preserves encrypted: false from the file - not coerced to absent",
    sanitizeKey(fileRow({ encrypted: false }))?.encrypted,
    false,
  );
  ok(
    "a file row that does not mention it leaves the field ABSENT, not false",
    !("encrypted" in (sanitizeKey(fileRow()) ?? {})),
  );
  ok(
    "and a non-boolean value leaves it absent too, rather than arriving as a truthy claim",
    !("encrypted" in (sanitizeKey(fileRow({ encrypted: "yes" })) ?? {})) &&
      !("encrypted" in (sanitizeKey(fileRow({ encrypted: 1 })) ?? {})),
  );
  // `null` specifically, because it is the value a hand-written or
  // machine-generated JSON file most plausibly carries for "no value" - and
  // absent is the right landing place for it, not `false`. `false` would be this
  // record claiming an inspection looked and found the body unencrypted, which
  // is the stronger claim and the one that silences the warning.
  ok(
    "and a null leaves it absent too, rather than arriving as an inspected-and-unencrypted claim",
    !("encrypted" in (sanitizeKey(fileRow({ encrypted: null })) ?? {})),
  );
  // The two presence flags are still forced, and this row is why the one above
  // is not simply "the file wins": those two describe the EXPORTING machine's
  // keychain, `encrypted` describes the key material.
  check(
    "the two presence flags are still forced false even when the file claims both",
    [
      sanitizeKey(fileRow({ hasPrivateKey: true, hasPassphrase: true, encrypted: true }))
        ?.hasPrivateKey,
      sanitizeKey(fileRow({ hasPrivateKey: true, hasPassphrase: true, encrypted: true }))
        ?.hasPassphrase,
    ],
    [false, false],
  );
  // The chain, end to end and by value: an encrypted key exported from another
  // machine lands here with the file's encryption answer intact, and that answer
  // is what a reader gets to ask about. WHICH reader depends on the body.
  // `sanitizeKey` forces both presence flags false - the secrets do not travel
  // in the metadata it validates - so the row it returns is the bodyless one
  // above, and `keyMissingSecret` is what speaks for it. `keyNeedsPassphrase`
  // reads it once a body is actually stored under that id, which is what
  // `upsertKey` reports back and what `apply.ts`'s second `keyRecord` pass
  // writes when the private key landed in the same import.
  const imported = sanitizeKey(fileRow({ encrypted: true, fingerprint: "SHA256:x" }));
  ok(
    "an imported encrypted key keeps the encryption answer but has no body, so keyMissingSecret is its reader and keyNeedsPassphrase is not",
    imported !== null &&
      imported.encrypted === true &&
      keyMissingSecret(imported) &&
      !keyNeedsPassphrase(imported),
  );
  ok(
    "and that same row once the body IS stored reads as needing a passphrase - the state the whole field exists for",
    imported !== null && keyNeedsPassphrase({ ...imported, hasPrivateKey: true }),
  );

  // THE CONVERT MINT, both of its arms, and the reason it is checked at all is
  // that the prose about it has been wrong three rounds running with nothing
  // here to catch it. `encryptedKeyRefusal`'s doc in
  // `src/modules/vault/editor/draft.ts` and `keyNeedsPassphrase`'s doc in
  // `src/modules/vault/refs.ts` both justify the host-to-vault convert NOT
  // refusing an encrypted body with no passphrase by what the minted record
  // reports - and that justification holds on ONE arm. `applyCredentialChange`
  // in `src/modules/hosts/HostEditorDialog.tsx` inspects the stored key body
  // only while the field still holds it unedited, because facts read off an
  // edited body would describe a different key from the one whose accounts
  // travel; a touched field or a thrown inspection leaves `facts` at `{}`.
  //
  // THE TWO ARMS ARE ONE CHECK. Either row alone reads as an accident: the
  // empty-facts row says nothing about what a real inspection would have
  // recorded, and the inspected row on its own is section 5's create row again.
  // What the docs claim is the DIFFERENCE between them.
  //
  // Through the real `keyRecordFrom`, with the arguments the convert passes:
  // `convertHostToVault` in `src/modules/hosts/credentialMove.ts` builds a
  // `KeyDraft` carrying the new key's name with both secret fields and the
  // description blank, passes `existing` as null because the id was minted in
  // that same call, and passes the arm's `facts` straight through.
  const convertMint = (facts: VaultKeyFacts): VaultKey =>
    keyRecordFrom("k-new", keyDraft({ name: "prod key" }), null, facts);

  check(
    "convert's skipped-inspection arm - a mint from facts = {} records NONE of the four, `encrypted` included",
    convertMint({}),
    {
      id: "k-new",
      name: "prod key",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
    },
  );

  // `keyRecordFrom`'s two presence flags are placeholders that `upsertKey`
  // overwrites with what it actually stored (`writeKeySecrets` in
  // `src/modules/vault/store.ts`). On the convert path the host's private key
  // copies onto the new key's account and no passphrase is written, so the row a
  // reader eventually asks about is the mint with `hasPrivateKey: true` and
  // `hasPassphrase: false`. That overwrite is MODELLED here, not exercised - see
  // the limits note below - and it has to be applied for these two rows to ask
  // anything at all: `keyNeedsPassphrase` requires a stored body, so both arms
  // would answer `false` off the raw mint, the second one for the wrong reason.
  const asStored = (record: VaultKey): VaultKey => ({
    ...record,
    hasPrivateKey: true,
    hasPassphrase: false,
  });
  ok(
    "so keyNeedsPassphrase answers false for that minted key - nothing reports the state, and the key card is silent for it",
    keyNeedsPassphrase(asStored(convertMint({}))) === false,
  );

  const inspectedFacts = vaultKeyFactsFrom(keyInspectResult({ encrypted: true }));
  check(
    "convert's inspected arm - a mint from real inspected facts records the encryption answer with the other three",
    convertMint(inspectedFacts),
    {
      id: "k-new",
      name: "prod key",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
      keyType: "ed25519",
      fingerprint: "SHA256:x",
      publicKey: "ssh-ed25519 A",
      encrypted: true,
    },
  );
  ok(
    "and keyNeedsPassphrase answers true for THAT one - the arm the two docs' justification is scoped to",
    keyNeedsPassphrase(asStored(convertMint(inspectedFacts))) === true,
  );
  // THE PAIR STATEMENT, which is the claim the docs make and neither row makes
  // alone: the same builder, the same draft, the same id, differing only in
  // whether the inspection ran - and exactly one of the two ends up reported.
  ok(
    "the two convert arms differ only in whether the inspection ran, and only the inspected one is reported",
    keyNeedsPassphrase(asStored(convertMint(inspectedFacts))) === true &&
      keyNeedsPassphrase(asStored(convertMint({}))) === false,
  );
  // WHAT THESE FOUR ROWS DO NOT HOLD, said here rather than left in a review
  // note. They hold the RECORD SHAPE each arm produces and what a reader answers
  // for it. They do NOT hold that the gate in `HostEditorDialog.tsx` routes any
  // given interaction to the arm you think it does: that gate reads two React
  // refs and a textarea, and nothing in this repo EXECUTES it -
  // `credential-move-verify.ts` pins its conjuncts as source text through the
  // compiler API and calls `convertHostToVault` with `facts` already decided, so
  // which arm a real convert takes is held by reading the component, not by
  // running it. The `hasPrivateKey: true` above is modelled on what
  // `writeKeySecrets` reports for a landed copy rather than read back from it.
}

console.log(failed === 0 ? "\nAll vault-draft checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);

// --- mutation table ----------------------------------------------------
//
// A check that has not been watched fail is not a check. Every mutation below
// was actually run against the file named, its exit code recorded, and the
// source restored by hash.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   V1: draft.ts - identityRecordFrom's `keyId` line    section 2's password-auth
//     changed to `keyId: draft.keyId || undefined`        and agent-auth rows
//   V2: draft.ts - identitySecretsForSave's body        section 3's two blank rows
//     changed to `return { password: draft.password };`
//   V3: keyInspect.ts - vaultKeyFactsFrom's fingerprint  key-inspect-verify
//     line changed to `?? undefined`                      section 3b's blank-
//                                                        fingerprint check
//   V4: keyInspect.ts - the sealed-container branch      key-inspect-verify
//     changed to return a keyType                          section 3b's first two
//                                                        checks
//   V5: draft.ts - keyRecordFrom's facts branch changed  section 5's sealed-
//     to `??` old values under new ones                    container-over-an-
//                                                        existing-key row
//   V6: draft.ts - keySecretsForSave's replace branch    section 6's fourth row
//     changed to omit a blank passphrase
//   V7: draft.ts - keySecretsForSave's keep branch       section 6's first two
//     changed to always send both fields                  rows
//   V8: keyInspect.ts - vaultKeyTypeFrom's body changed  key-inspect-verify
//     to `return "unknown";` unconditionally               section 3 (eight rows)
//                                                        AND 3b's mapping row,
//                                                        AND this file's section 1
//   V9: draft.ts - privateKeyHelp changed to return      section 8's distinctness
//     "Paste a key." unconditionally                       check
//
// `VaultKey.encrypted`, one mutation per link in the chain. Each was run, its
// failing checks taken from that run's own output, and the source restored by
// hash.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   W1: keyInspect.ts - the sealed branch reverted to    section 5's "a sealed
//     `return {};`                                        container's facts ..."
//                                                       and "a create from a
//                                                       sealed container ..." (2).
//                                                       ALSO key-inspect-verify
//                                                       section [3b] (2).
//   W2: keyInspect.ts - `encrypted: info.encrypted`      section 1's four-key row
//     deleted from the parsed branch                      and its presence row,
//                                                       section 5's wholesale-
//                                                       replace row, the newly
//                                                       pasted ENCRYPTED body row
//                                                       and the create row (5).
//                                                       ALSO key-inspect-verify
//                                                       section [3b] (2).
//   W3: draft.ts - `encrypted: existing?.encrypted`      section 5's carry-forward
//     deleted from keyRecordFrom's facts === null          row and the two
//     branch                                              directions beside it (3).
//                                                       That branch is the one a
//                                                       rename-only save travels.
//   W4: types.ts - vaultKeyStamp reverted to the two-    section 10's two original
//     flag form, dropping the encryption character        stamp rows AND the new
//                                                       null row (3). RE-RUN after
//                                                       the rows below were added:
//                                                       it was 2. The non-boolean
//                                                       row survives this one -
//                                                       with the character gone
//                                                       every record stamps alike,
//                                                       which is what that row
//                                                       ASSERTS for a non-boolean,
//                                                       so it passes for the wrong
//                                                       reason. That is why the
//                                                       null row sits beside it.
//   W5: refs.ts - keyNeedsPassphrase's `=== true`        section 10's non-boolean
//     changed to `!!key.encrypted`                        row (1) - and ONLY that
//                                                       one, which is what says
//                                                       that row is not redundant
//                                                       with the absent row beside
//                                                       it
//   W6: refs.ts - the same test changed to               section 10's ABSENT row
//     `key.encrypted !== false`, i.e. absent read as      and its non-boolean row
//     encrypted                                           (2). RE-RUN after the
//                                                       convert-mint rows below
//                                                       were added: it is 4 now,
//                                                       the two extra being the
//                                                       skipped-inspection arm's
//                                                       keyNeedsPassphrase row and
//                                                       the pair statement. That
//                                                       is the same defect those
//                                                       rows exist for, arriving
//                                                       from the reader's side
//                                                       instead of the mint's: an
//                                                       arm that recorded no
//                                                       answer must not be read as
//                                                       having given one.
//   W7: backup/file.ts - sanitizeKey's typeof test       section 10's "preserves
//     narrowed to `raw.encrypted === true`                 encrypted: false" row (1)
//   W8: backup/file.ts - `encrypted` forced to false     section 10's preserves-
//     alongside the two presence flags                    true row, both absent
//                                                       rows, and the end-to-end
//                                                       import row (4)
//   W9: page/KeyCard.tsx - the whole needs-a-passphrase  NOTHING WHEN IT WAS RUN,
//     block deleted from the card's JSX                   and that gap is now
//                                                       CLOSED. At the time: this
//                                                       file, vault-shell-verify,
//                                                       vault-page-verify and
//                                                       key-inspect-verify all
//                                                       stayed green, `tsc`
//                                                       included, because the
//                                                       `const` the block reads
//                                                       goes with it. The check
//                                                       landed later in the same
//                                                       sub-wave, in the file this
//                                                       row already named as where
//                                                       it belonged:
//                                                       `vault-shell-verify`
//                                                       section 17 holds the block,
//                                                       and that file's own table
//                                                       records THIS SAME mutation
//                                                       as X1 - RED, exit 1. What
//                                                       is still true is the LIMIT
//                                                       of that pin: it reads the
//                                                       card's source through the
//                                                       compiler API, so it catches
//                                                       a deleted block, a rewired
//                                                       condition and a locally
//                                                       reimplemented predicate -
//                                                       not a wrong VALUE reaching
//                                                       a real render. Section 17's
//                                                       own comment says the same,
//                                                       and its "exactly one
//                                                       <Badge>" neighbour is why
//                                                       this state is a text line
//                                                       rather than a second chip.
//
// The private-half conjunct and the stamp's strict read, each mutated after the
// rows in section 10 that hold them were added. Every count below is from that
// run's own output, and the source was restored from a snapshot and diffed
// clean afterwards.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   N1: refs.ts - the `!keyMissingSecret(key)`          section 10's bodyless row,
//     conjunct removed from keyNeedsPassphrase,          the pair statement beside
//     leaving `key.encrypted === true &&                 it, and the end-to-end
//     !key.hasPassphrase`                                import row (3). Exit 1
//                                                       here; the other four
//                                                       suites stayed at exit 0,
//                                                       which is what says this
//                                                       file is where the property
//                                                       lives. The
//                                                       bodyless-WITH-a-passphrase
//                                                       row survives it, correctly:
//                                                       that row is held by the
//                                                       `!hasPassphrase` conjunct,
//                                                       not by this one, and it is
//                                                       there to say the two
//                                                       conjuncts are separate
//                                                       rules.
//   N2: types.ts - vaultKeyStamp's encryption           section 10's two new stamp
//     character reverted to the truthiness form          rows (2)
//     (`key.encrypted === undefined ? "-" :
//     key.encrypted ? "1" : "0"`)
//   N2b: the same, but strict for `1` only              the SAME two rows (2). The
//     (`... === undefined ? "-" : ... === true ?         narrower reading of the
//     "1" : "0"`), so a non-boolean still falls          fix - agree with the
//     to "0"                                             predicate on `1` but leave
//                                                       `null` stamping as
//                                                       "inspected and
//                                                       unencrypted" - and this is
//                                                       the mutation that says the
//                                                       two rows are what pin the
//                                                       wider one.
//   N3: refs.ts - keyMissingSecret widened to           section 10's other-
//     `!key.hasPrivateKey || !key.hasPassphrase`,        direction pair row, the
//     the widening its own doc refuses                   sibling-not-widened row,
//                                                       and the encrypted-with-no-
//                                                       passphrase row (4 here,
//                                                       exit 1) - plus 6 in
//                                                       vault-page-verify, exit 1.
//                                                       Run because
//                                                       keyNeedsPassphrase now
//                                                       DELEGATES to that function,
//                                                       so its meaning is this
//                                                       predicate's dependency; the
//                                                       coupling is held loudly on
//                                                       both sides.
//   N4: this file - the null sanitizeKey row's          that row alone (1), exit 1.
//     fixture changed from `encrypted: null` to          A CHECK-SIDE mutation, and
//     `encrypted: false`                                 weaker than the rest: the
//                                                       branch it guards is
//                                                       `src/modules/backup/file.ts`'s
//                                                       `typeof raw.encrypted ===
//                                                       "boolean"`, and this
//                                                       mutation leaves that test
//                                                       alone. So it says the
//                                                       row really evaluates
//                                                       sanitizeKey's output and is
//                                                       sensitive to what that
//                                                       function does with the
//                                                       value - NOT that a
//                                                       widening of the typeof test
//                                                       would redden here. W7 and
//                                                       W8 above are the source-
//                                                       side mutations of that same
//                                                       function.
//
// The convert mint's two arms. These rows exist because the paragraph they hold
// - `encryptedKeyRefusal`'s doc and `keyNeedsPassphrase`'s - was wrong in three
// consecutive rounds with no check anywhere over it. Both mutations were run,
// the counts are from that run's own output, and `draft.ts` was restored from a
// snapshot blob and diffed clean afterwards.
//
//   Mutation                                          Check(s) it killed
//   -------------------------------------------------  ---------------------------
//   C1: draft.ts - keyRecordFrom's facts branch         the skipped-inspection
//     changed to `{ ...base, encrypted: true,            arm's shape row, its
//     ...facts }`, so an arm that read no facts at       keyNeedsPassphrase row and
//     all manufactures the answer anyway                 the pair statement (3),
//                                                       exit 1. Every other row in
//                                                       sections 5 and 10 stayed
//                                                       green - all of their fact
//                                                       fixtures carry `encrypted`
//                                                       already, which is exactly
//                                                       why the empty-facts arm
//                                                       needed rows of its own.
//   C2: draft.ts - the same branch changed to           the shape row ALONE (1),
//     `{ ...base, ...facts, encrypted:                   exit 1. The two reader
//     facts.encrypted ?? false }`, so absent             rows survive it, and
//     degrades to the inspected-and-unencrypted          correctly: `encrypted:
//     claim                                              false` still answers
//                                                       `false`, so the card stays
//                                                       silent either way. This is
//                                                       the mutation that says the
//                                                       shape row is not redundant
//                                                       with the reader row beside
//                                                       it - only the shape row
//                                                       can tell ABSENT from
//                                                       present-and-false, which
//                                                       is the difference between
//                                                       "nobody looked" and "we
//                                                       looked and it is not
//                                                       encrypted".
//
// NEITHER MUTATION IS ON THE GATE, and none can be from this file: the routing
// between the two arms lives in a React component's refs. See the limits note
// at the end of section 10 for what holds that instead.
//
// Section 2b's mutations were run from credential-move-verify's side, where
// the caller lives - see that file's own table. The one that lands here:
//
//   H2: credentialMove.ts - the third argument dropped   credential-move-verify
//     from identityRecordFrom(identityId, draft, "keep")   sections 4 and 4b.
//                                                        NOT section 2b, which
//                                                        calls the rule directly
//                                                        and so cannot see a
//                                                        caller that stops using
//                                                        it - which is exactly
//                                                        why 2b is not the only
//                                                        check on this rule.
