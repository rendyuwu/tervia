/**
 * Self-check for the vault editors' pure layer (6e wave 3, step 1).
 * Run: `pnpm verify vault-draft` (or `npx tsx scripts/vault-draft-verify.ts` to iterate).
 *
 * `src/modules/vault/editor/draft.ts` is pure - no React, no store, no Tauri,
 * no keychain read - which is the only reason this file can exist, the same
 * argument `vault-page-verify.ts`'s own header makes for `page/derive.ts`. This
 * script is that module's only caller: steps 2 and 3 wire the two editor
 * dialogs to it.
 *
 * Modelled on `vault-page-verify.ts`: same `canonical()` (JSON is key-order
 * sensitive and drops `undefined` keys, and both matter here - `keyId: undefined`
 * must read differently from a `want` that simply omits the key), same
 * `check`/`ok` pair, fixtures, numbered sections, and a mutation table at the
 * tail recording every mutation actually run against this file. Copied rather
 * than imported: there is no `scripts/lib`, and every script in this suite
 * duplicates these (VLT-33).
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { vaultKeyFactsFrom, type KeyInspectResult } from "../src/modules/vault/keyInspect";
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
import type { VaultKey } from "../src/modules/vault/types";

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
    "a parsed answer produces exactly the three keys, present, undefined included where absent",
    vaultKeyFactsFrom(keyInspectResult()),
    { keyType: "ed25519", fingerprint: "SHA256:x", publicKey: "ssh-ed25519 A" },
  );
}

// --- 2. identityRecordFrom - the VLT-73 rule, literal per row ---------------
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
    "password auth drops a key still sitting in the draft (VLT-73)",
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
    "password auth with a blank password passes - VLT-44, and the row that makes 'missingSecret' reachable",
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
    "facts === null carries all three existing facts forward unchanged",
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
    },
  );

  const freshFacts = vaultKeyFactsFrom(keyInspectResult());
  check(
    "fresh facts over an existing key REPLACE all three wholesale",
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
    },
  );

  const sealedFacts = vaultKeyFactsFrom(keyInspectResult({ parsed: false }));
  check(
    "a sealed container's facts ({}) over an existing key with facts leaves all three ABSENT, not carried forward",
    keyRecordFrom("k-1", keyDraft(), existing, sealedFacts),
    {
      id: "k-1",
      name: "id_ed25519",
      description: undefined,
      hasPrivateKey: false,
      hasPassphrase: false,
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

  // VLT-80/7d(a): an IMPORT-SPECIFIER parse, not a quoted-needle scan. The
  // needle list this replaced forbade the exact quoted text `"../store"`,
  // `"../adapters"`, `"../resolve"` and three `@/modules/vault/*` spellings -
  // and `import { findKey } from "../../vault/store";` (P10, reviewer A's own
  // executed evasion) matches none of them: it resolves under this tsconfig
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

// --- 9. encryptedKeyRefusal (VLT-77/7b) --------------------------------------
console.log(
  "\n[9] encryptedKeyRefusal - refuses only an ENCRYPTED body saved with a BLANK (trimmed) passphrase",
);
{
  const REFUSAL =
    "This key file is encrypted and needs its passphrase. Enter it below and save again - a key" +
    " stored without it cannot be used, and nothing on the saved record can tell that apart from" +
    " a key that has none.";

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
}

console.log(failed === 0 ? "\nAll vault-draft checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);

// --- mutation table ----------------------------------------------------
//
// Handoff discipline (this wave's plan, step 1): a check that has not been
// watched fail is not a check. Every mutation below was actually run against
// the file named, its exit code recorded, and the source restored by hash -
// see /tmp/wave3-step1-pure/MUTATIONS.md for the full before/after/restore
// transcript.
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
