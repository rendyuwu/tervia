import type { VaultKeyType } from "./types";

// What a key inspection means for the UI, as pure functions.
//
// The classification itself is Rust's - `ssh_key_inspect` already tells a public
// key from a DSA key from a SEC1 EC key from a wrong passphrase, and phrases each
// one. What is here is the translation from that answer into the three things a
// form has to render, plus the one mapping the vault's own key record needs.
//
// Nothing here makes a secret safer, and nothing here holds one: a fingerprint and
// a public half are not secrets, and the private key body never enters this module.

/**
 * Structurally what `inspectSshKey` resolves with.
 *
 * Declared rather than imported so this module pulls in no Tauri surface and stays
 * loadable under plain node - `modules/ssh/bridge.ts` imports
 * `@tauri-apps/api/core` at top level. The two shapes are identical, so the
 * bridge's result passes straight in.
 */
export type KeyInspectResult = {
  parsed: boolean;
  encrypted: boolean;
  keyType: string | null;
  fingerprint: string | null;
  publicKey: string | null;
  comment: string | null;
};

/**
 * Structurally what `classifySshText` resolves with. Declared rather than
 * imported, for the same reason {@link KeyInspectResult} is - see its own
 * doc comment.
 */
export type SshTextClassification =
  | { kind: "privateKey" }
  | {
      kind: "certificate";
      caFingerprint: string;
      /** The CERTIFIED key's own fingerprint, not the CA's. */
      fingerprint: string;
      keyId: string;
      principals: string[];
      validAfter: number;
      /** `null` when the certificate never expires. */
      validBefore: number | null;
    }
  | {
      kind: "publicKey";
      algorithm: string;
      fingerprint: string;
      comment: string | null;
      publicKey: string;
    }
  | { kind: "unsupported"; reason: string };

export type KeyInspectState =
  | { kind: "idle" }
  | { kind: "checking" }
  /** The container is readable but sealed: everything below it needs the
   *  passphrase. Not an error - prompt and call again. */
  | { kind: "locked" }
  | {
      kind: "ok";
      keyType: string;
      fingerprint: string;
      encrypted: boolean;
      /** The `.pub` line, for the key editor's Generate flow: a key nobody
       *  has installed anywhere yet needs to be copyable the moment it
       *  exists, not only after it is saved and reopened. Same fallback as
       *  `keyType`/`fingerprint` - a real key answers this, so an absent
       *  half is treated as "not yet known" rather than given its own state. */
      publicKey: string;
      comment?: string;
    }
  | { kind: "error"; message: string };

/**
 * `inspectSshKey`'s answer, translated into what the panel renders.
 *
 * `parsed === false` is the container-sealed state - `keyType`, `fingerprint` and
 * `comment` are all null then, and that is normal rather than a failure. Once
 * parsed, a missing `keyType` renders as `"unknown"` rather than a blank field, and
 * a missing `comment` is left absent rather than coerced to an empty string, so the
 * panel can tell "no comment" from "comment not yet known".
 */
export function describeKeyInfo(info: KeyInspectResult): KeyInspectState {
  if (!info.parsed) return { kind: "locked" };
  return {
    kind: "ok",
    keyType: info.keyType ?? "unknown",
    fingerprint: info.fingerprint ?? "",
    encrypted: info.encrypted,
    publicKey: info.publicKey ?? "",
    comment: info.comment ?? undefined,
  };
}

/**
 * The backend's message, with its `ssh: ` prefix removed.
 *
 * Stripped because the message is rendered inside a field already labelled as an
 * SSH private key, where the prefix is noise. The message itself is NOT rewritten:
 * every dead end has its own sentence naming what to do next, and paraphrasing
 * them here would put a second copy of that wording in the tree.
 */
export function describeKeyError(err: unknown): KeyInspectState {
  const raw = err instanceof Error ? err.message : String(err);
  const message = raw.startsWith("ssh: ") ? raw.slice("ssh: ".length) : raw;
  return { kind: "error", message };
}

/**
 * What `classifySshText`'s answer means for the certificate panel in the
 * key editor's `cert` kind - the same "translate the backend's classification
 * into what a form renders" job {@link describeKeyInfo} does for a private
 * key, over a different question ("what is this text") rather than "what did
 * unlocking it find".
 */
export type CertInspectState =
  | { kind: "idle" }
  | { kind: "checking" }
  | {
      kind: "ok";
      caFingerprint: string;
      fingerprint: string;
      keyId: string;
      principals: string[];
      validAfter: number;
      validBefore: number | null;
    }
  /** The pasted text classified as something other than a certificate - a
   *  private key, a public-key line, or unsupported. One state rather than
   *  three: the panel this backs only ever needs to say "that is not a
   *  certificate", not which of the other three it was. */
  | { kind: "notACertificate" }
  | { kind: "error"; message: string };

export function describeCertClassification(
  classification: SshTextClassification,
): CertInspectState {
  if (classification.kind !== "certificate") return { kind: "notACertificate" };
  return {
    kind: "ok",
    caFingerprint: classification.caFingerprint,
    fingerprint: classification.fingerprint,
    keyId: classification.keyId,
    principals: classification.principals,
    validAfter: classification.validAfter,
    validBefore: classification.validBefore,
  };
}

/** {@link describeKeyError}, over a `ssh_key_classify` rejection instead of
 *  an `ssh_key_inspect` one - same prefix-stripping rule, same reason. */
export function describeCertError(err: unknown): CertInspectState {
  const raw = err instanceof Error ? err.message : String(err);
  const message = raw.startsWith("ssh: ") ? raw.slice("ssh: ".length) : raw;
  return { kind: "error", message };
}

/**
 * The wire algorithm name as the vault records it.
 *
 * `ssh_key_inspect` reports what the key file says - `ssh-ed25519`,
 * `ecdsa-sha2-nistp256`, `rsa-sha2-512` - and `VaultKey.keyType` is a four-member
 * union. This is the only mapping between them, so a saved key's type is decided
 * once instead of at each editor that stores one.
 */
export function vaultKeyTypeFrom(algorithm: string | null | undefined): VaultKeyType {
  const alg = (algorithm ?? "").toLowerCase();
  if (alg.includes("ed25519")) return "ed25519";
  if (alg.startsWith("ecdsa-") || alg.startsWith("sk-ecdsa-")) return "ecdsa";
  if (alg === "ssh-rsa" || alg.startsWith("rsa-sha2-")) return "rsa";
  return "unknown";
}

/**
 * The four things a saved {@link VaultKey} records about the key it holds.
 *
 * A DIFFERENT question from {@link KeyInspectState}, over the same answer, and
 * that is why this is a second type rather than four more fields on the
 * display union: the panel renders what the user is looking at right now, and
 * this is what is written to the store. A display union that grows a field only
 * the store reads has stopped being a display union.
 *
 * Every field is optional because every one of them can be genuinely unknown -
 * see {@link vaultKeyFactsFrom}.
 *
 * `encrypted` is the one of the four that survives a sealed container, and the
 * reason it is recorded at all is {@link VaultKey.encrypted}: without it a saved
 * record cannot tell a key that has no passphrase from an encrypted key whose
 * passphrase nobody holds.
 */
export type VaultKeyFacts = {
  keyType?: VaultKeyType;
  fingerprint?: string;
  publicKey?: string;
  encrypted?: boolean;
};

/**
 * What a saved key records, from one `ssh_key_inspect` answer.
 *
 * Two rules, and both are the difference between "we looked and the answer is
 * X" and "we could not look".
 *
 * A SEALED CONTAINER yields the one fact it can answer, and nothing else.
 * `parsed === false` is a PuTTY or PKCS#8 key inspected without its passphrase
 * - normal, not a failure, as {@link describeKeyInfo} says - so it says nothing
 * about the algorithm, the fingerprint or the public half, and it must not
 * become `keyType: "unknown"`. `"unknown"` claims the algorithm was read and is
 * none of the three this app names; absent is the truth here, which is that
 * nothing was read. The two render differently on purpose: `page/KeyCard.tsx`
 * shows the record's own `keyType.toUpperCase()` for the first and the literal
 * "Unknown type" for the second.
 *
 * But a sealed container DOES answer the encryption question, and answers it
 * definitively: `parsed === false` is reached only from `needs_passphrase` in
 * `src-tauri/src/modules/ssh/mod.rs`, i.e. a container that cannot be opened
 * without a passphrase, which is what "encrypted" means. So the sealed branch
 * carries `encrypted: true` - stated rather than copied off the input, because
 * the fact belongs to the sealed STATE and not to whatever a hand-built
 * `KeyInspectResult` put in the field beside it. `encryptedKeyRefusal` in
 * `editor/draft.ts` already relies on that pairing.
 *
 * A BLANK STRING becomes `undefined` rather than travelling as `""`.
 * `VaultKey.fingerprint` and `VaultKey.publicKey` are both optional and every
 * reader uses `??` - `page/KeyCard.tsx` renders
 * `vaultKey.fingerprint ?? "No fingerprint recorded"`, and `"" ?? x` is `""`,
 * so an empty string stored here renders a blank line exactly where the honest
 * sentence belongs, and nothing fails anywhere.
 *
 * `keyType` goes through {@link vaultKeyTypeFrom} and is never mapped here:
 * that function is the single mapping from the wire algorithm name to the
 * vault's four-member union, and a second one is how two surfaces come to
 * disagree about what an `sk-ecdsa-` key is.
 *
 * The parsed branch returns all four keys PRESENT, undefined included -
 * `encrypted` present even when it is `false`. That is load-bearing for
 * {@link keyRecordFrom}'s wholesale replace, which spreads this over a record.
 */
export function vaultKeyFactsFrom(info: KeyInspectResult): VaultKeyFacts {
  if (!info.parsed) return { encrypted: true };
  return {
    keyType: vaultKeyTypeFrom(info.keyType),
    fingerprint: info.fingerprint || undefined,
    publicKey: info.publicKey || undefined,
    encrypted: info.encrypted,
  };
}

/**
 * The five things a saved `cert`-kind {@link VaultKey} records about its
 * certificate, from one `ssh_key_classify` answer over the certificate text.
 * A sibling of {@link VaultKeyFacts}, over a different classification shape -
 * this one has only one answer to translate ("certificate"), so there is no
 * sealed/absent split to draw the way {@link vaultKeyFactsFrom} does.
 */
export type VaultCertFacts = {
  certCaFingerprint: string;
  certKeyId: string;
  certPrincipals: string[];
  certValidAfter: number;
  /** Absent when the certificate never expires. */
  certValidBefore?: number;
};

/** `null` when `classification` is not a certificate at all - the caller's
 *  own refusal to save covers that case, using the specific wrong-kind
 *  message the other three variants already carry. */
export function vaultCertFactsFrom(classification: SshTextClassification): VaultCertFacts | null {
  if (classification.kind !== "certificate") return null;
  return {
    certCaFingerprint: classification.caFingerprint,
    certKeyId: classification.keyId,
    certPrincipals: classification.principals,
    certValidAfter: classification.validAfter,
    ...(classification.validBefore !== null ? { certValidBefore: classification.validBefore } : {}),
  };
}

/**
 * A `hardware`-kind key's facts, from one `ssh_key_classify` answer over a
 * pasted or agent-picked public-key line. Reuses {@link VaultKeyFacts} rather
 * than a fourth "hardware facts" shape: `keyType`/`fingerprint`/`publicKey`
 * mean exactly what they mean for a `pem` key, they just come from a
 * public-key classification instead of an unlock. `encrypted` is explicitly
 * `undefined` (not omitted) for the same "wholesale replace" reason
 * {@link vaultKeyFactsFrom}'s own doc comment gives.
 *
 * `null` when `classification` is not a public-key line at all.
 */
export function hardwareFactsFrom(classification: SshTextClassification): VaultKeyFacts | null {
  if (classification.kind !== "publicKey") return null;
  return {
    keyType: vaultKeyTypeFrom(classification.algorithm),
    fingerprint: classification.fingerprint,
    publicKey: classification.publicKey,
    encrypted: undefined,
  };
}
