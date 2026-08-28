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
