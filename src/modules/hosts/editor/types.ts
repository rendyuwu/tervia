import type { VaultAuthMode } from "@/modules/vault/types";

// The draft the merged host editor edits, split the way the dialog is split: the
// shared half, and one credential half per protocol.
//
// Three objects rather than one flat draft with every field optional, because
// only one credential half is ever on screen and a flat draft cannot say that -
// it would let a save read `username` off a row whose protocol is `ssh`.

/** The fields both protocols share. */
export type SharedDraft = {
  name: string;
  host: string;
  /** A string, not a number: an input mid-edit is legitimately empty, and
   *  `Number.parseInt` on save is where that becomes an error message. */
  port: string;
  /** "" = no group. A group is CHOSEN here and created on the Hosts page. */
  groupId: string;
  description: string;
};

export type SshCredentialDraft = {
  user: string;
  authMode: VaultAuthMode;
  password: string;
  privateKey: string;
  keyPassphrase: string;
};

export type RdpCredentialDraft = {
  username: string;
  domain: string;
  /** Blank means "leave the stored password alone" on an edit, and "not set yet"
   *  on a new host. The stored password is never read back into the webview, so
   *  the only way this is non-empty is the user typing in it. */
  password: string;
};

/**
 * Which SSH secret fields the USER has edited in this sitting.
 *
 * The whole point of tracking it: an untouched field is saved as `undefined`,
 * which is the store's "leave whatever is stored alone" state. A form that seeded
 * a password field and sent it back would be one failed keychain read away from
 * sending `""` instead - and `""` is the store's CLEAR instruction. See the save
 * path in `HostEditorDialog.tsx`.
 *
 * The second job it does there: the keychain seed YIELDS to it, so a password
 * typed while the read was still in flight is not replaced by the stored one. That
 * is why the editor holds this in a ref rather than state - the seed reads it
 * after an await, and a state value read there is the one captured before the user
 * could have typed anything.
 */
export type SshSecretTouched = {
  password: boolean;
  privateKey: boolean;
  keyPassphrase: boolean;
};

export const NO_SSH_SECRETS_TOUCHED: SshSecretTouched = {
  password: false,
  privateKey: false,
  keyPassphrase: false,
};

/**
 * The Test button's state. `summary` is already formatted, because the two
 * protocols report different things - a desktop size means nothing for SSH - and
 * a union here would push that branch into every reader.
 */
export type TestState =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "ok"; summary: string }
  | { kind: "fail"; message: string };
