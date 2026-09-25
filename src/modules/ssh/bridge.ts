import { invoke, Channel } from "@tauri-apps/api/core";
// The two carriers, imported rather than declared here, because
// `classifySshConnectFailure` reads them back with `instanceof` and that file
// must stay import-free (it is loaded by scripts that cannot touch a webview
// API). It imports nothing, so pulling it in costs this file nothing either.
import {
  SshAuthRejectedError,
  SshLocalConnectError,
} from "@/modules/terminal/lib/ssh-exit-decision";
import type { SecretSource } from "@/modules/vault/resolve";

/** First-connect host-key confirmation request from the backend. */
export type SshHostKeyPrompt = { promptId: string; fingerprint: string; host: string };

/** Why the shell channel ended, carried alongside `onExit`'s numeric `code`
 *  (which is a convenience duplicate of `reason.code` for "exit", and
 *  meaningless - always 0 - for the other two kinds; a caller that only
 *  needs "did the session end" can keep ignoring `reason` entirely). Mirrors
 *  the three ways `session.rs`'s pump can end a channel:
 *    - "exit": the remote reported its own exit status
 *      (`ChannelMsg::ExitStatus`) - a deliberate, in-band termination. 0 is
 *      e.g. the user typing `exit`; nonzero is the process's own failure
 *      code. NOT a dropped connection.
 *    - "signal": the remote process was killed by a signal
 *      (`ChannelMsg::ExitSignal`) before the channel closed - also
 *      deliberate, but for a reason on the REMOTE side (OOM killer, `kill`,
 *      a crash), not because the transport dropped.
 *    - "disconnected": the channel just ended (Eof/Close, or the read
 *      loop's `wait()` returning `None`) with NEITHER of the above ever
 *      reported. The one genuinely ambiguous case - the remote may have
 *      exited cleanly (Eof/Close can race a fast exit on some servers) or
 *      the transport may really have died - and the only one worth treating
 *      as reconnect-eligible. */
export type SshExitReason =
  | { kind: "exit"; code: number }
  | { kind: "signal"; name: string; coreDumped: boolean }
  | { kind: "disconnected" };

export type SshEvent =
  | { type: "jumpConnected"; connectionId: string; fingerprint: string }
  | { type: "hostKeyPrompt"; promptId: string; fingerprint: string; host: string }
  | { type: "data"; data: string }
  | { type: "stderr"; data: string }
  | { type: "exit"; code: number }
  | { type: "signal"; name: string; coreDumped: boolean }
  | { type: "disconnected" };

/**
 * A wire event that ends the channel -> the two arguments `onExit` is called
 * with. Extracted from `channel.onmessage` and exported so it can be CALLED by
 * a check rather than read as source text: `openSsh` invokes a Tauri command
 * and is unreachable from a node script, so a pure function is the only part of
 * this seam that can be covered behaviourally - the same reason
 * `sshConnectErrorFrom` below is its own function.
 *
 * The returned `code` is `onExit`'s first argument and nothing more: the
 * remote's own status for "exit", and 0 for the two kinds that never reported
 * one (see `SshExitReason`). Returning both halves together is what lets a
 * check pin that the duplicate is the event's own code rather than a hardcoded
 * 0, which is one of the two ways the collapse this split exists to prevent
 * could come back.
 */
export function exitReasonFromSshEvent(
  event: Extract<SshEvent, { type: "exit" | "signal" | "disconnected" }>,
): { code: number; reason: SshExitReason } {
  switch (event.type) {
    case "exit":
      return { code: event.code, reason: { kind: "exit", code: event.code } };
    case "signal":
      return {
        code: 0,
        reason: { kind: "signal", name: event.name, coreDumped: event.coreDumped },
      };
    case "disconnected":
      return { code: 0, reason: { kind: "disconnected" } };
  }
}

export type SshHandlers = {
  /** A jump host in the ProxyJump chain authenticated. `connectionId` is the
   *  saved connection the hop came from, so the caller pins its fingerprint. */
  onJumpConnected?: (connectionId: string, fingerprint: string) => void;
  /** First-connect host-key confirmation. Show the fingerprint and call
   *  `confirmHostKey(promptId, accept)`; the handshake is paused (no
   *  credentials sent) until then. */
  onHostKeyPrompt?: (prompt: SshHostKeyPrompt) => void;
  /** The session's connection ended on its own - remote disconnect, transport
   *  error, keepalive timeout. At most once; never for `close()`. */
  onClosed?: () => void;
};

/** One hop in a ProxyJump chain, resolved from a saved connection into keychain
 *  references. Passed to `openSsh` in connect order (entry host first). */
export type SshJumpHop = {
  connectionId: string;
  host: string;
  port: number;
  user: string;
  useAgent?: boolean;
  password?: SecretSource;
  privateKey?: SecretSource;
  privateKeyPassphrase?: SecretSource;
  expectedFingerprint?: string;
  /** OpenSSH certificate text, paired with `privateKey` - set only for a
   *  vault entry of the `cert` kind. Public, unlike every field above it. */
  certificate?: string;
  /** Restrict `useAgent` to the ssh-agent identity with this SHA256
   *  fingerprint - set for a vault entry of the `hardware` kind. */
  agentKeyFingerprint?: string;
};

export type SshOpenInput = {
  host: string;
  port: number;
  user: string;
  /** Authenticate through the local ssh-agent. The private key stays in the
   *  agent; only signatures cross the wire, so no secret is read or stored. */
  useAgent?: boolean;
  password?: SecretSource;
  privateKey?: SecretSource;
  privateKeyPassphrase?: SecretSource;
  /** SHA256 fingerprint from a previous connect. If set and the server key differs, the backend returns a `host key mismatch` error. */
  expectedFingerprint?: string;
  /** OpenSSH certificate text, paired with `privateKey` - set only for a
   *  vault entry of the `cert` kind. Public, unlike every field above it. */
  certificate?: string;
  /** Restrict `useAgent` to the ssh-agent identity with this SHA256
   *  fingerprint - set for a vault entry of the `hardware` kind. */
  agentKeyFingerprint?: string;
  /** ProxyJump chain in connect order (entry host first). Empty/absent = direct. */
  jumps?: SshJumpHop[];
};

/** One key held by the local ssh-agent, as `ssh-add -l` would list it. */
export type SshAgentKey = {
  algorithm: string;
  comment: string;
  fingerprint: string;
  /** The `.pub` line, empty when the backend could not build one. Lets a
   *  vault `hardware` key editor fill its public-key field from a picked
   *  agent identity, the same shape `SshTextClassification`'s `publicKey`
   *  variant already carries for a pasted line. */
  publicKey: string;
};

/** Keys the local ssh-agent is holding. Rejects with a message naming what to
 *  start (`ssh-agent` service / `SSH_AUTH_SOCK`) when no agent answers. */
export function listSshAgentKeys(): Promise<SshAgentKey[]> {
  return invoke<SshAgentKey[]>("ssh_agent_keys");
}

/** What a private key can be described as without connecting anywhere. */
export type SshKeyInfo = {
  /** `false` means the key is encrypted in a format that hides its public half
   *  (PKCS#8, PuTTY, PEM): prompt for the passphrase and call again. Every
   *  other field is null until then. */
  parsed: boolean;
  encrypted: boolean;
  /** Wire algorithm name, e.g. `ssh-ed25519`, `ecdsa-sha2-nistp256`. */
  keyType: string | null;
  /** `SHA256:...`, the same form `ssh-keygen -lf` prints. */
  fingerprint: string | null;
  /** The `.pub` line: `ssh-ed25519 AAAA... comment`. */
  publicKey: string | null;
  comment: string | null;
};

/** Describe a pasted or picked private key - algorithm, fingerprint, `.pub`
 *  line - without dialing a host. An `openssh-key-v1` key answers all of it
 *  even while encrypted, so `passphrase` is only needed for the other formats
 *  (and to verify a passphrase early). Rejects with a message naming the
 *  problem: a public key pasted by mistake, DSA, a SEC1 `EC PRIVATE KEY`, or a
 *  wrong passphrase. */
export function inspectSshKey(pem: string, passphrase?: string): Promise<SshKeyInfo> {
  return invoke<SshKeyInfo>("ssh_key_inspect", { pem, passphrase: passphrase ?? null });
}

/** What `ssh_key_classify` resolves pasted text as - a private key
 *  (`ssh_key_inspect` unlocks and describes it, unchanged), an OpenSSH
 *  certificate, a bare public-key line, or neither. Backs the vault key
 *  editor's `cert` and `hardware` kinds. */
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

/** Classify pasted text as a private key, an OpenSSH certificate, a public
 *  key line, or neither - no passphrase, no unlocking, no KDF. Rejects on
 *  empty text with the same message `ssh_key_inspect` uses. */
export function classifySshText(text: string): Promise<SshTextClassification> {
  return invoke<SshTextClassification>("ssh_key_classify", { text });
}

/** Algorithms `ssh_key_generate` accepts, matched exactly against the Rust
 *  side's own list in `src-tauri/src/modules/ssh/mod.rs`. */
export type SshKeyAlgorithm = "ed25519" | "ecdsa-p256" | "rsa-4096";

/** `ssh_key_generate`'s answer: the new PEM plus exactly what `SshKeyInfo`
 *  reports for it (the Rust side flattens the two), so a generated key
 *  describes itself the same way an inspected one does and `describeKeyInfo`/
 *  `vaultKeyFactsFrom` (`src/modules/vault/keyInspect.ts`) need no second
 *  translation for it. */
export type SshKeyGenerated = SshKeyInfo & { pem: string };

/** Generate a new SSH key pair - the vault's other half of "only import one".
 *  The private key is built and serialized entirely in Rust, for the same two
 *  reasons {@link inspectSshKey}'s own comment gives; this returns the PEM the
 *  caller stores exactly as a pasted key's body, never anything less final.
 *  RSA-4096 generation can take a few seconds - the same `spawn_blocking` cost
 *  `inspectSshKey` already pays for bcrypt-pbkdf. */
export function generateSshKey(
  algorithm: SshKeyAlgorithm,
  passphrase?: string,
  comment?: string,
): Promise<SshKeyGenerated> {
  return invoke<SshKeyGenerated>("ssh_key_generate", {
    algorithm,
    passphrase: passphrase ?? null,
    comment: comment ?? null,
  });
}

/** Prefix used by the Rust side for host-key-mismatch errors. Callers check for this to offer a "trust new key" prompt instead of auto-reconnecting. */
export const HOST_KEY_MISMATCH_PREFIX = "ssh: host key mismatch:";

export function isHostKeyMismatchError(err: unknown): boolean {
  if (!err) return false;
  const msg = err instanceof Error ? err.message : String(err);
  return msg.startsWith(HOST_KEY_MISMATCH_PREFIX);
}

/** Answer a first-connect host-key prompt. `accept = true` lets the paused
 *  handshake proceed (and pins the fingerprint on success); `false` aborts the
 *  connect before any credential is sent. */
export function confirmHostKey(promptId: string, accept: boolean): Promise<void> {
  return invoke("ssh_confirm_host_key", { promptId, accept });
}

/**
 * What names ONE `ssh -L` listener once it is up, and the whole of what
 * {@link closeSshForward} accepts.
 *
 * The bound port alone is not an identity, which is why this is a pair. The
 * backend keys a session's live forwards by port (`SshSession::open_forward`),
 * so a listener that has gone and its successor on the same pinned port share
 * one key - and a close still in flight from the first would abort the second.
 * `generation` is minted per open and never reused within a session, so a close
 * naming a spent one is refused instead of landing on whatever is listening now.
 *
 * `boundPort` is what the backend actually bound, which for a request of 0 is
 * not the number that was sent - so a caller that asked for 0 must keep this
 * answer rather than the request.
 */
export type SshForwardHandle = {
  boundPort: number;
  generation: number;
};

/**
 * Start an `ssh -L` local forward on a live session: bind `127.0.0.1:localPort`
 * and tunnel it to `remoteHost:remotePort` as resolved from the server.
 * `localPort` 0 picks a free port. Resolves with the {@link SshForwardHandle}
 * that names the listener it started.
 *
 * A forward still dies with its session, but that is no longer the only way one
 * ends: {@link closeSshForward} drops a single listener while the session and
 * its other forwards stay up.
 */
export function openSshForward(
  id: number,
  localPort: number,
  remoteHost: string,
  remotePort: number,
): Promise<SshForwardHandle> {
  return invoke<SshForwardHandle>("ssh_forward_open", { id, localPort, remoteHost, remotePort });
}

/** Close ONE `ssh -L` listener on a live session, naming it with both halves of
 *  the {@link SshForwardHandle} the open handed back. `false` means there was no
 *  such forward - an unknown session, a port already closed, or a generation a
 *  later open on that port has superseded. Not an error: a teardown fires this
 *  without knowing whether the open finished. */
export function closeSshForward(
  id: number,
  boundPort: number,
  generation: number,
): Promise<boolean> {
  return invoke<boolean>("ssh_forward_close", { id, boundPort, generation });
}

/**
 * Start an `ssh -R` remote forward on a live session: ask the server to
 * listen on `bindAddress:bindPort` (`bindPort` 0 lets the SERVER pick) and
 * route every connection it accepts back to `localHost:localPort` on THIS
 * machine. Resolves with the SAME {@link SshForwardHandle} shape `-L` does -
 * `boundPort` here is the port the SERVER bound. Both halves have to come
 * back to {@link closeSshRemoteForward}.
 */
export function openSshRemoteForward(
  id: number,
  bindAddress: string,
  bindPort: number,
  localHost: string,
  localPort: number,
): Promise<SshForwardHandle> {
  return invoke<SshForwardHandle>("ssh_remote_forward_open", {
    id,
    bindAddress,
    bindPort,
    localHost,
    localPort,
  });
}

/** Close ONE `ssh -R` listener on a live session, naming it with `bindAddress`
 *  plus both halves of the {@link SshForwardHandle} the open handed back.
 *  `false` means there was no such forward, on the same terms
 *  {@link closeSshForward} already gives for `-L`. */
export function closeSshRemoteForward(
  id: number,
  bindAddress: string,
  boundPort: number,
  generation: number,
): Promise<boolean> {
  return invoke<boolean>("ssh_remote_forward_close", { id, bindAddress, boundPort, generation });
}

/**
 * Start an `ssh -D` SOCKS5 listener on a live session: bind
 * `127.0.0.1:localPort` (0 picks a free port) and open one
 * `channel_open_direct_tcpip` per accepted CONNECT. Resolves with the SAME
 * {@link SshForwardHandle} shape `-L` does, and closes through the SAME
 * {@link closeSshForward} - a SOCKS5 listener lives in the identical
 * per-session forward map `-L`'s does, so it needs no close command of its
 * own.
 */
export function openSshSocks(id: number, localPort: number): Promise<SshForwardHandle> {
  return invoke<SshForwardHandle>("ssh_socks_open", { id, localPort });
}

export type SshSession = {
  id: number;
  /** SHA256 fingerprint the target presented. */
  fingerprint: string;
  close: () => Promise<void>;
};

/** Which side's fact ended a connect attempt, as `ssh_open` reports it.
 *  Mirrors `SshConnectErrorKind` in src-tauri/src/modules/ssh/session.rs, whose
 *  doc comment defines what each one means and how to place a new failure site.
 *  The two sets are checked against each other rather than trusted - a kind
 *  added on one side only would arrive here unrecognised and fall back to the
 *  ladder. */
export type SshConnectErrorKind = "config" | "auth" | "transport";

/** The rejected value of `ssh_open`, and the only Tauri command in this app
 *  that rejects with an object rather than a string. */
export type SshConnectErrorPayload = { kind: SshConnectErrorKind; message: string };

function isSshConnectErrorPayload(raw: unknown): raw is SshConnectErrorPayload {
  if (typeof raw !== "object" || raw === null) return false;
  const { kind, message } = raw as { kind?: unknown; message?: unknown };
  if (typeof message !== "string") return false;
  return kind === "config" || kind === "auth" || kind === "transport";
}

/**
 * THE boundary. Turn `ssh_open`'s rejected value into the typed `Error` the rest
 * of the frontend already knows how to classify, and make sure nothing
 * downstream ever sees the raw object.
 *
 * Extracted from `openSsh` and exported so it can be CALLED by a check.
 * `openSsh` itself invokes a Tauri command and is unreachable from a node
 * script, which is exactly why the decision has to live out here: a pure
 * function is the only part of this path that can be covered behaviourally
 * rather than by reading source text.
 *
 * Anything that is not a recognised `{kind, message}` object is returned
 * UNCHANGED - a raw string, a bare `Error`, `null`, a Tauri framework rejection,
 * a kind this build does not know. That pass-through is not politeness. It is
 * what keeps this side correct against a backend that is older, newer, or rolled
 * back: an unrecognised rejection reaches `classifySshConnectFailure` as
 * something it did not raise, is filed transport, and ladders - the behaviour
 * this app had before the kind existed, rather than a crash or a wrong park.
 *
 * `cause` carries the original so a console trace still shows what arrived.
 */
export function sshConnectErrorFrom(raw: unknown): unknown {
  if (!isSshConnectErrorPayload(raw)) return raw;
  switch (raw.kind) {
    case "config":
      return new SshLocalConnectError(raw.message, { cause: raw });
    case "auth":
      return new SshAuthRejectedError(raw.message, { cause: raw });
    case "transport":
      // A plain `Error`, deliberately: neither wrapper means "reconnect-
      // eligible", and transport is what an unwrapped error already classifies
      // as. Wrapping it in a third class would add a type with no reader.
      return new Error(raw.message, { cause: raw });
  }
}

function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

export async function openSsh(input: SshOpenInput, handlers: SshHandlers): Promise<SshSession> {
  const channel = new Channel<SshEvent>();
  channel.onmessage = (event) => {
    switch (event.type) {
      case "jumpConnected":
        handlers.onJumpConnected?.(event.connectionId, event.fingerprint);
        break;
      case "hostKeyPrompt":
        handlers.onHostKeyPrompt?.({
          promptId: event.promptId,
          fingerprint: event.fingerprint,
          host: event.host,
        });
        break;
      case "disconnected":
        handlers.onClosed?.();
        break;
      case "data":
      case "stderr":
      case "exit":
      case "signal":
        // Shell-channel events; never sent on the session channel `openSsh` opens.
        break;
    }
  };

  // The one place the connect error's kind is read. Everything downstream -
  // the reconnect ladder, the host editor's Test button, the forward tunnel -
  // receives an `Error` and behaves exactly as it did when this command
  // rejected with a string.
  const { id, fingerprint } = await invoke<{ id: number; fingerprint: string }>("ssh_open", {
    input: {
      host: input.host,
      port: input.port,
      user: input.user,
      useAgent: input.useAgent ?? false,
      password: input.password ?? null,
      privateKey: input.privateKey ?? null,
      privateKeyPassphrase: input.privateKeyPassphrase ?? null,
      expectedFingerprint: input.expectedFingerprint ?? null,
      certificate: input.certificate ?? null,
      agentKeyFingerprint: input.agentKeyFingerprint ?? null,
      jumps: (input.jumps ?? []).map((j) => ({
        connectionId: j.connectionId,
        host: j.host,
        port: j.port,
        user: j.user,
        useAgent: j.useAgent ?? false,
        password: j.password ?? null,
        privateKey: j.privateKey ?? null,
        privateKeyPassphrase: j.privateKeyPassphrase ?? null,
        expectedFingerprint: j.expectedFingerprint ?? null,
        certificate: j.certificate ?? null,
        agentKeyFingerprint: j.agentKeyFingerprint ?? null,
      })),
    },
    onEvent: channel,
  }).catch((e: unknown) => {
    throw sshConnectErrorFrom(e);
  });

  return { id, fingerprint, close: () => invoke("ssh_close", { id }) };
}

export type SshShellHandlers = {
  onData: (bytes: Uint8Array) => void;
  /** Fires exactly once when the shell channel ends on its own - see SshExitReason. Never for close(). */
  onExit: (code: number, reason: SshExitReason) => void;
};

export type SshShell = {
  write: (data: string) => Promise<void>;
  resize: (cols: number, rows: number) => Promise<void>;
  close: () => Promise<void>;
};

/** Open one interactive shell channel on a live session. Every terminal tab
 *  calls this - not `openSsh` - so N tabs on one host share the session and
 *  cost N shell channels, not N russh connections. */
export async function openSshShell(
  sessionId: number,
  cols: number,
  rows: number,
  handlers: SshShellHandlers,
): Promise<SshShell> {
  const channel = new Channel<SshEvent>();
  channel.onmessage = (event) => {
    switch (event.type) {
      case "data":
        handlers.onData(decodeBase64(event.data));
        break;
      case "stderr":
        // Surface stderr inline. The server PTY usually merges both streams already.
        handlers.onData(decodeBase64(event.data));
        break;
      case "exit":
      case "signal":
      case "disconnected": {
        // One call for all three, so the mapping itself is the pure function's
        // and cannot drift per arm.
        const ending = exitReasonFromSshEvent(event);
        handlers.onExit(ending.code, ending.reason);
        break;
      }
      case "jumpConnected":
      case "hostKeyPrompt":
        // Session-channel events; never sent on a shell channel.
        break;
    }
  };
  const shellId = await invoke<number>("ssh_shell_open", {
    id: sessionId,
    cols,
    rows,
    onEvent: channel,
  });
  return {
    write: (data) => invoke("ssh_shell_write", { id: sessionId, shellId, data }),
    resize: (cols, rows) => invoke("ssh_shell_resize", { id: sessionId, shellId, cols, rows }),
    close: () => invoke("ssh_shell_close", { id: sessionId, shellId }),
  };
}
