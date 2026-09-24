/**
 * Pure PuTTY `.reg` export grammar, kept free of the Tauri runtime for the
 * same reason `sshConfigImport.ts` is - `scripts/foreign-import-verify.ts`
 * exercises it under plain node. Encoding (a `regedit.exe` export is UTF-16LE
 * with a BOM by default) is `fs_read_file`'s job, not this module's - see
 * `classify_bytes` in `src-tauri/src/modules/fs/file.rs`; this file only ever
 * sees the already-decoded JS string.
 *
 * PuTTY has no `ProxyJump`/`IdentityFile` equivalent in this app's scope, so a
 * session imports with a blank inline SSH credential exactly like an
 * `ssh_config` host with no `IdentityFile` - see `sshConfigImport.ts`'s
 * `ParsedForeignHost`, reused here unchanged.
 */
import { port } from "./file";
import { newId, type ParsedForeignHost } from "./sshConfigImport";

export type PuttyRefusalReason = "nonSsh" | "proxyMethodSet";

export type PuttyParseResult = {
  hosts: ParsedForeignHost[];
  refused: Record<PuttyRefusalReason, number>;
  /** A session that parsed but had no usable `HostName`/`PortNumber` - one
   *  number, matching `sshConfigImport.ts`'s own `skipped`. */
  skipped: number;
};

const REG_HEADER = "Windows Registry Editor Version 5.00";
const SESSION_SECTION = /^\[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\(.+)]$/i;

/** PuTTY's own escaping for a session name inside the registry path: each
 *  byte outside `[A-Za-z0-9]` is written as `%XX`, which is URL
 *  percent-encoding for exactly the bytes PuTTY escapes -
 *  `decodeURIComponent` decodes it unchanged. Falls back to the raw text on a
 *  malformed escape rather than throwing over one odd session name. */
function decodeSessionName(encoded: string): string {
  try {
    return decodeURIComponent(encoded);
  } catch {
    return encoded;
  }
}

/** `"Key"="a quoted, backslash-escaped string"` -> the decoded value, or
 *  `null` when the line is not that shape. */
function stringValue(line: string): string | null {
  const m = /^"([^"]*)"="((?:[^"\\]|\\.)*)"$/.exec(line);
  if (!m) return null;
  return m[2].replace(/\\(.)/g, "$1");
}

/** `"Key"=dword:00000016` -> `22`, or `null` when the line is not that shape. */
function dwordValue(line: string): number | null {
  const m = /^"([^"]*)"=dword:([0-9a-fA-F]{1,8})$/.exec(line);
  return m ? parseInt(m[2], 16) : null;
}

function keyOf(line: string): string | null {
  return /^"([^"]*)"=/.exec(line)?.[1] ?? null;
}

/**
 * Parse a `.reg` export's PuTTY sessions. Throws a named-format error when the
 * file does not open with the registry editor header, the same way
 * `parseBackupFile` refuses a wrong Tervia format by name - caught and
 * toasted by the picker handler.
 *
 * `Default%20Settings` (PuTTY's own bookkeeping session, not one a user
 * authored) is skipped SILENTLY: it counts toward neither `refused` nor
 * `skipped`. Every other session either becomes a host or is refused and
 * counted: `Protocol` other than `"ssh"` (including absent) under `nonSsh`;
 * `ProxyMethod` set to anything but `0`, or a non-empty `ProxyHost`, under
 * `proxyMethodSet` - a proxy is not a `proxyJumpId`-representable saved-host
 * reference, the same reasoning `sshConfigImport.ts` refuses `ProxyCommand`
 * for.
 */
export function parsePuttyReg(text: string): PuttyParseResult {
  const lines = text.split(/\r\n|\r|\n/);
  const firstNonBlank = lines.find((l) => l.trim().length > 0)?.trim();
  if (firstNonBlank !== REG_HEADER) {
    throw new Error(
      'Not a PuTTY registry export (.reg): missing the "Windows Registry Editor Version 5.00" header.',
    );
  }

  const hosts: ParsedForeignHost[] = [];
  const refused: Record<PuttyRefusalReason, number> = { nonSsh: 0, proxyMethodSet: 0 };
  let skipped = 0;

  let sessionName: string | null = null;
  let fields = new Map<string, string>();

  const flush = () => {
    if (sessionName === null) return;
    const name = sessionName;
    const current = fields;
    sessionName = null;
    fields = new Map();

    if (name === "Default%20Settings") return;

    const protocol = current.get("protocol")?.toLowerCase();
    if (protocol !== "ssh") {
      refused.nonSsh++;
      return;
    }
    const proxyMethod = current.get("proxymethod");
    const proxyHost = current.get("proxyhost");
    if ((proxyMethod !== undefined && proxyMethod !== "0") || (proxyHost?.length ?? 0) > 0) {
      refused.proxyMethodSet++;
      return;
    }

    const host = current.get("hostname")?.trim();
    const rawPort = current.get("portnumber");
    const p = rawPort === undefined ? 22 : port(Number(rawPort));
    if (!host || p === null) {
      skipped++;
      return;
    }
    hosts.push({
      id: newId("h"),
      alias: decodeSessionName(name),
      host,
      port: p,
      user: current.get("username")?.trim() ?? "",
    });
  };

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const section = SESSION_SECTION.exec(line);
    if (section) {
      flush();
      sessionName = section[1];
      continue;
    }
    if (line.startsWith("[")) {
      // A different hive/key entirely (not a PuTTY session) - close whatever
      // session was open and ignore this section's own lines.
      flush();
      continue;
    }
    if (sessionName === null) continue;
    const key = keyOf(line);
    if (!key) continue;
    const lower = key.toLowerCase();
    const str = stringValue(line);
    if (str !== null) {
      fields.set(lower, str);
      continue;
    }
    const dw = dwordValue(line);
    if (dw !== null) fields.set(lower, String(dw));
  }
  flush();

  return { hosts, refused, skipped };
}

/** PuTTY's own private-key file header. Offered here means the user picked a
 *  `.ppk` at this importer instead of a `.reg` export; checked by CONTENT
 *  rather than by extension, matching this codebase's own never-trust-the-
 *  extension discipline (`parseBackupFile` does the same for a
 *  `.tervia-ssh`/`.tervia-backup` file). The caller refuses with a message
 *  pointing at the Vault's key editor instead of at host import. */
export function isPuttyPrivateKeyFile(text: string): boolean {
  return text.trimStart().startsWith("PuTTY-User-Key-File-");
}
