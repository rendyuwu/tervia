/**
 * Pure `ssh_config` grammar: stanza splitting and directive parsing, kept free
 * of the Tauri runtime for the same reason `file.ts`'s own header states -
 * `scripts/foreign-import-verify.ts` exercises it under plain node.
 * `foreignImport.ts` is the Tauri-dependent layer on top: it resolves an
 * `IdentityFile` path, reads and inspects the key, and resolves `ProxyJump`
 * against `listHosts()`; this file only extracts what the config text itself
 * says, case-insensitively, the same way OpenSSH's own parser does.
 *
 * ONE HOST RECORD PER ALIAS. `Host prod prod.internal` becomes two imported
 * hosts sharing the same directive block, not one - dropping every alias but
 * the first would be silent data loss (a name the user can literally type
 * after `ssh `), where a near-duplicate second row is visible and one delete
 * away from fixed. `resolveProxyJumpChain`'s caller resolves an alias by
 * FIRST OCCURRENCE when two different `Host` lines claim the same literal
 * text - a corner case, resolved deterministically rather than refused.
 *
 * DIRECTIVES READ: `HostName` (default = the alias), `Port`, `User`,
 * `ProxyJump`, `IdentityFile`. Everything else that is not one of the four
 * refusal keywords below is silently ignored, because none of it changes
 * *where* or *how* the dial happens - the two things a `Host` record and its
 * credential binding can express. Considered and left ignored:
 * `IdentitiesOnly`, `ForwardAgent`, `AddKeysToAgent`,
 * `ServerAliveInterval`/`CountMax`, `TCPKeepAlive`, `Compression`,
 * `ConnectTimeout`, `StrictHostKeyChecking`, `UserKnownHostsFile`,
 * `HashKnownHosts`, `CheckHostIP`, `VisualHostKey`,
 * `PreferredAuthentications` (Tervia's own auth mode already governs what is
 * tried; this only reorders negotiation), `Ciphers`/`MACs`/`KexAlgorithms`/
 * `HostKeyAlgorithms`, `ControlMaster`/`ControlPath`/`ControlPersist`,
 * `EscapeChar`, `LogLevel`, `SendEnv`/`SetEnv`, `RequestTTY`, `GatewayPorts`,
 * `AddressFamily`, `BindAddress`, and `LocalForward`/`RemoteForward`/
 * `DynamicForward` (forwarding happens after the connection already exists;
 * a `ForwardRule` is a different record this issue's acceptance boxes never
 * ask for).
 */
import { port } from "./file";

/** Opaque, `h-` prefixed, minted here rather than through `hosts/store.ts`'s
 *  own `newHostId` - importing that would pull the whole Tauri-backed store
 *  into a module that has to stay loadable under plain node. Same shape as
 *  the three existing copies of this helper (`hosts/store.ts`,
 *  `vault/store.ts`, `forwards/store.ts`), each duplicated for that reason -
 *  but shared between the two PURE parsers rather than duplicated a fourth
 *  time, since `puttyRegImport.ts` already imports `ParsedForeignHost` from
 *  this module and neither reaches Tauri. */
export function newId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

/**
 * One imported host's fields before `IdentityFile`/`ProxyJump` are resolved
 * against the live store - `foreignImport.ts` does both. Shared with
 * `puttyRegImport.ts`, whose sessions fill the same shape with no
 * `proxyJumpTokens`/`identityFilePath`.
 */
export type ParsedForeignHost = {
  id: string;
  /** What the user types after `ssh `, or the PuTTY session name. Becomes the
   *  saved host's `name`. */
  alias: string;
  host: string;
  port: number;
  user: string;
  /** Raw `ProxyJump` tokens, in the order written - `[a, b]` for
   *  `ProxyJump a,b` means "connect to a, then from a to b, then to this
   *  host", the same order `ssh -J a,b` means. Absent (or a bare `none`)
   *  means no jump. */
  proxyJumpTokens?: string[];
  /** Unexpanded: may start with `~/`, be relative to the config file's own
   *  directory, or already be absolute. `foreignImport.ts` resolves it. */
  identityFilePath?: string;
};

export type SshConfigRefusalReason = "match" | "wildcardHost" | "include" | "proxyCommand";

export type SshConfigParseResult = {
  hosts: ParsedForeignHost[];
  refused: Record<SshConfigRefusalReason, number>;
  /** A stanza that parsed but produced no usable host - today only an
   *  invalid `Port` - one number, not a diagnosis, matching
   *  `sanitizePayload`'s own `skipped` in `file.ts`. */
  skipped: number;
};

/** Whether a `Host` pattern is one concrete alias: no glob (`*`/`?`) and no
 *  negation (`!pattern`). A stanza is refused as a whole when ANY of its
 *  space-separated patterns fails this - a stanza that lists a concrete alias
 *  alongside a wildcard is still a pattern-matching rule, not a request to
 *  import one host under two names. */
function isConcreteAlias(pattern: string): boolean {
  return (
    pattern.length > 0 &&
    !pattern.includes("*") &&
    !pattern.includes("?") &&
    !pattern.startsWith("!")
  );
}

/** One `Keyword value` / `Keyword=value` line (comment and blank already
 *  stripped by the caller), lower-cased keyword, quotes stripped from the
 *  value. `null` for a line with nothing on it. */
function directive(line: string): { keyword: string; value: string } | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  const eq = trimmed.indexOf("=");
  const sp = trimmed.search(/\s/);
  const at = sp === -1 ? eq : eq === -1 ? sp : Math.min(eq, sp);
  if (at === -1) return { keyword: trimmed.toLowerCase(), value: "" };
  const keyword = trimmed.slice(0, at).toLowerCase();
  let value = trimmed.slice(at + 1).trim();
  if (value.startsWith("=")) value = value.slice(1).trim();
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1);
  }
  return { keyword, value };
}

/** One stanza's accumulated directives. First occurrence per keyword wins,
 *  matching OpenSSH's own first-match-wins precedence within one stanza. */
type Stanza = { aliases: string[]; fields: Map<string, string> };

export function parseSshConfig(text: string): SshConfigParseResult {
  const hosts: ParsedForeignHost[] = [];
  const refused: Record<SshConfigRefusalReason, number> = {
    match: 0,
    wildcardHost: 0,
    include: 0,
    proxyCommand: 0,
  };
  let skipped = 0;

  let current: Stanza | null = null;
  // Set while inside a `Match` block or a wildcard/negated `Host` block: every
  // directive up to the next `Host`/`Match` line belongs to a stanza already
  // refused and counted, and must not also be read as a global directive.
  let inRefusedBlock = false;

  const flush = () => {
    if (!current) return;
    for (const alias of current.aliases) {
      const host = current.fields.get("hostname")?.trim() || alias;
      const rawPort = current.fields.get("port");
      const p = rawPort === undefined ? 22 : port(Number(rawPort));
      if (p === null) {
        skipped++;
        continue;
      }
      const user = current.fields.get("user")?.trim() ?? "";
      const proxyJump = current.fields.get("proxyjump")?.trim();
      const identityFile = current.fields.get("identityfile")?.trim();
      const tokens =
        proxyJump && proxyJump.toLowerCase() !== "none"
          ? proxyJump
              .split(",")
              .map((t) => t.trim())
              .filter(Boolean)
          : [];
      hosts.push({
        id: newId("h"),
        alias,
        host,
        port: p,
        user,
        ...(tokens.length > 0 ? { proxyJumpTokens: tokens } : {}),
        ...(identityFile ? { identityFilePath: identityFile } : {}),
      });
    }
    current = null;
  };

  for (const raw of text.split(/\r\n|\r|\n/)) {
    // `#` starts a comment that runs to end of line. None of the five
    // directives this parser reads legitimately contains one, so this is
    // stripped before the value is otherwise touched.
    const d = directive(raw.split("#")[0]);
    if (!d) continue;

    if (d.keyword === "include") {
      // A stanza that pulls in a file this reader never opened is refused
      // whole, the same treatment ProxyCommand gets below: a directive this
      // stanza is missing (or one it already has, wrongly) may live in the
      // included file. Top-level (no stanza open yet) is still counted -
      // it names a directive this reader refuses to honor even though
      // nothing is being discarded. Already inside a refused block, it is
      // not counted again: that stanza's single refusal already covers it.
      if (current) {
        refused.include++;
        current = null;
        inRefusedBlock = true;
      } else if (!inRefusedBlock) {
        refused.include++;
      }
      continue;
    }

    if (d.keyword === "match") {
      flush();
      inRefusedBlock = true;
      refused.match++;
      continue;
    }

    if (d.keyword === "host") {
      flush();
      inRefusedBlock = false;
      const patterns = d.value.split(/\s+/).filter(Boolean);
      if (patterns.length === 0) continue;
      if (!patterns.every(isConcreteAlias)) {
        refused.wildcardHost++;
        inRefusedBlock = true;
        continue;
      }
      current = { aliases: patterns, fields: new Map() };
      continue;
    }

    if (inRefusedBlock || !current) continue;

    if (d.keyword === "proxycommand") {
      refused.proxyCommand++;
      current = null;
      inRefusedBlock = true;
      continue;
    }

    if (!current.fields.has(d.keyword)) current.fields.set(d.keyword, d.value);
  }
  flush();

  return { hosts, refused, skipped };
}

/**
 * `ProxyJump` resolution over already-resolved lookups, pure so it is
 * unit-testable without a store - `foreignImport.ts` supplies `lookup` from
 * the file's own aliases (first occurrence) and `await listHosts()`.
 *
 * A SINGLE TOKEN resolves straightforwardly; unresolved, it is silently
 * dropped (`proxyJumpId` absent, `chainUnresolved: false`) - the same "clear
 * a dangling jump and say nothing" `clearDanglingJumps` in `file.ts` already
 * does for the existing backup importer, with no dedicated counter today.
 *
 * A COMMA CHAIN (`tokens.length > 1`) maps only when every token resolves AND
 * the resolved chain already agrees with what each hop's own `proxyJumpId`
 * says: for `[a, b]`, host(b)'s stored/resolved `proxyJumpId` must already
 * equal host(a)'s id. Tervia's chain model has no way to synthesize a bridge
 * host for a token naming neither a stanza nor a saved host, so an
 * inconsistent or partially-unresolved chain is refused outright
 * (`chainUnresolved: true`) rather than partially applied - the caller counts
 * that refusal, unlike the silent single-hop drop above.
 */
export function resolveProxyJumpChain(
  tokens: readonly string[],
  lookup: (token: string) => { id: string; proxyJumpId?: string } | undefined,
): { proxyJumpId?: string; chainUnresolved: boolean } {
  if (tokens.length === 1) {
    const hop = lookup(tokens[0]);
    return hop ? { proxyJumpId: hop.id, chainUnresolved: false } : { chainUnresolved: false };
  }

  const hops = tokens.map(lookup);
  if (hops.some((h) => !h)) return { chainUnresolved: true };
  for (let i = 0; i < hops.length - 1; i++) {
    if (hops[i + 1]!.proxyJumpId !== hops[i]!.id) return { chainUnresolved: true };
  }
  return { proxyJumpId: hops[hops.length - 1]!.id, chainUnresolved: false };
}
