/**
 * Self-check for the `ssh_config`/PuTTY `.reg` foreign-import GRAMMAR: stanza
 * splitting and directive parsing in `sshConfigImport.ts`/`puttyRegImport.ts`.
 * Run: `pnpm verify foreign-import-verify` (or `npx tsx
 * scripts/foreign-import-verify.ts` to iterate).
 *
 * Deliberately does NOT re-check `clearDanglingJumps`/`refuseProtocolConflicts`/
 * `orderHostWrites` - those already have `scripts/backup-verify.ts`, and the
 * host-import backlog item's own "Checks" note asks for exactly that: this
 * suite is for the grammar this project has never read before (stanza
 * splitting, directive parsing, the `.reg` shape), not a second copy of the
 * merge machinery it reuses unchanged.
 *
 * Kept free of the Tauri runtime, same as the two modules under test: neither
 * imports `@tauri-apps/api` or `invoke`, only `port` from `backup/file.ts`.
 */
import { port } from "../src/modules/backup/file";
import { isPuttyPrivateKeyFile, parsePuttyReg } from "../src/modules/backup/puttyRegImport";
import { parseSshConfig, resolveProxyJumpChain } from "../src/modules/backup/sshConfigImport";

let failed = 0;

function shape(v: unknown): string {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (Array.isArray(v)) return `[${v.map(shape).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${shape(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? String(v);
}

function check(label: string, got: unknown, want: unknown): void {
  const found = shape(got);
  const wanted = shape(want);
  if (found === wanted) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${found}, want ${wanted}`);
    failed++;
  }
}

function throwsIncluding(label: string, fn: () => unknown, needle: string): void {
  try {
    fn();
    console.error(`  FAIL: ${label} did not throw`);
    failed++;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.toLowerCase().includes(needle.toLowerCase())) {
      console.log(`  ok: ${label}`);
    } else {
      console.error(`  FAIL: ${label} threw "${msg}", expected to mention "${needle}"`);
      failed++;
    }
  }
}

// --- ssh_config: stanza splitting and field mapping ------------------------

{
  const cfg = `
# a comment, and a blank line above
Host prod
  HostName prod.example.com
  Port 2222
  User deploy
`;
  const r = parseSshConfig(cfg);
  check("one Host stanza -> one host", r.hosts.length, 1);
  check(
    "HostName/Port/User mapped",
    {
      host: r.hosts[0].host,
      port: r.hosts[0].port,
      user: r.hosts[0].user,
    },
    { host: "prod.example.com", port: 2222, user: "deploy" },
  );
  check("no refusals for a clean stanza", r.refused, {
    match: 0,
    wildcardHost: 0,
    include: 0,
    proxyCommand: 0,
  });
  check("nothing skipped", r.skipped, 0);
}

{
  const r = parseSshConfig("Host bare\n  Port 22\n");
  check("HostName absent defaults to the alias", r.hosts[0].host, "bare");
}

{
  // `Keyword=value`, quoted value, unknown directive ignored.
  const cfg = 'Host quoted\n  HostName="q.example.com"\n  Compression yes\n';
  const r = parseSshConfig(cfg);
  check("Keyword=value with a quoted value", r.hosts[0].host, "q.example.com");
  check("an unrecognised directive (Compression) does not refuse the stanza", r.hosts.length, 1);
}

{
  // One Host line, several concrete aliases -> one record per alias, same fields.
  const cfg = "Host prod prod.internal\n  HostName prod.example.com\n";
  const r = parseSshConfig(cfg);
  check("Host with two aliases -> two host records", r.hosts.length, 2);
  check(
    "both share the same HostName",
    r.hosts.map((h) => h.host),
    ["prod.example.com", "prod.example.com"],
  );
  check(
    "aliases preserved, in order",
    r.hosts.map((h) => h.alias),
    ["prod", "prod.internal"],
  );
  check("each alias gets its own id", r.hosts[0].id === r.hosts[1].id, false);
}

// --- ssh_config: the four refused-and-counted directives --------------------

{
  // The stanza carrying `ProxyCommand` is itself the one refused whole - `bad`
  // never surfaces a `host` field, only the count. `ok1` (before it) and `ok3`
  // (after it) both still import, which is the property under test: one
  // refused stanza does not abandon the rest of the file.
  const cfg = `
Match host prod
  User someone

Host ok1
  HostName ok1.example.com

Host prod*
  HostName wild.example.com

Include other.conf

Host bad
  HostName bad.example.com
  ProxyCommand nc -x proxy.example.com %h %p

Host ok3
  HostName ok3.example.com
`;
  const r = parseSshConfig(cfg);
  check(
    "Match, wildcard Host, Include and ProxyCommand each refuse their own stanza; ok1/ok3 still import",
    {
      aliases: r.hosts.map((h) => h.alias),
      refused: r.refused,
    },
    {
      aliases: ["ok1", "ok3"],
      refused: { match: 1, wildcardHost: 1, include: 1, proxyCommand: 1 },
    },
  );
}

{
  const r = parseSshConfig("Host neg\n  HostName x\nHost !neg\n  HostName y\n");
  check("a negated Host pattern (!alias) is refused as wildcardHost", r.refused.wildcardHost, 1);
}

// --- ssh_config: Port validation reuses port() ------------------------------

{
  check("port() itself: in range", port(2222), 2222);
  check("port() itself: 0 is invalid", port(0), null);
  check("port() itself: out of range is invalid", port(70000), null);
}

{
  const r = parseSshConfig("Host badport\n  HostName x\n  Port 0\n");
  check(
    "an invalid Port skips just that host, counted",
    { hosts: r.hosts.length, skipped: r.skipped },
    {
      hosts: 0,
      skipped: 1,
    },
  );
}

// --- ssh_config: ProxyJump token extraction ---------------------------------

{
  const r = parseSshConfig("Host t\n  HostName x\n  ProxyJump none\n");
  check("ProxyJump none carries no tokens", r.hosts[0].proxyJumpTokens, undefined);
}

{
  const r = parseSshConfig("Host t\n  HostName x\n  ProxyJump bastion\n");
  check("a single ProxyJump token", r.hosts[0].proxyJumpTokens, ["bastion"]);
}

{
  const r = parseSshConfig("Host t\n  HostName x\n  ProxyJump a, b\n");
  check("a comma-separated ProxyJump chain, whitespace trimmed", r.hosts[0].proxyJumpTokens, [
    "a",
    "b",
  ]);
}

// --- resolveProxyJumpChain: single hop and chain consistency ---------------

{
  const lookup = (t: string) => (t === "known" ? { id: "h-known" } : undefined);
  check("single token resolves", resolveProxyJumpChain(["known"], lookup), {
    proxyJumpId: "h-known",
    chainUnresolved: false,
  });
  check(
    "single unresolved token silently drops (no chainUnresolved)",
    resolveProxyJumpChain(["missing"], lookup),
    { chainUnresolved: false },
  );
}

{
  // a -> b -> target, and b's OWN proxyJumpId already names a: consistent chain.
  const lookup = (t: string) =>
    t === "a" ? { id: "id-a" } : t === "b" ? { id: "id-b", proxyJumpId: "id-a" } : undefined;
  check(
    "a consistent two-hop chain resolves to the outer hop's id",
    resolveProxyJumpChain(["a", "b"], lookup),
    { proxyJumpId: "id-b", chainUnresolved: false },
  );
}

{
  // b resolves but its OWN proxyJumpId does not name a - inconsistent.
  const lookup = (t: string) =>
    t === "a" ? { id: "id-a" } : t === "b" ? { id: "id-b", proxyJumpId: "id-other" } : undefined;
  check(
    "an inconsistent chain is refused, not partially applied",
    resolveProxyJumpChain(["a", "b"], lookup),
    { chainUnresolved: true },
  );
}

{
  const lookup = (t: string) => (t === "a" ? { id: "id-a" } : undefined);
  check(
    "a chain with one unresolved hop is refused and counted",
    resolveProxyJumpChain(["a", "missing"], lookup),
    { chainUnresolved: true },
  );
}

// --- PuTTY .reg: header, sessions, dword decode -----------------------------

const REG_HEADER = "Windows Registry Editor Version 5.00";

{
  throwsIncluding(
    "a .reg without the registry header throws a named format error",
    () => parsePuttyReg("not a registry file\n"),
    "putty registry export",
  );
}

{
  const reg = `${REG_HEADER}

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\Default%20Settings]
"HostName"="unused"

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\my%20box]
"HostName"="box.example.com"
"PortNumber"=dword:00000016
"UserName"="root"
"Protocol"="ssh"
`;
  const r = parsePuttyReg(reg);
  check("Default Settings is silently skipped, not counted", r.skipped, 0);
  check(
    "one real session imports, PortNumber dword decoded, name percent-decoded",
    {
      count: r.hosts.length,
      alias: r.hosts[0]?.alias,
      host: r.hosts[0]?.host,
      port: r.hosts[0]?.port,
      user: r.hosts[0]?.user,
    },
    { count: 1, alias: "my box", host: "box.example.com", port: 22, user: "root" },
  );
}

{
  const reg = `${REG_HEADER}

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\telnetbox]
"HostName"="t.example.com"
"PortNumber"=dword:00000017
"Protocol"="telnet"
`;
  const r = parsePuttyReg(reg);
  check(
    "a non-ssh Protocol is refused and counted under nonSsh",
    { hosts: r.hosts.length, refused: r.refused },
    {
      hosts: 0,
      refused: { nonSsh: 1, proxyMethodSet: 0 },
    },
  );
}

{
  const reg = `${REG_HEADER}

[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\proxied]
"HostName"="p.example.com"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"ProxyMethod"=dword:00000001
`;
  const r = parsePuttyReg(reg);
  check(
    "a ProxyMethod other than 0 is refused and counted under proxyMethodSet",
    {
      hosts: r.hosts.length,
      refused: r.refused,
    },
    { hosts: 0, refused: { nonSsh: 0, proxyMethodSet: 1 } },
  );
}

{
  check(
    "isPuttyPrivateKeyFile recognises the .ppk header",
    isPuttyPrivateKeyFile("PuTTY-User-Key-File-3: ssh-ed25519\n..."),
    true,
  );
  check(
    "isPuttyPrivateKeyFile is false for an ordinary .reg export",
    isPuttyPrivateKeyFile(`${REG_HEADER}\n`),
    false,
  );
}

console.log(failed === 0 ? "\nAll foreign-import checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
