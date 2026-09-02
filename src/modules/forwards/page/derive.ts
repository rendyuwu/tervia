import { hasWordBoundaryMatch } from "@/lib/searchTiers";
import type { Host } from "@/modules/hosts/types";

import type { ForwardRule } from "../types";

// Everything the Port Forwarding page derives from its two inputs - the rule
// list and the host list - as PURE FUNCTIONS over plain data.
//
// No React and no store access, which is the whole reason
// `scripts/forwards-page-verify.ts` can exist: mirrors `modules/vault/page/derive.ts`
// in shape and purpose, right down to sharing `hasWordBoundaryMatch` from
// `@/lib/searchTiers` so the ranked searches across the app cannot disagree
// about what a word boundary is.
//
// Deliberately does NOT know whether a rule is running. That answer comes from
// the SSH runtime (`modules/forwards/runtime.ts`), not from anything
// persisted, and a `ForwardRule` on its own cannot say it - this file only
// ever sees a `ForwardRule` and a host map. Every function that needs a
// runtime fact - `localPortLabel`'s `boundPort`, `deleteNote`'s `running` -
// takes it as a plain argument instead of reaching for a store.

/** What {@link ruleRows} reports for a `hostId` naming a host the store does
 *  not have. A named label rather than `undefined`, because a rule's host is
 *  never optional - unlike `IdentityRow.keyName`, there is no "names no host
 *  at all" case for a dangling reference to be confused with. */
export const UNKNOWN_HOST_LABEL = "Unknown host";

export type ForwardRuleRow = {
  rule: ForwardRule;
  /** The SSH host's display name, or {@link UNKNOWN_HOST_LABEL}. */
  hostName: string;
  /** `hostId` names a host the store does not have. A separate field from the
   *  label, for the reason `IdentityRow.keyDangling` (`vault/page/derive.ts:69`)
   *  is separate from `keyName`: a host genuinely named "Unknown host" would
   *  render identically to a dangling reference, and only a structural flag
   *  can tell the two apart. */
  hostDangling: boolean;
  /** The route, ready to render: `localhost:18080 → bastion → 10.0.0.9:5432`. */
  route: string;
};

/**
 * One row per rule, everything the page shows precomputed.
 *
 * THE row builder, for every mount point that will ever list rules - mirrors
 * `identityRows` (`vault/page/derive.ts:122`) in contract and for the same
 * reason: a shared pure function guarantees nothing about callers that
 * assemble its arguments separately, so the assembly itself has to be the
 * shared thing.
 *
 * Returns a FRESH array on every call, the same as any function ending in
 * `.map` does - this is a plain function, not a memoized selector. A caller
 * MUST wrap the call in `useMemo` keyed on its two arguments, and must never
 * call it directly inside a zustand selector: a fresh array read as "changed"
 * on every store broadcast re-renders forever (v5 throws "Maximum update
 * depth exceeded" outright).
 *
 * `route` is built from `rule.localPort` alone, via {@link localPortLabel}
 * with no `boundPort` - this function has no runtime state to hand it one.
 * A page that knows a rule is running and wants the row to say the ACTUAL
 * bound port must recompute that one field itself; this row is the
 * configuration's own route, not a live one.
 */
export function ruleRows(
  rules: readonly ForwardRule[],
  hosts: ReadonlyMap<string, Host>,
): ForwardRuleRow[] {
  return rules.map((rule) => {
    const host = hosts.get(rule.hostId);
    const hostName = host ? host.name : UNKNOWN_HOST_LABEL;
    return {
      rule,
      hostName,
      hostDangling: host === undefined,
      route: `${localPortLabel(rule, undefined)} → ${hostName} → ${rule.remoteHost}:${rule.remotePort}`,
    };
  });
}

/**
 * `name` case-insensitively, then `id` - the shared tail of the ordering, on
 * the same terms as `byNameThenId` (`vault/page/derive.ts:168`). The `id`
 * tie-break is what makes the order TOTAL: without it, two rows equal on name
 * would keep whatever relative order the input happened to have, so two
 * surfaces fed the same rules in different iteration order could disagree
 * about which one shows first.
 */
function compareRuleRows(a: ForwardRuleRow, b: ForwardRuleRow): number {
  const byName = a.rule.name.toLowerCase().localeCompare(b.rule.name.toLowerCase());
  if (byName !== 0) return byName;
  return a.rule.id.localeCompare(b.rule.id);
}

/**
 * The strongest tier `row` qualifies for against a lowercased, non-empty
 * `query`, or `null` when it matches none. Checked strongest-first and
 * returns on the first hit, mirroring `identityMatchTier`'s shape
 * (`vault/page/derive.ts:192`).
 *
 * `localPort` and `remotePort` are matched as STRINGS, in the substring tier
 * ONLY - never as a prefix, the same trap §4.37 already named for a different
 * field. A port is a short, dense numeric string, so a prefix test over one
 * matches far too much: a query of "1" would prefix-match every rule bound to
 * port 1, 18080, 1194 or 100 alike. The discriminating part of a port is the
 * whole of it, which only a substring test respects.
 */
function ruleMatchTier(row: ForwardRuleRow, query: string): number | null {
  const name = row.rule.name.toLowerCase();
  const remoteHost = row.rule.remoteHost.toLowerCase();
  const hostName = row.hostName.toLowerCase();
  const localPort = String(row.rule.localPort);
  const remotePort = String(row.rule.remotePort);

  if (name === query) return 1;
  if (name.startsWith(query)) return 2;
  if (hasWordBoundaryMatch(name, query)) return 3;
  if (remoteHost.startsWith(query)) return 4;
  if (
    name.includes(query) ||
    remoteHost.includes(query) ||
    hostName.includes(query) ||
    localPort.includes(query) ||
    remotePort.includes(query)
  ) {
    return 5;
  }
  return null;
}

/**
 * Filter and rank rules, case-insensitively, over name, remote host, the
 * bound host's name and (substring tier only) both ports. Same default-order
 * and drop-non-matches rules as `rankIdentities`: an empty or whitespace-only
 * query returns every row in its default order (name, then id), and a row
 * matching no tier is DROPPED, not sorted to the bottom.
 */
export function rankRules(rows: readonly ForwardRuleRow[], query: string): ForwardRuleRow[] {
  const trimmed = query.trim().toLowerCase();
  if (trimmed.length === 0) {
    return [...rows].sort(compareRuleRows);
  }

  const matched: Array<{ row: ForwardRuleRow; tier: number }> = [];
  for (const row of rows) {
    const tier = ruleMatchTier(row, trimmed);
    if (tier !== null) matched.push({ row, tier });
  }

  matched.sort((a, b) => (a.tier !== b.tier ? a.tier - b.tier : compareRuleRows(a.row, b.row)));
  return matched.map((m) => m.row);
}

/**
 * The local endpoint of a rule, in the form the page renders it: the
 * auto/pinned/bound three-way that keeps a RUNNING rule honest about which
 * port it actually got.
 *
 * `boundPort` wins whenever it is known, regardless of what `rule.localPort`
 * asked for - a pinned rule whose requested port differs from the port it was
 * actually bound to (mid-connect PID reuse, another process winning the race)
 * must show the port that is ACTUALLY LISTENING, never the number the rule
 * merely asked for. Showing the requested port for a running rule is exactly
 * what §4.10's second defect produced.
 */
export function localPortLabel(rule: ForwardRule, boundPort: number | undefined): string {
  if (boundPort !== undefined) return `localhost:${boundPort}`;
  return rule.localPort === 0 ? "Auto" : `localhost:${rule.localPort}`;
}

/** The one sentence {@link bindFailureText}'s permission-denied arm and
 *  {@link privilegedPortWarning} share, so a bind actually refused for
 *  lacking administrator rights and an editor warning about the same fact
 *  never drift into two different sentences. */
function needsAdminRightsSentence(port: number): string {
  return `Port ${port} needs administrator rights. Pick a port above 1024.`;
}

/**
 * Turns `ssh: bind 127.0.0.1:<port> failed: <io error>` into one of four
 * sentences (research §12.8), matched on the io error text itself. This is
 * inherently string-matching against an OS message, not a structural
 * decision - none of the four cases below claims otherwise.
 *
 * The FALLBACK arm is the important one: it passes the raw message through
 * UNCHANGED, so a bind failure this table does not recognise is still
 * legible to whoever reads it. A `default` arm that swallowed it behind
 * "could not bind" would hide the one message a bug report actually needs.
 */
export function bindFailureText(error: string, localPort: number): string {
  // Lower-cased ONCE and matched against lower-case needles, because what the
  // backend actually sends is `std::io::Error`'s Display and that is prose with
  // a capital letter: `session.rs:443` is
  // `format!("ssh: bind 127.0.0.1:{local_port} failed: {e}")`, so a real
  // EADDRINUSE arrives as "Address already in use (os error 98)" on Linux, "…
  // (os error 48)" on macOS, and "Only one usage of each socket address
  // (protocol/network address/port) is normally permitted. (os error 10048)" on
  // Windows. The SYMBOLIC names are matched too and they are the cheap half:
  // nothing in the pipeline emits them today, they cost one `||` each, and they
  // are what a backend that ever switches to `errno` names would send.
  const io = error.toLowerCase();
  // Checked BEFORE the permission-denied case below, not after. Two reasons,
  // and both were live: "wsaeacces" contains "eacces", and the Windows message
  // for 10013 contains the words "access permissions", so a
  // permission-denied-first check would take every Windows-specific failure
  // and this sentence would never fire.
  if (
    io.includes("os error 10013") ||
    io.includes("wsaeacces") ||
    io.includes("forbidden by its access permissions")
  ) {
    return (
      "Windows reserves some port ranges for Hyper-V and WSL2, and they do not appear in " +
      "netstat. Run netsh interface ipv4 show excludedportrange protocol=tcp to see them."
    );
  }
  const permissionDenied = io.includes("eacces") || io.includes("permission denied");
  // `>= 1` and not just `< 1024`, matching {@link privilegedPortWarning}'s own
  // guard exactly. `localPort` here is the port the rule ASKED FOR, and 0 means
  // "let the OS pick" - so `0 < 1024` is true and an auto-port rule would be
  // told "Port 0 needs administrator rights. Pick a port above 1024.", which
  // names a port that does not exist and prescribes something the rule already
  // does. The two functions share `needsAdminRightsSentence` precisely so they
  // cannot disagree about the words; they have to agree about the RANGE too, or
  // the shared sentence is just a shared way of being wrong.
  if (permissionDenied && localPort >= 1 && localPort < 1024) {
    return needsAdminRightsSentence(localPort);
  }
  // "address in use" is a SUBSTRING of neither real message - Linux and macOS
  // say "address already in use", with "already" splitting the phrase, and
  // Windows says none of those words at all. So all three spellings are
  // needed; the port-number forms are `os error`-qualified so a rule pinned to
  // port 10048 cannot read its own number as an error code.
  const addressInUse =
    io.includes("eaddrinuse") ||
    io.includes("address already in use") ||
    io.includes("address in use") ||
    io.includes("os error 10048") ||
    io.includes("only one usage of each socket address");
  // `localPort !== 0` for the same reason the permission arm needs `>= 1`: this
  // sentence NAMES the port, and for an auto-port rule the number it would name
  // is 0, which nothing was ever listening on. An auto rule that somehow gets
  // this failure falls through to the raw message instead, which is the one
  // honest thing available - the port the OS actually picked is not knowable
  // here, because a bind that failed bound nothing.
  if (addressInUse && localPort !== 0) {
    return `Port ${localPort} is already in use on this machine.`;
  }
  return error;
}

/**
 * A sentence for a `localPort` the editor should warn about before the user
 * ever tries to start the rule (research §12.8: the editor warns at entry,
 * not at start), or `undefined` for a port that needs no warning.
 *
 * `0` ("let the OS pick") gets no warning: the OS never hands out an
 * ephemeral port below 1024, so the fact this checks for cannot be true of
 * it.
 */
export function privilegedPortWarning(localPort: number): string | undefined {
  return localPort >= 1 && localPort < 1024 ? needsAdminRightsSentence(localPort) : undefined;
}

/**
 * The two-sentence Stop copy, as one function so the Stop button's tooltip
 * and the row's status line say it identically rather than drifting into two
 * paraphrases of the same fact.
 */
export function stopNote(): string {
  return (
    "No new connections; connections already open keep running until one side closes. " +
    "The SSH session stays up while anything else is using it."
  );
}

/**
 * The facts {@link deleteNote} needs, and no more - the page's own pending-delete
 * state carries `id` and `name` too (for the title and any refusal message),
 * but this type only takes what decides which sentence is TRUE. A structural
 * subset on purpose, for the same reason `DeleteNoteSubject`
 * (`vault/page/derive.ts:368`) is one: this file is store-free by design (see
 * the header above), so it has no way to ask a `ForwardRuleRow` whether the
 * rule is currently running - that answer lives in the runtime layer, not in
 * anything persisted. The page's wider type is assignable here without a
 * cast.
 */
export type DeleteNoteSubject = { running: boolean; startWithHost: boolean };

/**
 * What the confirm dialog says about deleting this rule, said in terms of
 * what actually happens to THIS rule rather than a blanket sentence for every
 * rule alike.
 *
 * Modelled on `deleteNote` (`vault/page/derive.ts:401`), and needed for the
 * same reason: a single sentence would be one thing for every rule, but a
 * running rule and a rule that starts with its host each have something
 * specific and true to say, and neither fact implies the other.
 */
export function deleteNote(subject: DeleteNoteSubject): string {
  const runningNote = subject.running
    ? "Stopping it first is not required — deleting a running rule stops it."
    : null;
  const startNote = subject.startWithHost
    ? "It will no longer start automatically with its host."
    : null;

  if (runningNote && startNote) return `${runningNote} ${startNote}`;
  if (runningNote) return runningNote;
  if (startNote) return startNote;
  // Neither running nor starting with its host: deleting it changes nothing
  // else. Said outright rather than omitted - a blank space where the other
  // three cases all say something reads as an unfinished dialog, not as
  // "nothing to see", the same reasoning vault's own fallback arm gives.
  return "Deleting it changes nothing else.";
}
