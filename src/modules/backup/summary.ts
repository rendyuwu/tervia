import type { ImportResult } from "./apply";

// What the backup dialog SAYS about an export it just wrote and an import it just
// applied. The sentences only - nothing here renders one.
//
// No React, no store, no Tauri, so `scripts/backup-verify.ts` exercises every
// string here BY VALUE, the same discipline `hosts/editor/credentialChoice.ts`
// and `vault/editor/draft.ts` are held to and for the same reason. In
// `BackupDialog.tsx` both functions were module-private in a file that imports
// React, so no check could call one: the only thing holding either of them was a
// substring pin over its own source text, which says a guard expression is
// present and nothing at all about what the sentence reads.
//
// THE NON-ZERO CLAUSE RULE, which every clause below obeys and the two leading
// ones used not to. A collection earns its own clause only when it is non-zero,
// or a vault-only import opens "0 added, 0 updated" and a host-only one trails
// "0 identities, 0 keys, 0 rules" - both look broken. The one case the rule
// cannot answer for itself is an import that landed nothing at all, and
// `summarize` says below what it does there and why.
//
// EVERY FIELD IS READ AS `r.<collection>.<field>` AT THE POINT OF USE, never
// through a local alias of `r` or of one of its sub-objects. That is not a
// formatting preference and it is not free to change: `scripts/backup-verify.ts`
// derives the set of fields this file reads off these very expressions and
// partitions `ImportResult`'s leaves against it.
//
// An alias does not hide the field - the partition reddens and names it - but it
// reddens with a FALSE REASON, saying the field is not summarised when it is, and
// the obvious way to make that check green again is to add the field to
// {@link IMPORT_FIELDS_LEFT_UNSAID}. That would put a lie in the one list whose
// whole job is being true, and nothing downstream would ever catch it. Hence the
// rule here rather than a note there.

function plural(n: number, noun: string, pluralNoun?: string): string {
  return `${n} ${n === 1 ? noun : (pluralNoun ?? `${noun}s`)}`;
}

/**
 * The export result line's five-collection summary, under the module's non-zero
 * clause rule: a vault-only export would otherwise read "0 hosts, 0 host groups"
 * and a host-only one "0 identities, 0 keys, 0 rules".
 */
export function describeExport(counts: {
  hosts: number;
  groups: number;
  identities: number;
  keys: number;
  rules: number;
}): string {
  const parts: string[] = [];
  if (counts.hosts > 0) parts.push(plural(counts.hosts, "host"));
  if (counts.groups > 0) parts.push(plural(counts.groups, "host group"));
  if (counts.identities > 0) parts.push(plural(counts.identities, "identity", "identities"));
  if (counts.keys > 0) parts.push(plural(counts.keys, "vault key"));
  if (counts.rules > 0) parts.push(plural(counts.rules, "forward rule"));
  return parts.join(", ");
}

/**
 * Every leaf of {@link ImportResult} that {@link summarize} deliberately does NOT
 * read, with the reason it is left unsaid.
 *
 * THE LIST IS HALF OF A PARTITION, not a note. `scripts/backup-verify.ts`
 * enumerates `ImportResult`'s leaf fields through the TypeScript compiler API and
 * asserts every one of them is either read by `summarize` or named here, so a
 * field a later build adds to that type reddens instead of quietly joining the
 * ones below. The paths are the walk's own spelling: a nested field is
 * `<collection>.<field>`, a top-level one is bare.
 *
 * TWO CLASSES SIT IN HERE AND THEY ARE NOT EQUALLY SETTLED. Four of the six are
 * left unsaid because a clause would be WRONG - it would report an ordinary
 * re-import as a loss, or report a case that went right at all. Two of them -
 * `identities.withoutKeys` and `rules.dropped` - are rows the file carried that
 * did not arrive and that nothing else mentions either, and they are here because
 * the decision was to give three counters a clause and no more. Each entry says
 * which it is; the second pair is where an argument for a fourth clause belongs.
 */
export const IMPORT_FIELDS_LEFT_UNSAID: readonly string[] = [
  // A CLAUSE WOULD BE WRONG HALF THE TIME. It counts a password-auth identity
  // whose password did not travel, and cannot tell "the file carried none because
  // this machine already holds it" - the ordinary re-import - from "the file
  // carried none and neither does this machine". A keychain write that actually
  // REFUSED is a different fact and is named in `problems`, with its reason.
  "identities.withoutSecrets",
  // A ROW THAT DID NOT ARRIVE, AND NOTHING ELSE SAYS SO. Key auth naming a key
  // that will not exist here is skipped rather than downgraded, and a skipped
  // identity is in no other counter: not in `added`, not in `replaced`, and not
  // in `skipped`, which counts only what the parser refused. Left unsaid by the
  // three-clause decision, not because it is harmless.
  "identities.withoutKeys",
  // NOTHING TO DO ABOUT IT. Only a `keyId` that named nothing was cleared, and
  // the mode did not need one: the identity authenticates exactly as before.
  "identities.keysDropped",
  // WRONG HALF THE TIME, the same as `identities.withoutSecrets`: it counts a key
  // re-imported over a private body this machine already holds, where the key
  // works and only the FILE carried nothing.
  "keys.withoutSecrets",
  // A ROW THAT DID NOT ARRIVE, like `identities.withoutKeys`. The rule named a
  // host that will not exist here, or an RDP host, which has no SSH session for a
  // forward to ride - and neither the missing host nor the dropped rule is
  // reported. Left unsaid by the same decision, and it is the other entry worth
  // re-opening.
  "rules.dropped",
  // THE CASE THAT WENT RIGHT. Nothing was refused and nothing is missing: the
  // file's binding was applied exactly as it asked, on a host new to this machine
  // naming an identity that will exist. A clause for that is noise.
  "vaultBindingsApplied",
];

/** What one applied import has to say for itself: one sentence, plus one line per
 *  thing it could not do.
 *
 *  ONE RETURN RATHER THAN TWO FUNCTIONS, because the two are one report and the
 *  defect this shape fixes is precisely that the reasons were never fetched. A
 *  second function is one a caller can forget to call; a second field of the value
 *  it already has is one the caller has to decide, out loud, to drop. */
export type ImportSummary = {
  /** The sentence, always `Imported: ...`. A pure function of the result, so
   *  `scripts/backup-verify.ts` can assert it by value. */
  line: string;
  /** Verbatim from the result: `applyV3` pushes exactly one line per refusal it
   *  catches, and no record can produce two - a failed record write keeps that
   *  record out of the flag pass that would report it again.
   *
   *  EIGHT OF ITS NINE PUSH SITES NAME THE RECORD; the ninth is the credential
   *  write, and it is the arm this list was built for. Every account the import
   *  is going to write goes down in ONE `backup_apply_secrets` call - the landed
   *  keys and identities, plus the landed hosts that own their own accounts - so
   *  its refusal is a single line for that whole batch, naming nothing: "no
   *  stored credentials could be written to the keychain". A reader sizing the
   *  damage off the line count gets one for a file whose every secret was
   *  refused.
   *
   *  Rendered as a LIST rather than folded into `line`, because the line is one
   *  sentence and a forty-host import can carry several. */
  problems: string[];
};

/**
 * The import result line, and the refusals underneath it.
 *
 * THE REASON IS THE PART THAT WAS MISSING. Every clause below is a number, and a
 * number cannot say why: a forty-host file whose host twelve the store refused
 * reported thirty-nine added and nothing else, and a keys-and-identities file
 * whose keychain write threw reported both collections as landed with no hint
 * that the private bodies did not. `problems` is the only thing in the result
 * that answers either, which is why it travels with the line rather than beside
 * it.
 */
export function summarize(r: ImportResult): ImportSummary {
  const added = r.ssh.added + r.rdp.added;
  const replaced = r.ssh.replaced + r.rdp.replaced;
  const withoutSecrets = r.ssh.withoutSecrets + r.rdp.withoutSecrets;
  const sshHosts = r.ssh.added + r.ssh.replaced;
  const rdpHosts = r.rdp.added + r.rdp.replaced;
  // The per-protocol split only earns its space when both are present; a v1 file
  // or an SSH-only export would otherwise report "0 RDP".
  const split =
    rdpHosts > 0 && sshHosts > 0
      ? ` (${plural(sshHosts, "SSH host")}, ${plural(rdpHosts, "RDP host")})`
      : "";

  // THE SPLIT RIDES THE LAST HOST CLAUSE, not the end of the sentence, because
  // every clause after it is about another collection: trailing it would put
  // "(3 SSH hosts, 2 RDP hosts)" after a sentence about group names, where it
  // reads as qualifying that instead. It rode `updated` when that clause was
  // unconditional; now that either host clause can be absent it has to follow
  // whichever one is last. Appending "" is a no-op, and an EMPTY `hostParts`
  // cannot coincide with a non-empty split: the split needs a host on both
  // protocols, which needs at least one of these two clauses. Which means no
  // fixture can distinguish this guard from one that always fires - widening it
  // changes no output and reddens nothing, measured. `KNOWN-LIMITS.md` carries
  // that as an accepted state rather than counted coverage; retire the entry if
  // the split gains a second attachment point.
  const hostParts: string[] = [];
  if (added > 0) hostParts.push(`${added} added`);
  if (replaced > 0) hostParts.push(`${replaced} updated`);
  if (hostParts.length > 0) hostParts[hostParts.length - 1] += split;

  const parts: string[] = [...hostParts];
  if (r.skipped > 0) parts.push(`${r.skipped} skipped as unreadable`);
  if (withoutSecrets > 0) parts.push(`${withoutSecrets} without stored credentials`);
  const groupCount = r.groups.added + r.groups.replaced;
  const identityCount = r.identities.added + r.identities.replaced;
  const keyCount = r.keys.added + r.keys.replaced;
  const ruleCount = r.rules.added + r.rules.replaced;
  if (groupCount > 0) parts.push(plural(groupCount, "host group"));
  if (identityCount > 0) parts.push(plural(identityCount, "identity", "identities"));
  if (keyCount > 0) parts.push(plural(keyCount, "vault key"));
  if (ruleCount > 0) parts.push(plural(ruleCount, "forward rule"));

  // ONE NUMBER ACROSS THE SIX COLLECTIONS. Each collection already has its own
  // clause for what landed, and a refusal is rare enough that six more clauses
  // would double the sentence for a case most imports never reach. The words
  // matter as much as the number: "3 failed" beside "39 added" reads as if the
  // import failed, where what happened is that this machine's store would not
  // take three of the rows and took everything else.
  const failed =
    r.ssh.failed +
    r.rdp.failed +
    r.groups.failed +
    r.identities.failed +
    r.keys.failed +
    r.rules.failed;
  if (failed > 0) parts.push(`${plural(failed, "record")} the store refused`);
  // A row refused because the host already saved under that id speaks the OTHER
  // protocol. Replacing it would delete the secrets that host owns with nothing
  // copied first, so the row is refused rather than written.
  if (r.protocolConflicts > 0) {
    parts.push(
      `${plural(r.protocolConflicts, "row")} refused because the host saved here under that id speaks the other protocol`,
    );
  }
  // NOT DATA LOSS, and the clause has to survive being read by someone who
  // assumes it is. A backup carries no vault, so a binding the file declared
  // cannot always be honoured - and every row this counts either kept the
  // credential already saved on this machine (an incoming binding over a saved
  // inline host, over a saved binding to another identity, or an incoming inline
  // row over a saved binding) or arrived as a blank inline host, which is the one
  // arm where there was nothing here to keep. Never as a vault-bound record over
  // somebody else's secrets, which is the case the counter exists for.
  if (r.vaultBindingsDropped > 0) {
    parts.push(
      `${plural(r.vaultBindingsDropped, "row")} did not take the file's vault binding, so each kept the credential saved here or arrived blank`,
    );
  }

  // Not failures - `problems` is for what could not be done - but not silent
  // either: each is a case where the file's hosts landed in a group other than
  // the one the file named, and the file's own record of that is gone the moment
  // this import finishes.
  if (r.groups.merged > 0) {
    const noun = r.groups.merged === 1 ? "group's" : "groups'";
    parts.push(`${r.groups.merged} ${noun} hosts merged into an existing group of the same name`);
  }
  if (r.groups.keptNames > 0) {
    const noun = r.groups.keptNames === 1 ? "group's" : "groups'";
    parts.push(
      `${r.groups.keptNames} ${noun} hosts kept this machine's group name instead of the file's`,
    );
  }

  // THE ONE CASE THE NON-ZERO RULE CANNOT ANSWER, because there is no non-zero
  // clause left to fall back on. "nothing" and not an explanation, because every
  // explanation available is false for at least one of the ways to get here: an
  // empty payload, a file of forward rules that all dangled, a file of identities
  // all skipped for a key that did not travel. The fields that would tell those
  // apart are exactly the ones IMPORT_FIELDS_LEFT_UNSAID records as deliberately
  // unread, so saying which would mean promoting one of them, not wording this
  // better.
  return {
    line: `Imported: ${parts.length > 0 ? parts.join(", ") : "nothing"}.`,
    problems: [...r.problems],
  };
}
