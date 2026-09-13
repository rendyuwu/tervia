/**
 * Self-check for the repository's comment-citation rule.
 * Run: `npx tsx scripts/citation-format-verify.ts`.
 *
 * `TERVIA.md` and `CONTRIBUTING.md` both carry the rule: a comment may cite only
 * what a reader holding nothing but the clone can open. A checked-in file, a
 * symbol, a path in the repo, an upstream project's public tracker named with
 * its project, or a pinned dependency's own source named with its crate. A LINE
 * NUMBER is none of those, and it is the shape that fails worst, because it is
 * correct only until the next commit touches the file it names and it never
 * announces that it stopped being correct.
 *
 * That class had been measured, corrected and re-measured more than once before
 * this file existed, and every correction rotted again from the next commit
 * onward. A structural check is the only version of the property that cannot
 * drift, so this replaces the correcting.
 *
 * Six shapes fail here:
 *
 *   1. A NAMED line citation, a file spelling followed by a colon and a line.
 *      No exemption, not even for a pinned dependency: a line into a
 *      dependency's source is no more openable from a clone than a line into
 *      this repository's own file is durable, and naming the crate makes such a
 *      citation attributable without making it reachable.
 *   2. A BARE line reference, a colon and a line leaning on a file named
 *      earlier in the same paragraph. It names no file at all, so a reader who
 *      starts mid-comment cannot even tell what it is relative to.
 *   3. A BARE tracker reference. This project's own tracker is not in the tree,
 *      so a number alone is not reachable. Naming the project is what makes one
 *      reachable, which is why the allow-list of upstream projects is pinned
 *      too.
 *   4. A MALFORMED dependency citation: a pinned crate opening a parenthesis
 *      that does not go on to name that crate's pinned version and a symbol, on
 *      one line. What a dependency citation buys by naming its crate is the
 *      right to cite a SYMBOL, and only at the version the lockfile pins.
 *   5. An UNCREDITED one: the shape of a dependency citation, a version and a
 *      symbol in parentheses, crediting no crate at all. This is what keeps the
 *      allow-list load-bearing now that shape 1 has no exemption. Without it a
 *      citation could name a version and a symbol while attributing them to
 *      nothing, and no other detector here would see it.
 *   6. A DEAD PATH: a backticked file spelling naming no file in the checkout.
 *      The first five are about a citation's SHAPE and all five pass one that is
 *      beautifully formed and points at nothing.
 *
 * WHY THE SIXTH IS THE ONE NO CARE CAN REPLACE. The first five guard a class
 * that rots when the CITED file changes, which is frequent and shallow. This one
 * guards the class that rots when the cited file is deleted or renamed, which is
 * rare, total, and invisible from the side that causes it. Nothing in the
 * toolchain connects deleting a module to the comments elsewhere that name it,
 * and the citing file may never be opened again: measured on this branch, one
 * commit deleted two modules and left six comments in a third file naming them,
 * and no commit since has touched that file. Authoring-time care cannot catch
 * that, because at authoring time the citation was right. Only a sweep over the
 * whole tree can.
 *
 * A seventh class is MEASURED BUT NOT FAILED: a partial spelling whose name is
 * shared by several files and whose citing directory does not break the tie. It
 * is capped rather than forbidden. See `PARTIAL_PATH_CEILING`.
 *
 * WHY IT READS COMMENTS AND NOT SOURCE TEXT. Half this suite legitimately
 * carries a file spelling and a line inside a STRING literal: the fixtures quote
 * store payloads, error strings and JSON, and several scripts assert over text
 * that contains exactly the shape above. A scan over raw source would redden
 * those, which is not a check anybody could keep. `lib/comments.ts` extracts the
 * comments out of the parse instead, and its own two-direction self-test runs
 * first below, because an extractor that silently returns nothing would turn
 * every check here green.
 *
 * WHY THE ALLOW-LISTS ARE PINNED AS EXACT SETS. An allow-list that can grow
 * without anybody noticing is not an allow-list. Every set here is asserted
 * sorted, deduplicated and at an exact length, so adding an entry is a visible
 * diff in this file, and every pinned crate version is read back out of
 * `src-tauri/Cargo.lock` so the allow-list cannot outlive the pin it describes.
 *
 * EVERY EXEMPTION IS ALSO ASSERTED STILL NECESSARY, which is the half such a
 * list usually lacks. An entry whose spelling somebody has since checked in
 * stops being an exemption and becomes a blindfold over a citation that has
 * become perfectly good, and nothing about the list's own shape would show it.
 * So each entry is re-resolved on every run and has to still fail.
 *
 * WHAT IT DOES NOT SEE, SAID OUT LOUD. The standing rule forbids more than
 * these six shapes, and the rest of it is not mechanically checkable from a
 * comment's text. A row id from one of this project's planning documents is a
 * violation of exactly the same rule and of exactly the same kind, since a
 * reader holding the clone cannot open it either, but it is prose: nothing
 * distinguishes such an id from an ordinary capitalised phrase. Also unseen: a
 * date, a commit hash, and a hand-test label. Green here therefore means
 * "carries none of the shapes below", never "obeys the citation rule", and a
 * reviewer still has to read.
 *
 * FOUR SHAPES THAT WOULD ESCAPE EVERY DETECTOR HERE, none of them in the tree,
 * listed so the paragraph is not read as exhaustive when it is merely complete
 * about what was found. A citation wrapped exactly at its extension's dot, so
 * that the stem ends one comment line and the extension opens the next, splits
 * the token across two ranges and matches neither the named nor the bare
 * pattern. A source-host line anchor, hash-L followed by a number, carries no
 * colon and no bare hash-digit. The same claim written as prose, "line 484 of
 * the session module", is a line citation with no punctuation to key on. And an
 * extension-less stem with a colon, a component name followed by a range, has
 * neither an extension for the named pattern nor a delimiter before the colon
 * for the bare one. The first two are cheap to add if one ever appears; the
 * third is prose and unreachable; the fourth would need the extension
 * requirement relaxed, which is what keeps host-and-port out.
 *
 * A BACKTICK IS WHAT MARKS A CITATION, so the resolvability half sees only
 * backticked spellings and a bare unquoted path is invisible to it. An attached
 * tracker reference is the same kind of gap: `word#123` passes for any word,
 * which is what lets `PKCS#8` through, so a bare number can be laundered by
 * attaching anything to it. That is this
 * repository's own convention rather than a shortcut, and it is why prose in
 * this file that mentions a file name as an EXAMPLE leaves the backticks off.
 * It does mean the sixth shape can be evaded by dropping them.
 *
 * A DELIBERATELY DEAD NAME IS LEGITIMATE, AND NOT DETECTABLE. A comment may
 * name a file precisely in order to say it is gone, and then the dead name is
 * the point: the sentence is false if the file still exists, and deleting the
 * name leaves the paragraph with no subject. The same dead spelling cited in the
 * present tense, as a live mechanism, is simply wrong. Both were in this tree at
 * once, and the difference between them is TENSE AND GRAMMATICAL SUBJECT, which
 * is a property of meaning and not of text. No detector reading a comment can
 * tell them apart, and a heuristic over surrounding words would only encode a
 * guess about English. So `DELIBERATELY_DEAD` is a human judgement recorded as
 * a pinned entry rather than a rule, keyed on the citing file so it cannot
 * travel to a file that cites the same dead name as though it were alive. It is
 * the only place in this check where that is true, and if it ever grows past a
 * couple of entries the honest reading is that the class needs a convention in
 * the prose, not a longer list here.
 *
 * A SYMBOL IS NOT CHECKED, and this was measured rather than assumed. The only
 * test available without a type checker is whether the token appears somewhere
 * in the tree, which is too weak to establish that a symbol exists (a name
 * surviving in a string literal passes) and too strong to be usable: 131 of the
 * 2,342 distinct backticked identifiers in this tree's comments appear nowhere
 * in its comment-stripped code, and almost every one is legitimate. They name
 * Win32 entry points, a dependency's internals, TypeScript compiler node kinds,
 * DOM events, and external tools. The decisive case is `secrets_list`, cited 22
 * times across 12 files precisely BECAUSE it does not exist: the secrets IPC
 * surface names an account per call and exposes no listing command, and several
 * docblocks argue exactly that. A resolvability rule would redden all 22 for
 * being right. So the ratio on offer was about 186 false positives to 1 true
 * one, and a symbol can legitimately live in a dependency in any case. Out of
 * scope, deliberately.
 *
 * THAT SYMBOL IS NAMED HERE, AND ITS ABSENCE IS ASSERTED, which is what makes
 * naming it safe. Two checks below hold this paragraph's arithmetic: one that
 * `secrets_list` still appears nowhere outside a comment in the three roots, and
 * one that it is still cited 22 times inside them. The day somebody implements
 * such a command, or edits one of those comments, a check reddens and whoever is
 * holding it learns that this paragraph needs rewriting. A prose claim about the
 * tree is exactly as durable as the assertion standing behind it, and with no
 * assertion it is a line number by another name.
 *
 * THE ROW-ID CLASS ABOVE NAMES NO INSTANCE, and the contrast with `secrets_list`
 * is the point rather than an inconsistency. An earlier draft named one such row
 * id and the file holding it, which was true when written and false within the
 * hour, because the id was deleted. A comment asserting a state of the tree rots
 * on the next commit for the same reason a line number does, and the shape of
 * the mistake does not change just because the subject is a defect rather than a
 * location.
 *
 * What separates the two: a row id's absence is nobody's invariant, so it can
 * change without anyone noticing and no check could reasonably watch it, whereas
 * `secrets_list` not existing is a deliberate architectural property that 22
 * comments already assert and that a check here now watches. Name a fact when
 * something announces its change, and describe the class when nothing does.
 *
 * WHY THE CONTROLS ARE HERE AND NOT IN A NOTE SOMEWHERE. Both halves of this
 * check can fail silently: a detector that matches nothing passes the tree, and
 * a detector that matches a string literal reddens a file nobody can fix. The
 * `[controls]` section runs every shape against a fixture that must be flagged
 * AND a fixture that must not, so neither direction can rot unobserved. The
 * fixtures live in string literals in this file, which makes this file its own
 * standing proof of the string-literal case: the tree scan below covers
 * `scripts/`, so it reads this file too and must not flag a single one of them.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  commentRangesOf,
  commentScannerSelfTest,
  hasKnownCommentSyntax,
  lineNumbersFor,
} from "./lib/comments";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The directories the rule binds. Everything else is generated or vendored.
 *
 * `src-tauri/tervia-cli/src` is a SEPARATE CRATE and was outside the first three
 * for no better reason than that nobody had looked. It holds no citation today,
 * so widening cost nothing and found nothing, which is the point: a coverage gap
 * with no instances is still a gap, and this one sits in exactly the place a
 * citation into the main crate gets written and then rots, since the launcher's
 * whole job is explained by reference to the GUI binary it spawns. A directory
 * rather than the one file it currently holds, so a second file in that crate is
 * covered without anybody remembering to add it.
 */
const ROOT_DIRS = ["scripts", "src", "src-tauri/src", "src-tauri/tervia-cli/src"];

/**
 * Hand-written source that sits in no scanned directory.
 *
 * Both are single files at a level that holds mostly generated or vendored
 * content, so scanning their directories would sweep in far more than the rule
 * governs. Named individually and asserted to exist, because a typo here would
 * silently scan nothing and read as coverage.
 *
 * Not exhaustive over the repository root by design: `tsconfig.json` carries a
 * long comment, but `.json` is not a syntax this check's extractor knows, and
 * inventing one for a file with a single comment in it would be a worse trade
 * than the gap. That gap is real and is named here rather than left implicit.
 */
const ROOT_FILES = ["src-tauri/build.rs", "vite.config.ts"];

let failed = 0;
function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    console.log(`  ok: ${label}`);
    return;
  }
  console.error(`  FAIL: ${label}`, detail === undefined ? "" : JSON.stringify(detail, null, 1));
  failed++;
}

// ---------------------------------------------------------------------------
// The pinned allow-lists
// ---------------------------------------------------------------------------

/**
 * The dependency sources a comment may cite, as `crate version`.
 *
 * SORTED, DEDUPLICATED AND FIXED IN LENGTH, all three asserted below. The point
 * of the pin is that widening it costs a diff in this file rather than
 * happening as a side effect of somebody's comment.
 *
 * Every version here is checked against `src-tauri/Cargo.lock` on every run, so
 * an entry cannot survive the bump that invalidates it. A crate that is NOT on
 * this list is not citable at all: `Cargo.lock` pins far more than seven
 * crates, and the ones listed are the ones whose internals this repository
 * actually reasons about.
 *
 * DO NOT REBUILD THIS LIST FROM A VERSION SCAN. An earlier draft of it was
 * assembled by collecting the versions that appear in comments, and that method
 * is structurally blind to a crate cited WITHOUT one: `ironrdp-async` was named
 * in two comments with no version beside it, so a scan keyed on versions could
 * not see it and the list came out one entry short. The set is a statement about
 * which dependencies this code reasons about, not a summary of what the comments
 * happen to say, and only the lockfile can confirm an entry.
 */
const THIRD_PARTY_SOURCES = [
  "ironrdp-async 0.9.0",
  "ironrdp-connector 0.9.0",
  "ironrdp-input 0.6.0",
  "ironrdp-pdu 0.8.0",
  "ironrdp-session 0.10.0",
  "tauri 2.11.5",
  "tauri-plugin-window-state 2.4.1",
];

/**
 * The upstream projects whose public tracker a comment may cite by number IN
 * THE SPACE-SEPARATED FORM.
 *
 * Same discipline, same reason. A tracker number is reachable only through the
 * project that hosts it, so the project name is the citation and the number is
 * the argument. This project's own tracker is deliberately absent: it is not in
 * the tree, so nothing a clone holds can open it.
 *
 * THREE AND NOT FOUR, and the entry that came off is worth a note because
 * keeping it would have misrepresented the assertion beside it. A fourth entry
 * named a project cited only in the ATTACHED form, and the attached form never
 * consults this list: `BARE_TRACKER` refuses to fire when a word character
 * precedes the hash, which is what lets `PKCS#8` through and, with it, any
 * `project#123`. So that entry was never read, while "a sorted set of exactly
 * four entries" read as an assurance that all four were load-bearing. An
 * unexercised allow-list entry is the same shape as an unexercised exemption,
 * and this file refuses those elsewhere for the same reason. If the spaced form
 * of that project ever appears, the fix is one line and a visible diff, which is
 * what a pinned list is for.
 */
const UPSTREAM_TRACKERS = ["IronRDP", "Kitty", "xterm.js"];

const sortedSet = (xs: string[]): boolean =>
  xs.every((x, i) => i === 0 || xs[i - 1] < x) && new Set(xs).size === xs.length;

console.log("[allow-list] pinned, sorted, and still true of the lockfile");
check(
  "the third-party source allow-list is a sorted set of exactly 7 entries",
  sortedSet(THIRD_PARTY_SOURCES) && THIRD_PARTY_SOURCES.length === 7,
  THIRD_PARTY_SOURCES,
);
check(
  "the upstream tracker allow-list is a sorted set of exactly 3 entries",
  sortedSet(UPSTREAM_TRACKERS) && UPSTREAM_TRACKERS.length === 3,
  UPSTREAM_TRACKERS,
);

/** Every `name`/`version` pair `Cargo.lock` declares. */
const lockVersions = new Map<string, string>();
for (const m of readFileSync(join(ROOT, "src-tauri/Cargo.lock"), "utf8").matchAll(
  /\[\[package\]\]\r?\nname = "([^"]+)"\r?\nversion = "([^"]+)"/g,
)) {
  lockVersions.set(m[1], m[2]);
}
check("Cargo.lock parsed into package versions", lockVersions.size > 100, lockVersions.size);
for (const entry of THIRD_PARTY_SOURCES) {
  const [crate, version] = entry.split(" ");
  check(`Cargo.lock still pins ${crate} at ${version}`, lockVersions.get(crate) === version, {
    lockfile: lockVersions.get(crate) ?? null,
  });
}

// ---------------------------------------------------------------------------
// The five detectors
// ---------------------------------------------------------------------------

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * A file spelling followed by a colon and one or more line numbers.
 *
 * NO EXEMPTION, not even for a pinned dependency. A line into a dependency's
 * source is unverifiable whether or not the crate is named: no clone checks that
 * source out and nothing in CI can open it, so naming the crate makes the
 * citation attributable without making it reachable. Naming a crate buys the
 * right to cite its SYMBOL, which is what the allow-list below is for; it does
 * not buy a line. An earlier draft of this file exempted a crate-qualified line
 * and that was the one hole through which the shape this check exists to remove
 * could come back green.
 *
 * The extension list is closed rather than open (`\w+` after the dot) because
 * an open one matches a sentence's `word.Another:2` and, worse, matches an
 * enum-ish `Foo.Bar:1`. Closed to the extensions this repository actually has,
 * plus the two lockfile spellings, since those get cited too.
 *
 * The optional quote before the colon is not cosmetic. A citation written as
 * a backticked path followed by an unbacked range puts a backtick between the
 * extension and the colon, and a pattern demanding adjacency reads that as a
 * bare reference and reports it without the file name. Measured: zero comments
 * in the three roots put a quote-then-colon-then-digit anywhere else, so
 * allowing it costs no false positive and buys a citation the generated
 * inventory could not see at all.
 *
 * The trailing `[-,]` group is what makes a multi-line and a multi-target
 * citation one match rather than several: a range and a comma-separated list are
 * both a single rotted reference, and counting them apart would inflate a
 * failure report without adding a fact.
 */
const NAMED_CITATION =
  /[A-Za-z0-9_@./-]*[A-Za-z0-9_-]\.(?:tsx?|mts|cts|jsx?|mjs|cjs|rs|css|html|json|toml|md|lock|ya?ml)[`'"]?\s*:\s*\d+(?:\s*[-,]\s*\d+)*/g;

/**
 * A colon and a line number with nothing in front of it.
 *
 * The lookbehind is the whole design. Requiring a backtick, an opening bracket
 * or whitespace before the colon is what separates a citation leaning on a file
 * named a paragraph earlier from the two shapes that are not citations at all:
 * an authority in a URL or an address, and a JSON key in a quoted fixture, both
 * of which put a word character or a quote immediately before the colon. This
 * is a remote-desktop and SSH client, so a comment illustrating a forward with
 * a host and a port is ordinary prose here and appears across the forwards and
 * terminal modules; a scan without the lookbehind is unusable rather than
 * merely noisy. `C_HOST_PORT` and `C_NOT_A_CITATION` hold that line.
 */
const BARE_LINE = /(?<=[`([\s])(?::\s*\d+(?:\s*[-,]\s*\d+)*)(?![\d.\w])/g;

/**
 * A tracker number, permitted only when a pinned project is named beside it.
 *
 * Two exclusions, both measured against what this tree's comments actually
 * carry rather than guessed:
 *
 *   - `(?<![\w#])` lets a number ATTACHED to a word through, which covers both
 *     `plugins-workspace#3085` (a project naming its own tracker, permitted)
 *     and the several `PKCS#8` / `PKCS#1` mentions, which are format names and
 *     not citations at all.
 *   - a leading `0` and a trailing hex digit are both refused, which is what
 *     keeps the theme presets and the stylesheet out of it: a six-digit colour
 *     cannot survive either test, and no tracker numbers its issues from zero.
 *     A six-digit issue number would be missed, which fails towards silence on
 *     a shape this repository does not contain.
 */
const BARE_TRACKER = /(?<![\w#])#[1-9]\d{0,4}(?![\dA-Fa-f])/g;

/**
 * A backticked pinned crate opening a parenthesis, which is citation position.
 *
 * Scoped to `(` deliberately. Naming a dependency in prose is not citing it:
 * two comments legitimately read "after `tauri-plugin-window-state` has ..."
 * with no symbol in sight, and demanding a version there would redden ordinary
 * English. Every one of the 21 dependency citations in the tree opens a
 * parenthesis, so the parenthesis is what distinguishes the two.
 */
const DEP_OPENER = new RegExp(
  `\\(\`(?:${THIRD_PARTY_SOURCES.map((e) => escapeRe(e.split(" ")[0])).join("|")})\``,
  "g",
);

/**
 * The one well-formed shape, per pinned crate: crate, its exact pinned version,
 * then a backticked symbol, all inside one set of parentheses.
 *
 * `[ \t]` and never `\s` in the gaps, which is how the ONE-LINE requirement is
 * enforced rather than merely hoped for. A triple split across two comment lines
 * is malformed and reddens as `dep-form`. Two mechanisms, and the requirement
 * BINDS BOTH LANGUAGES rather than only Rust, which an earlier draft of this
 * paragraph got wrong: every line-comment extractor here emits one range per
 * line, the TypeScript one as much as the Rust one, so the half after the break
 * is not in the same string this pattern sees whichever language it is written
 * in. Inside a block comment the halves ARE in one string, and there the newline
 * plus continuation marker fails the gap. All 21 triples in the tree are in
 * `.rs` files, so the TypeScript half has no instance, and a reader who took the
 * old wording for a Rust quirk would have written a wrapped triple in a `.ts`
 * comment and been just as invisible. Neither silently accepted nor silently
 * rejected, which was the choice to make: it is reported, with the crate named,
 * so the fix is obvious.
 *
 * The symbol is `[^`\n]+` rather than an identifier pattern because the real
 * ones include qualified and generic spellings that no identifier pattern
 * survives, for instance a trait-qualified method on a generic type.
 */
const DEP_WELL_FORMED = THIRD_PARTY_SOURCES.map((entry) => {
  const [crate, version] = entry.split(" ");
  return new RegExp(
    `^\\(\`${escapeRe(crate)}\`[ \\t]+${escapeRe(version)},[ \\t]+\`[^\`\\n]+\`\\)`,
  );
});

/**
 * A parenthesised group carrying a version and a backticked symbol: the shape of
 * a dependency citation, whoever it credits.
 *
 * This is what keeps the allow-list load-bearing after the exemption above was
 * removed. Without it, a citation that drops the crate name has nothing left for
 * any detector to catch: it holds no line number, so the file-and-line patterns
 * are silent, and it names no pinned crate, so `DEP_OPENER` is silent too. The
 * form would then be free to name a version and a symbol while crediting
 * nothing, which is precisely the unattributable citation the allow-list exists
 * to forbid. Measured over the tree: this matches the 21 real triples and
 * nothing else, and all 21 credit a pinned crate.
 */
const DEP_SHAPE = /\([^()\n]{0,80}?\d+\.\d+\.\d+[ \t]*,[ \t]*`[^`\n]+`[^()\n]{0,12}\)/g;

/**
 * How far back a tracker number may look for the project that qualifies it:
 * ANYWHERE EARLIER IN THE SAME COMMENT, and not a character count.
 *
 * This was a 90-character window and that was a latent false positive with no
 * good fix. `webgl.ts` names `xterm.js` at the end of one line of a docblock and
 * carries `#4054` at the start of the next; an edit that pushed the project name
 * past the count would have reddened a correct citation, and the only remedy
 * available to whoever hit it is widening the number, which weakens the
 * detector for every real case. `KNOWN-LIMITS.md` already records that exact
 * shape, a check that reddens on correct code being worse than no check,
 * because the first contributor to hit one weakens it.
 *
 * The comment is the non-arbitrary bound, and it is the reader's bound too: a
 * reader meeting a bare number scans back for the nearest project name and
 * finds it if it is in the same comment, so that is precisely the span over
 * which the number is attributable. It costs one thing, which is worth stating
 * rather than hiding: a project named in a long docblock's first paragraph
 * qualifies a bare number in its last. That fails towards accepting a citation
 * a reader could still resolve, where a character count fails towards refusing
 * one that is already correct.
 *
 * For a line comment each `//` line is its own range, so a project name on the
 * previous line is out of reach whatever the bound. No citation in the tree is
 * written that way, and the fix if one appears is to join a run of adjacent line
 * comments rather than to reintroduce a count.
 */

/** A pinned upstream project named beside a tracker number. */
const TRACKER_PREFIX = new RegExp(UPSTREAM_TRACKERS.map(escapeRe).join("|"));

/** Any backticked pinned crate name, for telling `dep-form` from `dep-uncredited`. */
const ANY_PINNED_CRATE = new RegExp(
  `\`(?:${THIRD_PARTY_SOURCES.map((e) => escapeRe(e.split(" ")[0])).join("|")})\``,
);

// ---------------------------------------------------------------------------
// Resolvability: does a cited file exist?
// ---------------------------------------------------------------------------

/**
 * Every file a clone would have, by walking the checkout.
 *
 * Not `git ls-files`, for two reasons. Nothing else in this suite spawns a
 * child process, and a check that needs git present answers differently in a
 * shallow or exported checkout than in a working one. More importantly a walk
 * SEES A FILE ADDED BUT NOT YET COMMITTED, which is the state every branch is
 * in while it is being written: resolving against the index alone would redden
 * a citation of a file added in the same commit, which is the commonest
 * legitimate new citation there is.
 *
 * The skipped directories are NAMED rather than matched by a leading dot, and
 * the difference is load-bearing. A blanket dot rule looks tidy and drops
 * `.github/` with its workflows and shell scripts, and every checked-in dotfile
 * with them, so a citation of any of those reads as dead. Measured while
 * building this: that rule alone produced six findings against a checked-in
 * formatter config. The two dotted directories skipped here are skipped because
 * they hold no source the rule governs and a citation into either is forbidden
 * by the rule anyway.
 */
const SKIP_DIRS = new Set([
  ".claude",
  ".git",
  ".omc",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "target",
]);
function everyFile(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(name)) everyFile(full, out);
      continue;
    }
    out.push(relative(ROOT, full).split("\\").join("/"));
  }
  return out;
}
const REPO_FILES = everyFile(ROOT);
const REPO_FILE_SET = new Set(REPO_FILES);

/** The extensions a backticked spelling must end in to be read as a file at all. */
const FILE_EXT = /\.(?:tsx?|mts|cts|jsx?|mjs|cjs|rs|css|html|json|toml|md|lock|ya?ml|sh|ps1)$/;

/**
 * Why `s` is not a spelling of a file in this repository, or `null`.
 *
 * EVERY ONE OF THESE WAS MEASURED, not guessed, and the counts are what justify
 * them. Over the three roots there are about 12,900 backticked tokens in
 * comments that carry no file extension and 1,144 that do, so the extension is
 * doing almost all of the work and it has to be right.
 *
 *   `no-extension`   about 12,900 tokens, and the reason this detector requires
 *                    one. Five verify scripts quote relative import spellings
 *                    as EXAMPLES of a class rather than as citations, because
 *                    the property they check is that a module does not reach a
 *                    dependency by ANY spelling: `../store`, `../../vault/store`
 *                    and the alias form all appear side by side as members of an
 *                    unclosable set. Nothing in the text tells those apart from
 *                    a citation, so a detector that reddened them would be
 *                    deleted rather than fixed. Requiring an extension excludes
 *                    every one of them, and it excludes package specifiers and
 *                    bare directory prefixes with them.
 *   `bare-extension` 46 tokens: a comment saying "a `.tsx` file" or naming
 *                    `.d.ts`. An extension alone names no file.
 *   `glob`           14 tokens, almost all this suite naming its own members as
 *                    `*-verify.ts`. A pattern is not a path.
 *   `elided`         4 tokens, a path abbreviated with an ellipsis mid-way.
 *   `foreign-path`   6 tokens: Windows drive letters and backslashed paths, used
 *                    as examples of input the path helpers must handle.
 *   `absolute`       2 tokens, a leading slash, which names a filesystem root
 *                    rather than a repository path.
 *   `not-a-path`     51 tokens carrying a space, a bracket or a path-qualified
 *                    symbol, which no file spelling in this tree does.
 */
function notAFileSpelling(s: string): string | null {
  // A PROJECT NAME THAT ENDS IN AN EXTENSION is not a file spelling, and
  // `xterm.js` is one. Found by writing this file's own prose: backticking the
  // project name produced a `dead-path` finding against text that is plainly
  // correct, and a comment legitimately naming that project in backticks would
  // have hit the same thing. Read off `UPSTREAM_TRACKERS`, which is already this
  // check's register of upstream project names, so the two cannot disagree and
  // adding a project does not also require remembering this.
  if (UPSTREAM_TRACKERS.includes(s)) return "project-name";
  if (!FILE_EXT.test(s)) return "no-extension";
  if (/^\.[A-Za-z]{1,2}\.[A-Za-z]+$/.test(s)) return "bare-extension";
  if (!/[A-Za-z0-9_)\]]\.[A-Za-z0-9]+$/.test(s)) return "bare-extension";
  if (s.includes("*")) return "glob";
  if (s.includes("...")) return "elided";
  if (s.includes("\\") || /^[A-Za-z]:/.test(s)) return "foreign-path";
  if (s.startsWith("/")) return "absolute";
  if (/[\s()<>]/.test(s) || s.includes("::")) return "not-a-path";
  return null;
}

/**
 * The store files the app itself writes into the user's data directory.
 *
 * A PATTERN rather than a list, which is the one place here where deriving beats
 * enumerating: the app's data files all share this naming convention, a new one
 * lands whenever a new store does, and a pinned list would need a diff each
 * time for no judgement. Asserted below to match NO file in the checkout, which
 * is what stops it hiding a real citation: this convention names things the app
 * creates at runtime and nothing this repository ships.
 *
 * DERIVING FROM STRING LITERALS WAS TRIED AND REFUSED, because the measurement
 * killed it. "Exempt any spelling that appears as a string literal somewhere in
 * the tree" reads as elegantly self-maintaining and exempts 1,043 file
 * spellings, since the language registry and the file-icon registry each
 * enumerate hundreds of filenames as data. That is not an allow-list, it is an
 * opening. Narrowing it to "the initialiser of an exported const" is safe but
 * covers only 3 of the 8 store files, so a pinned list would still be needed
 * beside it: two mechanisms for less coverage than one pattern.
 */
const RUNTIME_STORE_FILE = /^tervia-[a-z0-9-]+\.json$/;

/**
 * The config spellings a formatter accepts in a USER'S opened project.
 *
 * Pinned, sorted and length-asserted: this is a closed set of what one external
 * tool reads, so adding one is a real decision about another tool's behaviour
 * rather than bookkeeping. Note that this repository's own `.prettierrc.json` is
 * deliberately absent: it is checked in, so it resolves normally, and that
 * contrast is the whole point of the list.
 */
const EXTERNAL_CONFIG_NAMES = [".prettierrc.js", ".prettierrc.yaml", "prettier.config.js"];

/**
 * A file name used as an EXAMPLE rather than as a pointer, pinned per citing
 * file so the exemption cannot travel.
 *
 * Keyed on the citing file and the spelling, and deliberately NOT on a line, so
 * the pin survives every edit that moves the comment. A line-keyed exemption
 * list inside a check about rotting line numbers would be its own joke.
 *
 * All three are hypothetical file names in prose about how a name is handled,
 * not claims that a file exists: one is about which icon an extension would
 * render, the other two are members of a list of command spellings a matcher
 * must NOT match. There is no mechanical difference between these and a
 * citation, which is exactly why they are enumerated rather than pattern-matched.
 */
const EXAMPLE_SPELLINGS = [
  "src/modules/explorer/lib/constants.ts foo.ts",
  "src/modules/terminal/lib/aiCliDetector.ts claude.ts",
  "src/modules/terminal/lib/aiCliDetector.ts codex-wrapper.sh",
];

/**
 * A file named in order to say that it is GONE, where the deletion is the
 * sentence's subject.
 *
 * THE ONE PLACE THIS CHECK RECORDS A HUMAN JUDGEMENT INSTEAD OF APPLYING A RULE,
 * and the docblock's WHAT IT DOES NOT SEE section carries the argument. In
 * short: the citing comment explains that once these two modules were deleted, a
 * keychain account became unreachable from inside the app, so a purge that skips
 * strands a private key. The sentence is FALSE if the files still exist. The
 * dead name is load-bearing and removing it would leave the paragraph with no
 * subject.
 *
 * The same dead spelling was, at the same time, cited elsewhere in the present
 * tense as a live mechanism, and there it was simply wrong. Same text, opposite
 * verdicts, and the difference is tense and grammatical subject: a semantic
 * property no detector over a comment's text can read. Hence an entry rather
 * than a rule. Keyed on the citing file, so the exemption cannot travel to
 * another file that cites the same dead name as though it were alive.
 */
const DELIBERATELY_DEAD = [
  "scripts/legacy-purge-verify.ts modules/rdp/connections.ts",
  "scripts/legacy-purge-verify.ts modules/ssh/connections.ts",
];

/** Is a spelling that resolved to nothing nevertheless permitted, and why? */
function exemptDeadPath(citing: string, spelling: string): string | null {
  if (RUNTIME_STORE_FILE.test(spelling)) return "runtime store file";
  if (EXTERNAL_CONFIG_NAMES.includes(spelling)) return "external tool's config name";
  if (EXAMPLE_SPELLINGS.includes(`${citing} ${spelling}`)) return "example, not a pointer";
  if (DELIBERATELY_DEAD.includes(`${citing} ${spelling}`)) return "deliberately dead";
  return null;
}

/** How many leading directory segments `a` and `b` agree on. */
function sharedDepth(a: string, b: string): number {
  const x = a.split("/");
  const y = b.split("/");
  let n = 0;
  while (n < x.length - 1 && n < y.length - 1 && x[n] === y[n]) n++;
  return n;
}

/**
 * The files `spelling`, cited from `citing`, could mean.
 *
 * Three forms, in order of how much they say:
 *
 *   - a relative spelling resolves against the CITING FILE'S directory, which
 *     is the only reading that makes a dot-slash spelling mean anything, and it
 *     hits one file or none;
 *   - the alias form maps to the source root, per the compiler's own path
 *     mapping;
 *   - anything else is matched as a path suffix on a segment boundary, so
 *     `hosts/store.ts` finds the one file ending that way.
 *
 * A suffix tie is then broken by NEARNESS to the citing file, which is how a
 * human reads it: a bare store-file name in a comment inside the hosts module
 * means the hosts one, and every reader knows that without being told. This is a
 * ranking and it can pick the wrong file among several that exist, so it is
 * used ONLY to answer "does this name something", never to report which file
 * was meant. Measured: nearness resolves 29 of the 67 spellings that are
 * ambiguous by suffix alone, and every one it resolves sits in the same module
 * as its citation.
 */
function resolveSpelling(citing: string, spelling: string): string[] {
  if (spelling.startsWith("./") || spelling.startsWith("../")) {
    const p = normalize(join(dirname(citing), spelling))
      .split("\\")
      .join("/");
    return REPO_FILE_SET.has(p) ? [p] : [];
  }
  const bare = spelling.startsWith("@/") ? "src/" + spelling.slice(2) : spelling;
  if (REPO_FILE_SET.has(bare)) return [bare];
  const all = REPO_FILES.filter((f) => f.endsWith("/" + bare));
  if (all.length <= 1) return all;
  const best = Math.max(...all.map((f) => sharedDepth(f, citing)));
  return best === 0 ? all : all.filter((f) => sharedDepth(f, citing) === best);
}

/**
 * Did a bare spelling resolve to the CITING FILE, while other files share the
 * name? The one silently-wrong resolution that is mechanically detectable.
 *
 * `resolveSpelling`'s nearness tie-break is a ranking, and its docblock says it
 * can pick the wrong file among several that exist. That limitation had one live
 * instance and it was the worst-shaped citation in the repository: a launcher
 * crate's own file said a setting was made in its entry point, two files of
 * that name are tracked, and nearness preferred the citing file by maximum
 * shared depth. It
 * resolved UNIQUELY and went green while delivering a reader to the file already
 * open in front of them, where the setting is not made. Green, unique, wrong.
 *
 * WHY THIS SHAPE AND NOT THE GENERAL LIMITATION. A wrong pick among two OTHER
 * files needs the citation's meaning to detect, which nothing here can read. But
 * preferring SELF is different: the citing file always wins nearness against any
 * candidate, automatically and regardless of what the sentence means, so the
 * ranking is doing no work and its answer carries no information. That is
 * checkable, and it is the sub-case the live defect fell into.
 *
 * Relative spellings are excluded because the author wrote the path out, so
 * nothing was inferred on their behalf.
 *
 * ADDED WITH ZERO INSTANCES IN THE TREE, which this file refuses elsewhere: the
 * npm-dependency exemption was declined for being unexercised. The difference is
 * the demonstrated defect. That exemption guarded a class that had never gone
 * wrong; this guards one that went wrong last week in the one directory nothing
 * was scanning, and it is exercised by the controls either way.
 */
function selfPreferred(citing: string, spelling: string, resolved: string): boolean {
  if (spelling.startsWith("./") || spelling.startsWith("../")) return false;
  if (resolved !== citing) return false;
  return REPO_FILES.filter((f) => f.endsWith("/" + spelling)).length > 1;
}

/** Every backticked run in a comment, which is where a citation is spelled. */
const BACKTICKED = /`([^`\n]+)`/g;

console.log("\n[resolvability] the file universe, and every exemption still necessary");
// A walk that found nothing, or only a handful, would make every resolution
// fail and every citation look dead. Asserted before anything is resolved.
check(`the checkout walk found files to resolve against`, REPO_FILES.length > 400, {
  files: REPO_FILES.length,
});
check(
  "a file added but not yet committed is resolvable",
  resolveSpelling("scripts/x.ts", "lib/comments.ts").length === 1,
);
check(
  "the external-config name list is a sorted set of exactly 3 entries",
  sortedSet(EXTERNAL_CONFIG_NAMES) && EXTERNAL_CONFIG_NAMES.length === 3,
  EXTERNAL_CONFIG_NAMES,
);
check(
  "the example-spelling list is a sorted set of exactly 3 entries",
  sortedSet(EXAMPLE_SPELLINGS) && EXAMPLE_SPELLINGS.length === 3,
  EXAMPLE_SPELLINGS,
);
check(
  "the deliberately-dead list is a sorted set of exactly 2 entries",
  sortedSet(DELIBERATELY_DEAD) && DELIBERATELY_DEAD.length === 2,
  DELIBERATELY_DEAD,
);
// An exemption for a spelling somebody has since checked in is an exemption
// hiding a resolvable citation, so every list has to stay TRUE and not merely
// short. This is the half an allow-list normally lacks.
check(
  "the runtime store-file pattern matches no file in the checkout",
  REPO_FILES.every((f) => !RUNTIME_STORE_FILE.test(f.split("/").pop() ?? "")),
  REPO_FILES.filter((f) => RUNTIME_STORE_FILE.test(f.split("/").pop() ?? "")),
);
for (const spelling of EXTERNAL_CONFIG_NAMES) {
  check(
    `the exemption for ${spelling} is still needed, because no such file exists`,
    resolveSpelling("src/x.ts", spelling).length === 0,
  );
}
// Two assertions per entry and not one, so a failure says WHICH half broke.
// Bundled, the label "still needed and still lands" is true of both a citing
// file that has been deleted and a spelling that has come back, and those want
// opposite fixes: retire the entry, or delete it and let the citation resolve.
for (const entry of [...EXAMPLE_SPELLINGS, ...DELIBERATELY_DEAD]) {
  const [citing, spelling] = entry.split(" ");
  // The entry has to still LAND. A citing file that has moved leaves the
  // exemption pinned to nothing, exempting a spelling nobody writes any more.
  check(
    `the exemption for ${spelling} still lands, because ${citing} is there`,
    REPO_FILE_SET.has(citing),
  );
  // And it has to still be NEEDED. This is the inverted half, and it is the
  // failure mode an exemption actually has: the day a deleted file comes back,
  // or somebody checks in a file by that name, the entry stops excusing an
  // unresolvable spelling and starts blindfolding the check to a citation that
  // has become perfectly good. Nothing about the list's own shape would show it,
  // so it is asserted rather than trusted.
  check(
    `the exemption for ${spelling} is still needed, because no such file exists yet`,
    resolveSpelling(citing, spelling).length === 0,
    resolveSpelling(citing, spelling),
  );
}

type Violation = { readonly where: string; readonly kind: string; readonly cite: string };

/**
 * Every citation in `src`'s COMMENTS that the rule refuses.
 *
 * `rel` decides the comment syntax and is what the report names, so it must be
 * the repository-relative spelling rather than an absolute path.
 *
 * EVERY LINE NUMBER HERE COMES FROM THE MATCH'S OWN OFFSET, never from the
 * comment range's start. This file reported the range's start once, and for a
 * block comment that is the line holding the opening delimiter: the three
 * findings it produced pointed at a bare `/**` and a reader following one
 * learned nothing. That is this check's own subject matter, a number that looks
 * checkable and lands on comment filler, reproduced inside the instrument built
 * to remove it. It survived fourteen controls because every one of them was a
 * single-line probe, where the two numbers coincide. Firing and pointing
 * somewhere are different properties and only the first had been tested; the
 * `[lines]` controls test the second.
 */
function violationsIn(rel: string, src: string): Violation[] {
  const out: Violation[] = [];
  const lineOf = lineNumbersFor(src);
  for (const comment of commentRangesOf(rel, src)) {
    const flag = (kind: string, at: number, cite: string): void => {
      out.push({ where: `${rel}:${lineOf(comment.pos + at)}`, kind, cite });
    };

    // Named first, and its spans remembered: a citation whose colon sits outside
    // a backtick satisfies the bare pattern too, and reporting it twice would
    // claim two defects where the file name is right there in the first one.
    const namedSpans: Array<{ from: number; to: number }> = [];
    for (const m of comment.text.matchAll(NAMED_CITATION)) {
      const at = m.index ?? 0;
      namedSpans.push({ from: at, to: at + m[0].length });
      flag("named", at, m[0]);
    }
    for (const m of comment.text.matchAll(BARE_LINE)) {
      const at = m.index ?? 0;
      if (namedSpans.some((s) => at >= s.from && at < s.to)) continue;
      flag("bare-line", at, m[0].trim());
    }

    for (const m of comment.text.matchAll(BARE_TRACKER)) {
      const at = m.index ?? 0;
      const before = comment.text.slice(0, at);
      if (!TRACKER_PREFIX.test(before)) flag("bare-tracker", at, m[0]);
    }

    // A pinned crate in citation position must complete its triple, on one line,
    // at the version the lockfile pins.
    for (const m of comment.text.matchAll(DEP_OPENER)) {
      const at = m.index ?? 0;
      const rest = comment.text.slice(at);
      if (!DEP_WELL_FORMED.some((re) => re.test(rest))) {
        flag("dep-form", at, rest.slice(0, 72).split("\n")[0]);
      }
    }
    // And a citation shaped like a triple must credit one. Skipped when a pinned
    // crate IS named, because then the more specific `dep-form` owns the finding.
    for (const m of comment.text.matchAll(DEP_SHAPE)) {
      if (!ANY_PINNED_CRATE.test(m[0])) flag("dep-uncredited", m.index ?? 0, m[0]);
    }

    // Finally the REFERENT rather than the shape: every file this comment names
    // has to be a file that exists. The five detectors above all pass a citation
    // that is beautifully formed and points at nothing.
    for (const m of comment.text.matchAll(BACKTICKED)) {
      const spelling = m[1].trim();
      if (notAFileSpelling(spelling) !== null) continue;
      const found = resolveSpelling(rel, spelling);
      // The exemptions are consulted ONLY on a miss, never before resolving.
      // Consulting them first would let an exemption silence an AMBIGUITY, which
      // is a different finding about a file that does exist, and would hide it
      // under a list whose every entry claims the opposite.
      if (found.length === 0) {
        if (exemptDeadPath(rel, spelling) === null) flag("dead-path", m.index ?? 0, spelling);
      } else if (found.length > 1) {
        flag("partial-path", m.index ?? 0, `${spelling} (${found.length} candidates)`);
      } else if (selfPreferred(rel, spelling, found[0])) {
        flag("self-resolved", m.index ?? 0, `${spelling} resolves to the citing file`);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The extractor's own proof, before anything is believed
// ---------------------------------------------------------------------------

console.log("\n[extractor] comments come out of the parse, in both directions");
for (const { label, ok } of commentScannerSelfTest()) check(label, ok);

// ---------------------------------------------------------------------------
// [controls] every detector, proved to fire and proved not to
// ---------------------------------------------------------------------------

/** The symbol every dependency control cites. Real, and reachable through the lockfile. */
const SYM = "DecodedImage::apply_rgb16_bitmap";

/** A named citation in a comment. MUST be flagged. */
const C_NAMED = "const a = 1; // mirrors the guard at foo.ts:12\n";
/** The identical text in a string literal. MUST NOT be flagged. */
const C_NAMED_IN_STRING = 'const a = "mirrors the guard at foo.ts:12";\n';
/**
 * A citation whose colon sits OUTSIDE the closing backtick. MUST be flagged, and
 * as `named` rather than as a bare reference, because the file is right there.
 *
 * The generated inventory that sized this work could not see this shape at all,
 * which is the reason it is a control: a second instrument that agrees with the
 * first by construction proves nothing about what the first one missed.
 */
const C_NAMED_OUTSIDE_BACKTICK = "const a = 1; // awaited before `hosts/store.ts`:954-961 runs\n";
/** A bare span in parentheses, the other shape the inventory missed. MUST be flagged. */
const C_BARE_SPAN = "const a = 1; // the direction is explained at (:112-114)\n";
/**
 * A dependency citation that still carries a line. MUST be flagged.
 *
 * The crate and the pinned version are both correct and it is still refused: a
 * line into a dependency's source is not reachable from a clone, so crediting it
 * makes it attributable without making it openable.
 */
const C_DEP_WITH_LINE = "const a = 1; // (`tauri` 2.11.5, `src/ipc/channel.rs:39`)\n";
/** The form the conversion lands on: crate, pinned version, symbol, no line. MUST NOT be flagged. */
const C_DEP_SYMBOL = `const a = 1; // (\`ironrdp-session\` 0.10.0, \`${SYM}\`)\n`;
/** The same with the crate name removed, and no line to redden it instead. MUST be flagged. */
const C_DEP_NO_CRATE = `const a = 1; // (0.10.0, \`${SYM}\`)\n`;
/** The same with the crate named but no version. MUST be flagged. */
const C_DEP_NO_VERSION = `const a = 1; // (\`ironrdp-session\`, \`${SYM}\`)\n`;
/**
 * The same at a version this repository does not pin. MUST be flagged.
 *
 * 0.9.0 is a real pinned version in this repository, of three OTHER crates, so
 * this also proves the version is checked against its own crate rather than
 * against the set of versions in use.
 */
const C_DEP_BAD_VERSION = `const a = 1; // (\`ironrdp-session\` 0.9.0, \`${SYM}\`)\n`;
/** A triple wrapped across two comment lines. MUST be flagged as malformed. */
const C_DEP_WRAPPED = `fn f() {} // (\`ironrdp-session\` 0.10.0,\n// \`${SYM}\`)\n`;
/** A dependency named in prose, citing no symbol. MUST NOT be flagged. */
const C_DEP_IN_PROSE =
  "const a = 1; // re-apply the floor after `tauri-plugin-window-state` has restored\n";
/** A bare line reference in a comment. MUST be flagged. */
const C_BARE = "const a = 1; // the other constructor is at `:1183`\n";
/** The identical text in a string literal. MUST NOT be flagged. */
const C_BARE_IN_STRING = 'const a = "the other constructor is at `:1183`";\n';
/** An address and a JSON key, neither of which is a citation. MUST NOT be flagged. */
const C_NOT_A_CITATION = 'const a = 1; // binds 127.0.0.1:5432 and logs `{"count":0}`\n';
/**
 * A forwarding route, which is illustrative prose. MUST NOT be flagged.
 *
 * The text is the one a page component carries to size its widest row. Three
 * host-and-port pairs, one of them a bare name and two of them addresses, in a
 * repository whose whole subject is forwarding ports between them.
 */
const C_HOST_PORT =
  "const a = 1; // the longest row is `localhost:18084 → bastion → 10.0.0.9:5432`\n";
/** A bare tracker number. MUST be flagged. */
const C_TRACKER = "const a = 1; // pinned above other apps (#33)\n";
/** A tracker number naming its project. MUST NOT be flagged. */
const C_TRACKER_NAMED = "const a = 1; // a known renderer bug (xterm.js #4054)\n";
/** A colour and a format name. MUST NOT be flagged. */
const C_TRACKER_LOOKALIKE = "const a = 1; // base0 (#839496) under an unencrypted PKCS#8\n";
/** A Rust comment behind a lifetime, which must not swallow the line. MUST be flagged. */
const C_RUST = "fn f<'a>(x: &'a str) -> &'a str { x } // see the tail at session.rs:484\n";
/** The identical text in a Rust string. MUST NOT be flagged. */
const C_RUST_IN_STRING = 'fn f() { let s = "see the tail at session.rs:484"; }\n';
/** A citation of a file that is not in the checkout. MUST be flagged. */
const C_DEAD_PATH = "const a = 1; // see `modules/ai/lib/httpProxy.ts` for the same reason\n";
/** The same spelling in a string literal. MUST NOT be flagged. */
const C_DEAD_PATH_IN_STRING = 'const a = "see modules/ai/lib/httpProxy.ts";\n';
/** A citation of a file that IS in the checkout. MUST NOT be flagged. */
const C_LIVE_PATH = "const a = 1; // see `src/modules/vault/resolve.ts` for the SSH side\n";
/**
 * A bare file name resolved by the citing file's own module. MUST NOT be flagged.
 *
 * That store-file name has six candidates in this tree, so a resolver ignoring
 * where the citation sits would call this ambiguous. Cited from inside the hosts
 * module it means the hosts one, which is how every reader takes it.
 */
const C_NEAREST_PATH = "const a = 1; // the write queue in `store.ts` runs first\n";
/**
 * The identical spelling with nothing nearby to disambiguate it. MUST be
 * flagged as partial.
 *
 * The SAME text as the control above, from a citing path in another tree. That
 * is what makes the pair a test of the resolution rule rather than of the
 * spelling: one string, two answers, and only a resolver that reads the citing
 * file's directory can produce both.
 */
const C_PARTIAL_PATH = C_NEAREST_PATH;
/** A relative spelling, which resolves against the citing file's directory. MUST NOT be flagged. */
const C_RELATIVE_PATH = "const a = 1; // mirrors `./store.ts` exactly\n";
/** A relative spelling that walks off the tree. MUST be flagged. */
const C_RELATIVE_DEAD = "const a = 1; // mirrors `./nothingHere.ts` exactly\n";
/** An import spelling quoted as an example of a class, not as a citation. MUST NOT be flagged. */
const C_IMPORT_EXAMPLE =
  "const a = 1; // no `../store`, no `../../vault/store`, no `@/modules/vault/store`\n";
/** This suite naming its own members with a glob. MUST NOT be flagged. */
const C_GLOB = "const a = 1; // every `scripts/*-verify.ts` runs in one pass\n";
/** A bare extension in prose, and a Windows path used as example input. MUST NOT be flagged. */
const C_NOT_A_FILE = "const a = 1; // a `.tsx` file, or `C:\\a\\b.md` on Windows\n";

/** The kinds `violationsIn` reports over a control, sorted, for one comparison. */
const kindsOf = (rel: string, src: string): string =>
  violationsIn(rel, src)
    .map((v) => v.kind)
    .sort()
    .join(",");

console.log("\n[controls] each detector fires, and each declines to");
check("a named citation in a comment is flagged", kindsOf("c.ts", C_NAMED) === "named");
check(
  "the identical text in a string literal is NOT flagged",
  kindsOf("c.ts", C_NAMED_IN_STRING) === "",
);
check(
  "a citation whose colon sits outside the backtick is flagged, as named",
  kindsOf("c.ts", C_NAMED_OUTSIDE_BACKTICK) === "named",
);
check("a bare span in parentheses is flagged", kindsOf("c.ts", C_BARE_SPAN) === "bare-line");
check(
  "a dependency citation still carrying a line IS flagged, crate and version notwithstanding",
  kindsOf("c.ts", C_DEP_WITH_LINE) === "named",
);
check(
  "the crate, version and symbol form the conversion lands on is NOT flagged",
  kindsOf("c.ts", C_DEP_SYMBOL) === "",
);
check(
  "the same form with the crate name removed IS flagged",
  kindsOf("c.ts", C_DEP_NO_CRATE) === "dep-uncredited",
);
check("the same form with no version IS flagged", kindsOf("c.ts", C_DEP_NO_VERSION) === "dep-form");
check(
  "the same form at a version this repository does not pin IS flagged",
  kindsOf("c.ts", C_DEP_BAD_VERSION) === "dep-form",
);
check(
  "a triple wrapped across two comment lines IS flagged as malformed",
  kindsOf("c.rs", C_DEP_WRAPPED) === "dep-form",
);
check("a dependency named in prose is NOT flagged", kindsOf("c.ts", C_DEP_IN_PROSE) === "");
check("a bare line reference is flagged", kindsOf("c.ts", C_BARE) === "bare-line");
check(
  "the identical bare reference in a string literal is NOT flagged",
  kindsOf("c.ts", C_BARE_IN_STRING) === "",
);
check(
  "an address and a JSON key in a comment are NOT flagged",
  kindsOf("c.ts", C_NOT_A_CITATION) === "",
);
check("a host:port forwarding route is NOT flagged", kindsOf("c.ts", C_HOST_PORT) === "");
check("a bare tracker number is flagged", kindsOf("c.ts", C_TRACKER) === "bare-tracker");
check(
  "a tracker number naming its project is NOT flagged",
  kindsOf("c.ts", C_TRACKER_NAMED) === "",
);
check(
  "a six-digit colour and an attached format name are NOT flagged",
  kindsOf("c.ts", C_TRACKER_LOOKALIKE) === "",
);
check("a Rust comment sitting behind a lifetime is flagged", kindsOf("c.rs", C_RUST) === "named");
check(
  "the identical text in a Rust string literal is NOT flagged",
  kindsOf("c.rs", C_RUST_IN_STRING) === "",
);

console.log("\n[referent] a cited file has to be a file that exists");
check(
  "a citation of a file not in the checkout is flagged",
  kindsOf("src/x.ts", C_DEAD_PATH) === "dead-path",
);
check(
  "the identical spelling in a string literal is NOT flagged",
  kindsOf("src/x.ts", C_DEAD_PATH_IN_STRING) === "",
);
check(
  "a citation of a file that IS in the checkout is NOT flagged",
  kindsOf("src/x.ts", C_LIVE_PATH) === "",
);
// The pair that tests the RULE and not the spelling: identical text, two
// answers, decided only by where the citation sits.
check(
  "a bare `store.ts` cited from inside the hosts module is NOT flagged",
  kindsOf("src/modules/hosts/jumps.ts", C_NEAREST_PATH) === "",
);
check(
  "the same spelling cited from a script, with nothing nearby, is flagged as partial",
  kindsOf("scripts/some-verify.ts", C_PARTIAL_PATH) === "partial-path",
);
check(
  "a relative spelling resolves against the citing file's own directory",
  kindsOf("src/modules/hosts/jumps.ts", C_RELATIVE_PATH) === "",
);
check(
  "a relative spelling that names nothing there is flagged",
  kindsOf("src/modules/hosts/jumps.ts", C_RELATIVE_DEAD) === "dead-path",
);
check(
  "import spellings quoted as examples of a class are NOT flagged",
  kindsOf("scripts/some-verify.ts", C_IMPORT_EXAMPLE) === "",
);
check("a glob naming this suite's members is NOT flagged", kindsOf("scripts/s.ts", C_GLOB) === "");
check(
  "a bare extension and a Windows example path are NOT flagged",
  kindsOf("src/x.ts", C_NOT_A_FILE) === "",
);

// The exemptions, each proved to fire AND proved not to travel. A pair per
// exemption, because "it is green" alone is satisfied by an exemption that
// swallows everything.
console.log("\n[exemptions] each one fires, and none of them travels");
check(
  "a runtime store-file name is exempt",
  kindsOf("src/x.ts", "const a = 1; // written to `tervia-vault.json`\n") === "",
);
check(
  "the same stem at another extension is NOT exempt, so the pattern is not a prefix",
  kindsOf("src/x.ts", "const a = 1; // written to `tervia-vault.ts`\n") === "dead-path",
);
check(
  "an external tool's config name is exempt",
  kindsOf("src/x.ts", "const a = 1; // reads `prettier.config.js` first\n") === "",
);
check(
  "this repository's own checked-in config resolves normally rather than by exemption",
  kindsOf("src/x.ts", "const a = 1; // reads `.prettierrc.json` first\n") === "",
);
// The escape hatch, and the control that matters most about it: the SAME dead
// spelling from a DIFFERENT file must still redden, because the judgement being
// recorded is about one sentence and not about the name.
check(
  "the deliberately-dead name is exempt in the file whose sentence is about its deletion",
  kindsOf(
    "scripts/legacy-purge-verify.ts",
    "const a = 1; // once `modules/ssh/connections.ts` was deleted\n",
  ) === "",
);
check(
  "the identical spelling cited from any other file IS flagged",
  kindsOf("src/x.ts", "const a = 1; // once `modules/ssh/connections.ts` was deleted\n") ===
    "dead-path",
);
// An exemption must never be able to silence an AMBIGUITY, which is a finding
// about a file that does exist. Proved by ordering: the runtime pattern is
// consulted only after resolution misses.
check(
  "an exemption cannot suppress a partial spelling",
  kindsOf("scripts/some-verify.ts", C_PARTIAL_PATH) === "partial-path",
);
// The discriminator itself, asserted by REASON and not by outcome. An
// extension-less import spelling must be refused BEFORE resolution, or the
// resolution step could quietly land it on a plausible file.
check(
  "an extension-less import spelling is refused for having no extension",
  notAFileSpelling("../store") === "no-extension" &&
    notAFileSpelling("@/modules/vault/store") === "no-extension",
  { relative: notAFileSpelling("../store"), alias: notAFileSpelling("@/modules/vault/store") },
);
check(
  "a real relative citation, which carries one, is NOT refused",
  notAFileSpelling("./store.ts") === null,
  notAFileSpelling("./store.ts"),
);
check(
  "an elided dependency path is refused for being elided, so no npm rule is needed",
  notAFileSpelling("react-remove-scroll/dist/.../SideEffect.js") === "elided",
  notAFileSpelling("react-remove-scroll/dist/.../SideEffect.js"),
);
// A project name that happens to end in an extension, against a file spelling
// that does not. Same shape, two answers, decided by the tracker register.
check(
  "a backticked upstream project name is NOT read as a file",
  kindsOf("src/x.ts", "const a = 1; // a known bug in `xterm.js` dims the glyphs\n") === "",
);
check(
  "a lookalike that is not a pinned project IS read as a file, and reddens",
  kindsOf("src/x.ts", "const a = 1; // a known bug in `xtermm.js` dims the glyphs\n") ===
    "dead-path",
);
// The silently-wrong unique resolution, using the shape that actually occurred.
// The pair is decided by whether the author wrote the path out: a bare name lets
// nearness prefer the citing file automatically, a full path does not.
check(
  "a bare name that resolves to the citing file, while others share it, IS flagged",
  kindsOf(
    "src-tauri/tervia-cli/src/main.rs",
    "// the subsystem is set in `main.rs`, not this one\n",
  ) === "self-resolved",
);
check(
  "the same claim with the path written out is NOT flagged",
  kindsOf(
    "src-tauri/tervia-cli/src/main.rs",
    "// the subsystem is set in `src-tauri/src/main.rs`, not this one\n",
  ) === "",
);
// And a bare name that resolves to the citing file when NOTHING else shares it
// is a redundant self-reference rather than a misdirection, so it passes.
check(
  "a bare self-reference with no other file of that name is NOT flagged",
  kindsOf("src/lib/storeRecovery.ts", "// as `storeRecovery.ts` does above\n") === "",
);

// The tracker window, which is now the comment rather than a character count.
// The project name sits on the line ABOVE the number inside one block comment,
// which a 90-character window did not reach.
check(
  "a project named earlier in the same block comment still qualifies its number",
  kindsOf(
    "src/x.ts",
    "const a = 1;\n/*\n * a known issue (xterm.js\n * #4054) dims the glyphs\n */\n",
  ) === "",
);
check(
  "the same number with no project anywhere in that comment IS flagged",
  kindsOf("src/x.ts", "const a = 1;\n/*\n * a known issue\n * (#4054) dims the glyphs\n */\n") ===
    "bare-tracker",
);
// And the attached form passes for ANY word, which is why the tracker list needs
// no entry for a project only ever cited that way.
check(
  "an attached tracker reference passes without the project being on the list",
  kindsOf("src/x.ts", "const a = 1; // torn by a power cut (some-project#3085)\n") === "",
);

// ---------------------------------------------------------------------------
// [lines] the report points at the citation, not at the comment's opener
// ---------------------------------------------------------------------------

/**
 * A `/* *\/ block whose citations sit on its third and fourth lines.
 *
 * Every fixture here opens its comment on file line 2 and puts the citation
 * further down, so a report taken from the comment's opening delimiter answers
 * 2 and a report taken from the match answers 4. Nothing above this section
 * could tell the two apart, because a single-line probe puts them at the same
 * number.
 *
 * This one carries TWO citations, on two different lines of ONE comment. That
 * is the strongest form of the assertion available: no single number can
 * satisfy it, so an implementation reporting anything per-range rather than
 * per-match fails it whichever line it picks.
 */
const C_BLOCK_TWO_LINES = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  " * mirrors the guard at foo.ts:12",
  " * and the other constructor is at `:1183`",
  " */",
  "",
].join("\n");

/** The same in a `/** *\/ docblock, which is the form the three real findings were in. */
const C_DOCBLOCK_LINES = [
  "const a = 1;",
  "/**",
  " * nothing citable on this line",
  " * mirrors the guard at foo.ts:12",
  " */",
  "",
].join("\n");

/** The same in a Rust block comment, which the hand-written scanner reads. */
const C_RUST_BLOCK_LINES = [
  "fn f() {}",
  "/*",
  " * nothing citable on this line",
  " * see the tail at session.rs:484",
  " */",
  "",
].join("\n");

/** And in a stylesheet, the fourth comment syntax and the fourth code path. */
const C_CSS_BLOCK_LINES = [
  ".a { color: red; }",
  "/*",
  " * nothing citable on this line",
  " * mirrors the guard at foo.ts:12",
  " */",
  "",
].join("\n");

/**
 * Two citations OF THE SAME KIND, on two lines of one comment, one fixture per
 * detector. This is the property the four fixtures above do not have.
 *
 * The pair at the top of this section mixes two kinds, so it proves a finding is
 * placed per MATCH rather than per comment. It cannot prove a COUNT: an
 * implementation reporting one finding per kind per comment satisfies it
 * whichever line it picks. The defect this section exists for had both halves at
 * once, one detector naming a single line for two occurrences, and a control
 * that sees only one half is half a control.
 *
 * COVERED EXHAUSTIVELY AND NOT BY SAMPLE, because sampling is what left the gap.
 * When this section held four fixtures they cited three spellings between them
 * and exercised two detectors; the other five must-be-zero kinds, and the
 * bounded one, had no line control at all. The two that did were the two those
 * three spellings happen to exercise, which is not a reason.
 *
 * Every fixture keeps the section's convention: the comment opens on file line 2
 * and both citations sit on lines 4 and 5, so the assertion is a pair that no
 * single number satisfies and that nothing but a per-match report produces.
 *
 * THE REPORT THAT PROMPTED THESE HAS SINCE BEEN RE-RUN, and it does not
 * reproduce. A project name ending in a scanned extension was once reported by
 * the dead-path detector as one finding on a line holding neither occurrence;
 * that spelling is now refused before resolution, so the symptom left before the
 * cause was established. Lifting the refusal and scanning this file again
 * returns both occurrences, each on its own line, so what fixed it was taking
 * the offset from the match rather than from the comment, and the refusal masks
 * nothing. The controls below are what makes that answer hold tomorrow.
 */

/** Two named citations, on two lines of one block comment. MUST report 4 and 5. */
const C_NAMED_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  " * mirrors the guard at foo.ts:12",
  " * and the fallback at foo.ts:98",
  " */",
  "",
].join("\n");

/** Two bare line references, on two lines of one block comment. MUST report 4 and 5. */
const C_BARE_LINE_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  " * the other constructor is at `:1183`",
  " * and its only caller is at `:204`",
  " */",
  "",
].join("\n");

/** Two bare tracker numbers, neither naming a project. MUST report 4 and 5. */
const C_TRACKER_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  " * pinned above other apps (#33)",
  " * and torn again on resume (#34)",
  " */",
  "",
].join("\n");

/** Two pinned crates in citation position, neither completing its triple. MUST report 4 and 5. */
const C_DEP_FORM_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  ` * (\`ironrdp-session\`, \`${SYM}\`) is consulted first`,
  ` * then (\`tauri\`, \`${SYM}\`) decides`,
  " */",
  "",
].join("\n");

/** Two triples crediting no crate at all. MUST report 4 and 5. */
const C_DEP_UNCREDITED_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  ` * (0.10.0, \`${SYM}\`) is consulted first`,
  ` * then (0.9.0, \`${SYM}\`) decides`,
  " */",
  "",
].join("\n");

/** Two spellings naming no file in the checkout. MUST report 4 and 5. */
const C_DEAD_PATH_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  " * see `modules/ai/lib/httpProxy.ts` for the same reason",
  " * and `modules/ai/lib/httpStream.ts` for the other one",
  " */",
  "",
].join("\n");

/**
 * Two bare names each resolving to the citing file while another shares it. MUST
 * report 4 and 5.
 *
 * A Rust block comment, because the one live instance this detector was built
 * for was in a Rust file, and because that puts the offset arithmetic in the
 * hand-written scanner rather than in the parse, which is a second code path.
 */
const C_SELF_RESOLVED_TWICE = [
  "fn f() {}",
  "/*",
  " * nothing citable on this line",
  " * the subsystem is set in `main.rs`, not this one",
  " * and the manifest is read by `main.rs` too",
  " */",
  "",
].join("\n");

/**
 * Two bare names each shared by several files, cited from too far away to break
 * the tie. MUST report 4 and 5.
 *
 * The one bounded class, controlled for line attribution all the same. A ceiling
 * is not a licence to misreport: every site it counts is printed for a reader to
 * lower the bound by, and a printed site pointing at comment filler is worth
 * less than no site at all.
 */
const C_PARTIAL_PATH_TWICE = [
  "const a = 1;",
  "/*",
  " * nothing citable on this line",
  " * the write queue in `store.ts` runs first",
  " * and the reader in `store.ts` runs after it",
  " */",
  "",
].join("\n");

/** The lines `violationsIn` reports over a control, in order, as one string. */
const linesOf = (rel: string, src: string): string =>
  violationsIn(rel, src)
    .map((v) => v.where.split(":").pop())
    .join(",");

console.log("\n[lines] a finding names the citation's line, not the comment's");
check(
  "two citations on two lines of one block comment report 4 and 5, not the opener's 2",
  linesOf("c.ts", C_BLOCK_TWO_LINES) === "4,5",
  linesOf("c.ts", C_BLOCK_TWO_LINES),
);
check(
  "a citation on a docblock's third line reports 4, not the opener's 2",
  linesOf("c.ts", C_DOCBLOCK_LINES) === "4",
  linesOf("c.ts", C_DOCBLOCK_LINES),
);
check(
  "a citation in a Rust block comment reports 4, not the opener's 2",
  linesOf("c.rs", C_RUST_BLOCK_LINES) === "4",
  linesOf("c.rs", C_RUST_BLOCK_LINES),
);
check(
  "a citation in a stylesheet's block comment reports 4, not the opener's 2",
  linesOf("c.css", C_CSS_BLOCK_LINES) === "4",
  linesOf("c.css", C_CSS_BLOCK_LINES),
);

// One per detector, each two occurrences of ONE kind on two lines of ONE
// comment. The kind is asserted beside the lines, because a fixture that fired
// the wrong detector would still answer 4 and 5 and the label would be a claim
// nothing behind it holds.
const twoOnTwoLines = (label: string, rel: string, src: string, kind: string): void =>
  check(
    `two ${label} on two lines of one comment report 4 and 5`,
    linesOf(rel, src) === "4,5" && kindsOf(rel, src) === `${kind},${kind}`,
    { lines: linesOf(rel, src), kinds: kindsOf(rel, src) },
  );

twoOnTwoLines("named citations", "c.ts", C_NAMED_TWICE, "named");
twoOnTwoLines("bare line references", "c.ts", C_BARE_LINE_TWICE, "bare-line");
twoOnTwoLines("bare tracker numbers", "c.ts", C_TRACKER_TWICE, "bare-tracker");
twoOnTwoLines("malformed dependency citations", "c.ts", C_DEP_FORM_TWICE, "dep-form");
twoOnTwoLines("uncredited triples", "c.ts", C_DEP_UNCREDITED_TWICE, "dep-uncredited");
twoOnTwoLines("dead paths", "src/x.ts", C_DEAD_PATH_TWICE, "dead-path");
twoOnTwoLines(
  "self-resolving bare names",
  "src-tauri/tervia-cli/src/main.rs",
  C_SELF_RESOLVED_TWICE,
  "self-resolved",
);
twoOnTwoLines("partial spellings", "scripts/some-verify.ts", C_PARTIAL_PATH_TWICE, "partial-path");

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "target" || name === "dist" || name === "gen") continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (hasKnownCommentSyntax(name)) out.push(full);
  }
  return out;
}

/**
 * How many partial spellings the tree may carry, as a CEILING rather than an
 * exact count.
 *
 * A partial spelling is a real citation of a real file whose name happens to be
 * shared, cited from somewhere too far away for the citing directory to break
 * the tie: a script naming a bare derive-file name when three modules have one.
 * Not one of them is a dead reference, and a reader resolves each from the citing
 * script's own subject, so reddening per site would commission an edit in every
 * one of them for no defect found.
 *
 * A ceiling and not an exact number so that FIXING one never reddens the check,
 * while ADDING one does. It ratchets in the direction the repository wants and
 * stays silent in the other. Lowering it as the number falls is a one-line diff
 * with the new number in the failure message.
 */
const PARTIAL_PATH_CEILING = 38;

/**
 * The symbol this file's own docblock names as absent, and the two counts that
 * keep that paragraph from becoming prose nobody checks.
 *
 * Naming an instance in a comment is safe exactly when something announces its
 * change, and unsafe otherwise: the docblock argues that distinction, and this
 * is the announcing half. Cited in comments and defined nowhere is a deliberate
 * property of the secrets IPC surface, so the day it stops being true a check
 * here reddens rather than a paragraph quietly going stale.
 *
 * Counted with the same instrument the claim came from, `lib/comments.ts`, so
 * the assertion and the measurement cannot disagree about what a comment is.
 */
const ABSENT_SYMBOL = "secrets_list";
/** How many comments cite it. An exact pin: the docblock states this number. */
const ABSENT_SYMBOL_CITATIONS = 22;
/**
 * This file, excluded from that accounting, because it names the symbol in order
 * to discuss it.
 *
 * Measured the moment the assertion was written: naming `secrets_list` in the
 * docblock moved the comment count from 22 to 27 and put the string literal
 * holding it into the code half, so BOTH assertions failed on their first run
 * against text that is entirely correct. The claim is about the app's IPC
 * surface, not about the file making the claim, and this is the same distinction
 * the docblock draws for a deliberately dead name.
 *
 * Derived from `import.meta.url` rather than written out, so renaming this file
 * cannot silently empty the exclusion and leave the counts looking wrong.
 */
const SELF = relative(ROOT, fileURLToPath(import.meta.url))
  .split("\\")
  .join("/");

/**
 * What gets scanned, as labelled units, so a failure names where it came from.
 *
 * The named files are one unit rather than one each, because two checks apiece
 * over a pair of files buys nothing a single labelled group does not.
 */
const SCAN_UNITS: Array<{ label: string; files: string[] }> = [
  ...ROOT_DIRS.map((dir) => ({ label: `${dir}/`, files: walk(join(ROOT, dir)) })),
  { label: "root-level source", files: ROOT_FILES.map((f) => join(ROOT, f)) },
];

console.log("\n[tree] no comment cites a line number, a bare tracker number or a dead path");
// A named file that has moved would silently scan nothing and read as coverage,
// which is the one failure a list of literal paths has.
check(
  "every named root-level file is there to be scanned",
  ROOT_FILES.every((f) => REPO_FILE_SET.has(f)),
  ROOT_FILES.filter((f) => !REPO_FILE_SET.has(f)),
);
// And the walk as a whole has to have found the tree. Per-unit counts below
// catch a single root breaking; this catches the walk itself breaking, which
// would otherwise turn every assertion in this section green over empty lists.
check(
  "the scan covers the whole hand-written tree",
  SCAN_UNITS.reduce((n, u) => n + u.files.length, 0) > 400,
  SCAN_UNITS.map((u) => `${u.label} ${u.files.length}`),
);

let partialTotal = 0;
const partialSites: string[] = [];
const unitComments: string[] = [];
let absentInComments = 0;
const absentInCode: string[] = [];
for (const { label: root, files } of SCAN_UNITS) {
  check(`${root} has files with comment syntax to scan`, files.length > 0, files.length);
  // Listed is not the same as READ. A unit whose files all failed to yield a
  // comment would pass every assertion below over an empty set, and that is the
  // shape a newly added root fails in: named correctly, walked correctly, and
  // silently contributing nothing.
  unitComments.push(
    `${root} ${files.reduce((n, f) => n + commentRangesOf(relative(ROOT, f), readFileSync(f, "utf8")).length, 0)}`,
  );

  const found: Violation[] = [];
  for (const file of files) {
    const rel = relative(ROOT, file);
    const src = readFileSync(file, "utf8");
    found.push(...violationsIn(rel, src));
    // Only the handful of files that mention it at all pay for a second parse.
    if (src.includes(ABSENT_SYMBOL) && rel !== SELF) {
      const ranges = commentRangesOf(rel, src);
      const occurrences = (text: string): number => text.split(ABSENT_SYMBOL).length - 1;
      absentInComments += ranges.reduce((n, c) => n + occurrences(c.text), 0);
      // Everything OUTSIDE the comments, which is where a definition, an
      // invocation or a registration would have to appear.
      let code = "";
      let at = 0;
      for (const c of ranges) {
        code += src.slice(at, c.pos);
        at = c.end;
      }
      code += src.slice(at);
      if (occurrences(code) > 0) absentInCode.push(`${rel} (${occurrences(code)})`);
    }
  }

  for (const kind of [
    "named",
    "bare-line",
    "bare-tracker",
    "dep-form",
    "dep-uncredited",
    "dead-path",
    "self-resolved",
  ]) {
    const offenders = found.filter((v) => v.kind === kind);
    check(
      `${root} carries no ${kind} citation in a comment`,
      offenders.length === 0,
      offenders.map((v) => `${v.where}  ${v.cite}`),
    );
  }

  const partial = found.filter((v) => v.kind === "partial-path");
  partialTotal += partial.length;
  partialSites.push(...partial.map((v) => `${v.where}  ${v.cite}`));
}

check(
  `the tree carries at most ${PARTIAL_PATH_CEILING} partial file spellings (now ${partialTotal})`,
  partialTotal <= PARTIAL_PATH_CEILING,
  partialSites,
);

check(
  "every scanned unit yielded comments, so none is listed but unread",
  unitComments.every((u) => Number(u.split(" ").pop()) > 0),
  unitComments,
);

// The docblock's own arithmetic, asserted. The first is the load-bearing half:
// were `secrets_list` ever implemented, the paragraph naming it as the decisive
// argument for leaving symbols alone would be citing a symbol that exists.
check(
  `${ABSENT_SYMBOL} appears nowhere outside a comment, which is what the docblock claims`,
  absentInCode.length === 0,
  absentInCode,
);
check(
  `${ABSENT_SYMBOL} is still cited ${ABSENT_SYMBOL_CITATIONS} times in comments (now ${absentInComments})`,
  absentInComments === ABSENT_SYMBOL_CITATIONS,
);

console.log(failed === 0 ? "\nAll citation-format checks passed." : `\n${failed} check(s) FAILED.`);
process.exit(failed === 0 ? 0 : 1);
