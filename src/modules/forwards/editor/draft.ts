import type { ForwardRule } from "../types";

// What `RuleEditorDialog` edits, and the pure functions that turn a draft into
// the record `upsertRule` is handed - the same split as `vault/editor/draft.ts`,
// for the reason its own header gives: the record builder is the single
// normaliser, and a second normalisation anywhere else (a draft default, a
// change handler, a spread at the call site) is how the two drift.
// `ruleRecordFrom` is THE place a `ForwardRule` is built from this editor;
// `RuleEditorDialog`'s save hands its result to `upsertRule` unmodified.
//
// Pure - no React, no store, no Tauri - mirroring `page/derive.ts`'s own
// reason for being pure: every rule below is exercised by value, under plain
// node, with nothing to mock.
//
// `validateRuleDraft` catches only what a draft can decide ALONE: it takes no
// host list and cannot ask whether `hostId` names a saved SSH host, so it does
// not try - `forwards/store.ts:93-122`'s host and protocol refusals stay the
// store's alone, and `RuleEditorDialog` classifies whichever one comes back
// from the round trip rather than this file guessing at it first. Ports are
// the one thing worth a shared conversion: {@link parseLocalPort} is reused by
// both `ruleRecordFrom` (the write) and the dialog's live privileged-port
// warning (a read), so the two can never describe one typed string two
// different ways.

/**
 * `RuleEditorDialog`'s fields.
 *
 * Ports are STRINGS here and numbers in the record - `HostEditorDialog.tsx`'s
 * `SharedDraft` idiom (`port: ""`, and `String(host.port)` on load) - so a
 * partial or empty port reads as an empty input instead of `NaN` painted into
 * a text box.
 */
export type RuleDraft = {
  name: string;
  hostId: string;
  /** "" or "0" both mean auto - see {@link parseLocalPort}. */
  localPort: string;
  remoteHost: string;
  remotePort: string;
  startWithHost: boolean;
  description: string;
};

/** Always replaced, never mutated in place - the same discipline
 *  `vault/editor/draft.ts`'s `EMPTY_IDENTITY_DRAFT` is held to. */
export const EMPTY_RULE_DRAFT: RuleDraft = {
  name: "",
  hostId: "",
  localPort: "",
  remoteHost: "",
  remotePort: "",
  startWithHost: false,
  description: "",
};

/** A stored rule, opened for editing. `localPort: 0` becomes `""`, the same
 *  blank {@link EMPTY_RULE_DRAFT} starts with, so a fresh rule and an
 *  auto-port rule read identically in the field. */
export function ruleDraftFrom(rule: ForwardRule): RuleDraft {
  return {
    name: rule.name,
    hostId: rule.hostId,
    localPort: rule.localPort === 0 ? "" : String(rule.localPort),
    remoteHost: rule.remoteHost,
    remotePort: String(rule.remotePort),
    startWithHost: rule.startWithHost,
    description: rule.description ?? "",
  };
}

/**
 * The one place a typed local-port string becomes the number the rest of the
 * app works in. Blank and `"0"` both parse to `0` ("let the OS pick" -
 * `types.ts:20-21`); anything else is a plain `Number.parseInt`, the same
 * idiom `HostEditorDialog.tsx:635` uses for its own port field.
 *
 * Exported so `RuleEditorDialog`'s live `privilegedPortWarning` preview reads
 * a typed port exactly the way {@link ruleRecordFrom} will write it - a second
 * parse in the dialog, even one that looks equivalent, is how the warning
 * shown while typing and the port actually saved could disagree.
 */
export function parseLocalPort(localPort: string): number {
  const trimmed = localPort.trim();
  if (trimmed === "" || trimmed === "0") return 0;
  return Number.parseInt(trimmed, 10);
}

/** Not exported - nothing outside `ruleRecordFrom` and `validateRuleDraft`
 *  needs a typed remote port, unlike the local port's live warning. */
function parseRemotePort(remotePort: string): number {
  return Number.parseInt(remotePort.trim(), 10);
}

/** Mirrors `forwards/store.ts`'s own `isValidLocalPort` so this form refuses
 *  nothing the store would accept and accepts nothing the store would refuse. */
function isValidLocalPort(port: number): boolean {
  return port === 0 || (Number.isInteger(port) && port >= 1 && port <= 65535);
}

/** Mirrors `forwards/store.ts`'s own `isValidRemotePort`. */
function isValidRemotePort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * The rule form's validation, or `null` when it passes.
 *
 * Deliberately silent on `hostId`: choosing no host is refused in
 * `RuleEditorDialog` itself, under the SSH host field, before this function is
 * ever called, and a `hostId` that names a deleted or now-RDP host is left for
 * `upsertRule` to refuse - see the file header. This function's job is
 * everything else the store also checks that a draft can decide with no
 * lookup: name, both ports and the remote host - four of `forwards/store.ts`'s
 * six refusals (`:95-122`) that need nothing but the draft itself.
 */
export function validateRuleDraft(draft: RuleDraft): string | null {
  if (!draft.name.trim()) return "Name is required";
  if (!isValidLocalPort(parseLocalPort(draft.localPort))) {
    return "Local port must be 0 (auto), or 1–65535";
  }
  if (!draft.remoteHost.trim()) return "Remote host is required";
  if (!isValidRemotePort(parseRemotePort(draft.remotePort))) {
    return "Remote port must be 1–65535";
  }
  return null;
}

/**
 * The record `upsertRule` is handed.
 *
 * THE single place a `ForwardRule` is built from this editor.
 * `RuleEditorDialog`'s save calls `upsertRule(ruleRecordFrom(id, draft),
 * findHost)` and hands the result through UNMODIFIED - no spread, no
 * override, no second call to this function anywhere else in that method.
 * The whole class of defect this guards against is a one-line spread at exactly
 * this call site, so this function existing at all is the fix: a caller that wants to
 * change one field has to change it HERE, in the draft, not at the call site.
 */
export function ruleRecordFrom(id: string, draft: RuleDraft): ForwardRule {
  return {
    id,
    name: draft.name.trim(),
    hostId: draft.hostId,
    localPort: parseLocalPort(draft.localPort),
    remoteHost: draft.remoteHost.trim(),
    remotePort: parseRemotePort(draft.remotePort),
    startWithHost: draft.startWithHost,
    description: draft.description.trim() || undefined,
  };
}
