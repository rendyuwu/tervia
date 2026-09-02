import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Combobox, type ComboboxOption } from "@/modules/hosts/editor/Combobox";
import { Field } from "@/modules/hosts/editor/FormControls";
import { savedHostOptions } from "@/modules/hosts/editor/hostOptions";
import { findHost } from "@/modules/hosts/store";
import { isSshHost, type Host } from "@/modules/hosts/types";
import type { ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import { pageMustStopFirst, stopRule } from "../controller";
import { privilegedPortWarning } from "../page/derive";
import { findRule, newRuleId, upsertRule } from "../store";
import type { ForwardRule } from "../types";
import {
  EMPTY_RULE_DRAFT,
  parseLocalPort,
  ruleDraftFrom,
  ruleRecordFrom,
  type RuleDraft,
  validateRuleDraft,
} from "./draft";

// The forward rule editor. Shares its shell with `IdentityEditorDialog.tsx` -
// the same token/load/ready/saving/error mechanics `HostEditorDialog.tsx`
// established - but there is no secret anywhere in this form: a rule rides the
// credential of the SSH host it names (`../types.ts`'s file header), so this
// dialog's `DialogDescription` says nothing about a store, unlike the identity
// editor's.
//
// `savedHostOptions` (`@/modules/hosts/editor/hostOptions`) is reused verbatim
// for the SSH host picker rather than written again here - DCR-4's answer
// (2026-09-02): `Field`, `Combobox` and `savedHostOptions` out of
// `hosts/editor/` are three instances of an already-counted decision. That
// function already filters to `SshHost[]` and already omits an RDP host,
// which is what makes an unknown- or wrong-protocol-host defect structurally
// unreachable from a FRESH selection in this editor. It cannot reach a host
// picked in an earlier sitting and then deleted or reprotocolled out from
// under a saved rule - see `save` below for that case.
//
// THE ONE THING THIS FORM DOES BEYOND WRITING A RECORD: it stops a forward
// this page is running for the rule being edited, before the write. Every
// component of `ssh/tunnel.ts`'s `forwardKey` is a field on this form, so the
// write invalidates the key that rule's own Stop would name - see `save`
// below. That is why `../controller` is in this file's import graph at all.
//
// VLT-90's placement rule, applied: `privilegedPortWarning` renders under the
// Local port field; the store's refusal for a non-SSH or missing host renders
// under the SSH host field; the generic save error renders at the bottom,
// where store and IPC failures belong that point at no one field.

export type RuleEditorTarget = { mode: "create" } | { mode: "edit"; ruleId: string };

export type RuleEditorDialogProps = {
  target: RuleEditorTarget | null;
  onClose: () => void;
  /**
   * Every saved host, UNFILTERED. The dialog filters to SSH itself with
   * `hosts.filter(isSshHost)` inside a `useMemo`.
   *
   * A PROP rather than a fresh read of the host store, for the reason
   * `IdentityEditorDialog.tsx:51-64` gives about its own `keyRows` prop: a
   * picker that re-reads the store is how two surfaces come to disagree about
   * one list. The page hands over its UNFILTERED host array - this list must
   * not follow the page's search box.
   */
  hosts: readonly Host[];
};

/** A token for "the row the form is showing right now" - see
 *  `HostEditorDialog.tsx`'s own `tokenFor` for the two jobs this does. */
function tokenFor(target: RuleEditorTarget | null): string | null {
  if (!target) return null;
  if (target.mode === "edit") return `edit:${target.ruleId}`;
  return "create";
}

export function RuleEditorDialog({ target, onClose, hosts }: RuleEditorDialogProps): ReactNode {
  const [mode, setMode] = useState<"create" | "edit">("create");
  const [draft, setDraft] = useState<RuleDraft>(EMPTY_RULE_DRAFT);
  /** The stored rule being edited, or null in create mode. */
  const [existing, setExisting] = useState<ForwardRule | null>(null);
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  /** The generic save/IPC error, rendered at the bottom - VLT-90's "neither"
   *  case. Never the store's host refusal; see {@link hostError} below. */
  const [error, setError] = useState<string | null>(null);
  /** The SSH host field's own error: "no host chosen", or the store's refusal
   *  for a saved rule whose host was deleted or turned into an RDP host in
   *  another window. Rendered under the SSH host field, never at the bottom -
   *  VLT-90. */
  const [hostError, setHostError] = useState<string | null>(null);

  const token = tokenFor(target);
  /** The token whose load has been applied - see `HostEditorDialog.tsx`'s
   *  `applied` for why this is a ref and not state. */
  const applied = useRef<string | null>(null);

  // Reset and populate whenever the editor is pointed at a different row.
  // Closing deliberately leaves the draft alone: the next open resets it, and
  // wiping it here would empty every field behind the dialog's own close
  // animation.
  useEffect(() => {
    if (applied.current === token) return;
    applied.current = token;
    if (!target || !token) return;

    setError(null);
    setHostError(null);
    setSaving(false);
    setExisting(null);
    setReady(false);
    setMode(target.mode);

    const stale = () => applied.current !== token;

    const load = async () => {
      if (target.mode === "create") {
        setDraft(EMPTY_RULE_DRAFT);
        setReady(true);
        return;
      }
      let rule: ForwardRule | undefined;
      try {
        rule = await findRule(target.ruleId);
      } catch (e) {
        if (!stale()) setError(e instanceof Error ? e.message : String(e));
        return;
      }
      if (stale()) return;
      if (!rule) {
        setError("That rule no longer exists - it was deleted in another window.");
        return;
      }
      setExisting(rule);
      setDraft(ruleDraftFrom(rule));
      setReady(true);
    };

    void load();
  }, [target, token]);

  const patch = (p: Partial<RuleDraft>) => setDraft((d) => ({ ...d, ...p }));

  const sshHosts = useMemo(() => hosts.filter(isSshHost), [hosts]);
  const hostOptions: ComboboxOption[] = useMemo(
    () => savedHostOptions(sshHosts, "Select an SSH host…"),
    [sshHosts],
  );
  /** Live, on every keystroke - research §12.8: the editor warns at entry, not
   *  at start. Reads {@link parseLocalPort} rather than a second parse, so
   *  this can never disagree with what `ruleRecordFrom` is about to write. */
  const localPortWarning = privilegedPortWarning(parseLocalPort(draft.localPort));

  const save = async () => {
    setError(null);
    setHostError(null);

    if (!draft.hostId) {
      setHostError("Choose an SSH host to carry this rule.");
      return;
    }
    const invalid = validateRuleDraft(draft);
    if (invalid) {
      setError(invalid);
      return;
    }

    setSaving(true);
    try {
      const id = existing?.id ?? newRuleId();
      // STOPPED BEFORE THE RECORD IT WAS OPENED UNDER CHANGES, and this side
      // of `upsertRule` rather than the other side is the whole claim.
      // `ssh/tunnel.ts`'s `forwardKey` is
      // `connectionId|remoteHost|remotePort|localPort` (`tunnel.ts:246-252`)
      // and this form can edit ALL FOUR, so a Stop issued after the write
      // names an entry that does not exist: the row reads "Stopped",
      // `markStopped` has discarded the claim, so no Stop can ever be issued
      // again - and the old port stays bound for the rest of the app's life,
      // exactly the leak `ForwardsPage.tsx`'s confirm closes on the delete
      // path. `existing` and NOT the record being written, for the same
      // reason: the identity `stopRule` needs is the one the forward was
      // opened under.
      //
      // UNCONDITIONAL ON WHICH FIELDS CHANGED, with the cost named rather
      // than hidden: saving a rename on a running rule stops it too, and the
      // row then reads "Stopped" with Start offered. Comparing just the four
      // key fields would spare that and would go stale the moment
      // `forwardKey` grows a fifth component - one visible, recoverable row
      // state against a port bound with no in-app recovery.
      //
      // `pageMustStopFirst` reads BOTH owners live (`../controller`): a
      // forward a terminal opened is not this dialog's to stop, and the
      // page's own status has to be read now rather than when the form
      // loaded. It answers `true` for a row still DIALLING as well as for a
      // running one, so a Save landed mid-dial stops that bind instead of
      // leaving the resolving open to publish itself under a key the write has
      // already invalidated - its own doc carries that argument.
      //
      // AND IF THE WRITE BELOW THROWS, the rule is left stopped with its
      // record unchanged and the message the catch shows says nothing about
      // it: reachable only on the host-deleted-in-another-window case `:215-221`
      // describes, recoverable with one Start click on the row, and the
      // alternative is holding the stop until after a write whose whole point
      // is that it invalidates the key that stop needs.
      if (existing && pageMustStopFirst(existing.id)) await stopRule(existing);
      // `ruleRecordFrom(id, draft)` is handed to `upsertRule` UNMODIFIED - no
      // spread, no override, no second call to it anywhere else in this
      // function. See `./draft.ts`'s header for why a second assembly here
      // would be exactly the drift that split exists to prevent (VLT-76).
      await upsertRule(ruleRecordFrom(id, draft), findHost);
      onClose();
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      // `upsertRule`'s only two host-shaped refusals both name the host id
      // (`forwards/store.ts:112-121`; its own doc at `:37-43` says every
      // refusal names the value it refuses), so the id is the anchor that
      // tells the two kinds of catch apart. Reachable only on an EDIT of a
      // rule whose host was deleted or turned into an RDP host in another
      // window - the picker above only ever offers a currently-saved SSH
      // host, so a fresh selection can never land here.
      if (message.includes(draft.hostId)) {
        setHostError(message);
      } else {
        setError(message);
      }
    } finally {
      setSaving(false);
    }
  };

  const busy = saving || !ready;
  const title = mode === "create" ? "New rule" : "Edit rule";

  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            A local port forward that rides the chosen SSH host&apos;s own connection.
          </DialogDescription>
        </DialogHeader>

        {/* DialogContent caps at calc(100dvh-2rem). min-h-0 lets the inner stack
            shrink so the form scrolls inside the dialog instead of top fields
            sliding off-screen. -mr-2/pr-2 keeps the scrollbar off the content
            edge - same reasoning as `HostEditorDialog.tsx`. */}
        <div className="-mr-2 flex min-h-0 flex-col gap-3 overflow-y-auto pr-2">
          {!ready && !error ? <p className="text-muted-foreground text-[11px]">Loading…</p> : null}
          {ready ? (
            <>
              <Field label="Name">
                <Input
                  value={draft.name}
                  onChange={(e) => patch({ name: e.target.value })}
                  placeholder="db-tunnel"
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
              </Field>

              <Field label="SSH host">
                <Combobox
                  options={hostOptions}
                  value={draft.hostId}
                  onChange={(hostId) => patch({ hostId })}
                  searchPlaceholder="Search hosts…"
                  emptyLabel="No host found."
                />
                {hostError ? (
                  <span className="text-destructive text-[10.5px]">{hostError}</span>
                ) : null}
              </Field>

              <Field label="Local port">
                <Input
                  value={draft.localPort}
                  onChange={(e) => patch({ localPort: e.target.value })}
                  placeholder="Auto"
                  inputMode="numeric"
                  className="h-8 font-mono text-[12px]"
                />
                {localPortWarning ? (
                  <span className="text-muted-foreground text-[10.5px]">{localPortWarning}</span>
                ) : null}
              </Field>

              <Field label="Remote host">
                <Input
                  value={draft.remoteHost}
                  onChange={(e) => patch({ remoteHost: e.target.value })}
                  placeholder="10.0.0.9 or db.internal"
                  spellCheck={false}
                  className="h-8 font-mono text-[12px]"
                />
              </Field>

              <Field label="Remote port">
                <Input
                  value={draft.remotePort}
                  onChange={(e) => patch({ remotePort: e.target.value })}
                  inputMode="numeric"
                  className="h-8 font-mono text-[12px]"
                />
              </Field>

              <Field label="Start with host">
                <label className="flex items-start gap-2 text-[12px]">
                  <Checkbox
                    checked={draft.startWithHost}
                    onCheckedChange={(checked) => patch({ startWithHost: checked === true })}
                    className="mt-0.5"
                  />
                  <span>
                    Bring this rule up when this host&apos;s terminal connects. It closes with that
                    tab.
                  </span>
                </label>
              </Field>

              <Field label="Description (optional)">
                <Input
                  value={draft.description}
                  onChange={(e) => patch({ description: e.target.value })}
                  placeholder="What this rule is for"
                  spellCheck={false}
                  className="h-8 text-[12px]"
                />
              </Field>
            </>
          ) : null}

          {error ? <p className="text-destructive text-[11px]">{error}</p> : null}
        </div>

        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">
              Cancel
            </Button>
          </DialogClose>
          <Button size="sm" onClick={() => void save()} disabled={busy}>
            {saving ? "Saving…" : mode === "edit" ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
