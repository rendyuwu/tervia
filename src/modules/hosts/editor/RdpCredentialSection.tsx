import { Input } from "@/components/ui/input";
import type { RdpCredential } from "@/modules/rdp/bridge";
import { HOST_KEYRING_SERVICE, HOST_RDP_PASSWORD_FIELD, vaultAccount } from "@/modules/vault/types";

import { Field } from "./FormControls";
import { SECRET_STORE_LOCATIONS } from "./secretStoreCopy";
import type { RdpCredentialDraft } from "./types";

// The RDP credential region, lifted out of `RdpConnectionDialog` as it stood, and
// changed only where the new plumbing forced it.
//
// The two properties that make this section different from the SSH one, both
// load-bearing:
//
// 1. The saved password is NEVER loaded into the form. There is no read-back path
//    for it at all, so an edit leaves the field blank and blank means "leave the
//    stored password alone". The only way the field is ever non-empty is the user
//    typing in it.
// 2. Test therefore PICKS its credential rather than always sending one. A typed
//    password goes down inline - the one sanctioned use of that form, since a
//    draft has no keychain entry yet - and an untouched field on a saved host
//    sends the keychain reference instead. So Test exercises exactly what a real
//    connect will use.

export type RdpCredentialSectionProps = {
  /** The identity this host is bound to, or null when it owns its password
   *  itself. A bound row shows a read-only panel and nothing editable. */
  boundIdentity: string | null;
  /** `boundIdentity`'s NAME, resolved by the dialog from the `identityRows`
   *  prop it already holds - this component does no vault read of its own.
   *  `undefined` renders the id alone, which covers a dangling binding. */
  identityName?: string;
  value: RdpCredentialDraft;
  onChange: (patch: Partial<RdpCredentialDraft>) => void;
  /** Whether the SAVED row already has a password stored. Blank is only
   *  "unchanged" when there is something to leave unchanged. */
  hasStoredPassword: boolean;
};

/**
 * The credential half of the form's validation, kept beside the fields it is
 * about. The shared half lives in the dialog.
 */
export function validateRdpCredential(
  draft: RdpCredentialDraft,
  boundIdentity: string | null,
  hasStoredPassword: boolean,
): string | null {
  // A vault-bound row has no username and no password of its own to validate:
  // both belong to the identity, and the form shows neither.
  if (boundIdentity) return null;
  if (!draft.username.trim()) return "Username is required";
  // Blank is only "unchanged" when there IS something to leave unchanged.
  if (!draft.password && !hasStoredPassword) return "Password is required";
  return null;
}

/**
 * Which credential form the editor may use for a Test right now.
 *
 * A typed password has no keychain entry behind it yet, which is the entire
 * reason the inline form exists; anything else must go through the reference.
 *
 * A vault-bound row gets neither. Its password lives at
 * `tervia-vault :: <identityId>::password`, which is a reference this form could
 * build - but the username and domain come from the identity too, so a working
 * Test needs the resolver and the picker that goes with it. Test is disabled
 * instead of dialling with the wrong user.
 */
export function rdpCredentialForTest(args: {
  draft: RdpCredentialDraft;
  boundIdentity: string | null;
  /** The saved host's id, or undefined for one that is not saved yet. */
  hostId: string | undefined;
  hasStoredPassword: boolean;
}): RdpCredential | null {
  if (args.boundIdentity) return null;
  if (args.draft.password) return { kind: "inline", password: args.draft.password };
  if (args.hostId && args.hasStoredPassword) {
    return {
      kind: "keychain",
      service: HOST_KEYRING_SERVICE,
      account: vaultAccount(args.hostId, HOST_RDP_PASSWORD_FIELD),
    };
  }
  return null;
}

export function RdpCredentialSection({
  boundIdentity,
  identityName,
  value,
  onChange,
  hasStoredPassword,
}: RdpCredentialSectionProps) {
  // Username, domain and password are one block, because a vault identity owns
  // all three: offering to edit the username of a bound row would be editing a
  // third of something this dialog cannot change.
  if (boundIdentity) {
    return <VaultBindingPanel identityId={boundIdentity} identityName={identityName} />;
  }

  return (
    <>
      <div className="grid grid-cols-2 gap-2">
        <Field label="Username">
          <Input
            value={value.username}
            onChange={(e) => onChange({ username: e.target.value })}
            placeholder="Administrator"
            spellCheck={false}
            className="h-8 font-mono text-[12px]"
          />
        </Field>
        <Field label="Domain (optional)">
          <Input
            value={value.domain}
            onChange={(e) => onChange({ domain: e.target.value })}
            placeholder="CORP"
            spellCheck={false}
            className="h-8 font-mono text-[12px]"
          />
        </Field>
      </div>
      <span className="text-muted-foreground -mt-1.5 text-[10.5px]">
        Leave the domain empty for a local account, or put a UPN (
        <span className="font-mono">user@domain.example</span>) in the username instead.
      </span>

      <Field label="Password">
        <Input
          type="password"
          value={value.password}
          onChange={(e) => onChange({ password: e.target.value })}
          placeholder={hasStoredPassword ? "•••••••• (saved, leave blank to keep)" : ""}
          className="h-8 font-mono text-[12px]"
        />
        <span className="text-muted-foreground text-[10.5px]">
          {hasStoredPassword
            ? "A password is stored for this connection. It is not shown here; leave this blank to keep it, or type a new one to replace it."
            : `Stored outside Tervia's settings file: ${SECRET_STORE_LOCATIONS}.`}
        </span>
      </Field>
    </>
  );
}

/**
 * What stands in for the username, domain and password fields when the row is
 * bound to a shared vault identity.
 *
 * Read-only, and it names which parts of the form still work: refusing to open
 * the dialog at all would leave an imported host unable to be renamed, resized
 * or re-pointed at all. The identity used to be named by
 * id alone because resolving the name meant a vault read this dialog had no
 * reason to do - it no longer does: `HostEditorDialog` holds `identityRows` for
 * its own credential picker and passes the resolved name down, so the id is now a
 * footnote under it rather than the only thing on screen, kept for the one case
 * a name cannot cover - a binding naming an identity that no longer exists.
 */
function VaultBindingPanel({
  identityId,
  identityName,
}: {
  identityId: string;
  identityName?: string;
}) {
  return (
    <Field label="Credential">
      {/* Same box as the recorded-certificate block. */}
      <div className="border-border/60 bg-muted/30 flex flex-col gap-1 rounded-md border px-2 py-1.5">
        <span className="text-[11px]">
          This host uses the shared vault identity{identityName ? ` "${identityName}"` : ""}.
        </span>
        <span className="text-muted-foreground truncate font-mono text-[10.5px]" title={identityId}>
          {identityId}
        </span>
      </div>
      <span className="text-muted-foreground text-[10.5px]">
        The username, domain and password belong to the identity, so none of them is editable here
        and Test cannot run. The binding is changed with the Credential picker above; everything
        else on this form can still be edited.
      </span>
    </Field>
  );
}
