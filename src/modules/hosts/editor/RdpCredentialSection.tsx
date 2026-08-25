import { Input } from "@/components/ui/input";
import type { RdpCredential } from "@/modules/rdp/bridge";
import { HOST_KEYRING_SERVICE, HOST_RDP_PASSWORD_FIELD, vaultAccount } from "@/modules/vault/types";

import { Field } from "./FormControls";
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
  value,
  onChange,
  hasStoredPassword,
}: RdpCredentialSectionProps) {
  // Username, domain and password are one block, because a vault identity owns
  // all three: offering to edit the username of a bound row would be editing a
  // third of something this dialog cannot change.
  if (boundIdentity) return <VaultBindingPanel identityId={boundIdentity} />;

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
            : "Stored in the OS keychain, not in Tervia's settings file."}
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
 * the dialog at all would leave an imported host unable to be renamed, resized or
 * re-pointed until the identity picker ships. The identity is named by id rather
 * than by name because resolving the name means a vault read, and a dialog that
 * cannot edit the binding does not need to load it.
 */
function VaultBindingPanel({ identityId }: { identityId: string }) {
  return (
    <Field label="Credential">
      {/* Same box as the recorded-certificate block. */}
      <div className="border-border/60 bg-muted/30 flex flex-col gap-1 rounded-md border px-2 py-1.5">
        <span className="text-[11px]">This host uses a shared vault identity.</span>
        <span className="text-muted-foreground truncate font-mono text-[10.5px]" title={identityId}>
          {identityId}
        </span>
      </div>
      <span className="text-muted-foreground text-[10.5px]">
        The username, domain and password belong to the identity, so none of them is editable here
        and Test cannot run - choosing or changing an identity arrives with the Vault page.
        Everything else on this form is editable, and saving leaves the binding exactly as it is.
      </span>
    </Field>
  );
}
