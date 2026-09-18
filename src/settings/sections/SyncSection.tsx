// The sync tab: what the user configures, and the status `main` writes back.
//
// ONE EXPLICIT SAVE, unlike every other section in this window. The others
// persist a preference per keystroke because a preference write is one store
// `set`; this one writes the OS keychain, so a passphrase typed a character at a
// time would be one keychain round trip per character, and the last one to land
// would not necessarily be the last one typed.
//
// SECRETS ARE WRITE-ONLY HERE. `SecretsIo` in `src/modules/vault/adapters.ts`
// has no single-value read at all - deliberately - and re-displaying a stored
// passphrase would buy nothing anyway. So the secret fields always render empty,
// and A BLANK FIELD MEANS "stored, unchanged": the alternative, treating blank
// as a clear, would wipe a working passphrase every time somebody opened this
// tab to correct a bucket name.

import { invoke } from "@tauri-apps/api/core";
import { emit } from "@tauri-apps/api/event";
import { ChevronDown } from "lucide-react";
import { useEffect, useMemo, useState, type ComponentProps } from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { createFileKeyValueStore } from "@/lib/fileKeyValueStore";
import { tauriStoreFileIo } from "@/lib/storeRecovery";
import { createSyncSettingsStore } from "@/modules/sync/store";
import {
  DEFAULT_SYNC_CONFIG,
  EMPTY_SYNC_STATUS,
  SYNC_ACCESS_KEY_ID_ACCOUNT,
  SYNC_KEYRING_SERVICE,
  SYNC_PASSPHRASE_ACCOUNT,
  SYNC_REQUEST_EVENT,
  SYNC_SECRET_ACCESS_KEY_ACCOUNT,
  SYNC_STORE_PATH,
  SYNC_WEBDAV_PASSWORD_ACCOUNT,
  SYNC_WEBDAV_USERNAME_ACCOUNT,
  namesTheSameRemote,
  type SyncConfig,
  type SyncRequest,
  type SyncStatus,
} from "@/modules/sync/types";
import { tauriSecretsIo } from "@/modules/vault/adapters";
import { Label } from "../components/Label";
import { SectionHeader } from "../components/SectionHeader";
import { SettingRow } from "../components/SettingRow";

/** The providers `build` in `src-tauri/src/modules/sync/provider.rs` dispatches
 *  on. A list rather than a constant because the id is stored and the label is
 *  not, and the two must not drift apart. */
const PROVIDERS: { id: string; label: string }[] = [
  { id: "s3", label: "S3-compatible" },
  { id: "webdav", label: "WebDAV (Nextcloud, ownCloud)" },
];

/**
 * What this session typed into the secret fields. Never read back out of the
 * keychain, and never written into {@link SyncConfig}.
 *
 * EVERY PROVIDER'S FIELDS IN ONE FLAT SHAPE, not one shape per provider. Only
 * the selected provider's fields are rendered, so the rest stay empty, and every
 * write below is already gated on "the user actually typed something" - which
 * makes the per-provider shape a discriminated union earning nothing but the
 * narrowing it would then demand at each of five call sites.
 */
type SecretDraft = {
  passphrase: string;
  accessKeyId: string;
  secretAccessKey: string;
  webdavUsername: string;
  webdavPassword: string;
};

const EMPTY_SECRETS: SecretDraft = {
  passphrase: "",
  accessKeyId: "",
  secretAccessKey: "",
  webdavUsername: "",
  webdavPassword: "",
};

/** Whether the keychain already holds each one, for the placeholders only. */
type SecretPresence = {
  passphrase: boolean;
  accessKeyId: boolean;
  secretAccessKey: boolean;
  webdavUsername: boolean;
  webdavPassword: boolean;
};

const NO_SECRETS: SecretPresence = {
  passphrase: false,
  accessKeyId: false,
  secretAccessKey: false,
  webdavUsername: false,
  webdavPassword: false,
};

/** What a rejected `invoke` or store call is worth showing. Tauri rejects with a
 *  bare string, so `String(e)` on its own would render "[object Object]" for the
 *  `Error` cases and nothing readable for the string ones. */
function message(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

function when(at: number | null): string {
  return at === null ? "Never" : new Date(at).toLocaleString();
}

/**
 * One labelled free-text field.
 *
 * A REAL `label`/`id` pair rather than `aria-label`, because these fields carry
 * a description each and a screen reader that gets only the terse name loses it.
 * `SettingRow` puts its control in a shrink-0 right slot, which is
 * right for a switch and wrong for an input that wants the width, so this
 * borrows that row's chrome and stacks instead.
 */
function Field({
  id,
  label,
  description,
  ...props
}: { id: string; label: string; description?: string } & ComponentProps<"input">) {
  return (
    <div className="border-border/60 bg-card flex flex-col gap-1.5 rounded-lg border px-3 py-2.5">
      <label htmlFor={id} className="text-[12.5px] font-medium">
        {label}
      </label>
      {description ? (
        <span className="text-muted-foreground text-[10.5px] leading-relaxed">{description}</span>
      ) : null}
      <Input id={id} spellCheck={false} className="h-8 rounded-lg text-[12px]" {...props} />
    </div>
  );
}

export function SyncSection() {
  // Every method on this wrapper drops its cache before it runs, which is what
  // makes a status `main` wrote visible here and a configuration written here
  // visible there. Nothing in this file has to reach past it to say so.
  const settings = useMemo(
    () => createSyncSettingsStore(createFileKeyValueStore(SYNC_STORE_PATH, tauriStoreFileIo)),
    [],
  );

  const [config, setConfig] = useState<SyncConfig>(DEFAULT_SYNC_CONFIG);
  const [secrets, setSecrets] = useState<SecretDraft>(EMPTY_SECRETS);
  const [stored, setStored] = useState<SecretPresence>(NO_SECRETS);
  const [status, setStatus] = useState<SyncStatus>(EMPTY_SYNC_STATUS);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  // Raised when the carry toggle goes on to off, and only then: the bodies
  // already published are unaffected by the toggle, so the offer to remove them
  // belongs at the moment the user changes their mind and nowhere else.
  const [offerPurge, setOfferPurge] = useState(false);
  const [purged, setPurged] = useState<number | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      const [loadedConfig, loadedStatus, present] = await Promise.all([
        settings.readConfig(),
        settings.readStatus(),
        // Presence only: the values are dropped on the next line and never
        // enter state. A failed keychain read costs a placeholder and must not
        // cost the configuration, so it resolves to "nothing stored" rather
        // than rejecting the whole load.
        //
        // EVERY PROVIDER'S ACCOUNTS, not the selected one's. Asking for a subset
        // would mean waiting for the configuration to land before the keychain
        // could be asked anything, and it would leave the placeholders lying the
        // moment the user picks a different provider from the list below without
        // reopening this tab.
        tauriSecretsIo
          .getAll(SYNC_KEYRING_SERVICE, [
            SYNC_PASSPHRASE_ACCOUNT,
            SYNC_ACCESS_KEY_ID_ACCOUNT,
            SYNC_SECRET_ACCESS_KEY_ACCOUNT,
            SYNC_WEBDAV_USERNAME_ACCOUNT,
            SYNC_WEBDAV_PASSWORD_ACCOUNT,
          ])
          .catch((): (string | null)[] => []),
      ]);
      if (!alive) return;
      const [passphrase, accessKeyId, secretAccessKey, webdavUsername, webdavPassword] = present;
      setConfig(loadedConfig);
      setStatus(loadedStatus);
      setStored({
        passphrase: passphrase != null,
        accessKeyId: accessKeyId != null,
        secretAccessKey: secretAccessKey != null,
        webdavUsername: webdavUsername != null,
        webdavPassword: webdavPassword != null,
      });
    })().catch((e: unknown) => {
      if (alive) setError(message(e));
    });
    return () => {
      alive = false;
    };
  }, [settings]);

  const refreshStatus = async () => {
    setStatus(await settings.readStatus());
  };

  /** Ask `main` to do the thing only `main` may do. Nothing here performs it. */
  const request = (what: SyncRequest) => {
    void emit(SYNC_REQUEST_EVENT, what).catch((e: unknown) => setError(message(e)));
  };

  const onSave = async () => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      // Only what the user actually filled in. A blank field here would write
      // the empty string, which every presence check in the app reads as a real
      // secret and nothing ever reads back to notice.
      if (secrets.passphrase) {
        await tauriSecretsIo.set(SYNC_KEYRING_SERVICE, SYNC_PASSPHRASE_ACCOUNT, secrets.passphrase);
      }
      if (secrets.accessKeyId) {
        await tauriSecretsIo.set(
          SYNC_KEYRING_SERVICE,
          SYNC_ACCESS_KEY_ID_ACCOUNT,
          secrets.accessKeyId,
        );
      }
      if (secrets.secretAccessKey) {
        await tauriSecretsIo.set(
          SYNC_KEYRING_SERVICE,
          SYNC_SECRET_ACCESS_KEY_ACCOUNT,
          secrets.secretAccessKey,
        );
      }
      if (secrets.webdavUsername) {
        await tauriSecretsIo.set(
          SYNC_KEYRING_SERVICE,
          SYNC_WEBDAV_USERNAME_ACCOUNT,
          secrets.webdavUsername,
        );
      }
      if (secrets.webdavPassword) {
        await tauriSecretsIo.set(
          SYNC_KEYRING_SERVICE,
          SYNC_WEBDAV_PASSWORD_ACCOUNT,
          secrets.webdavPassword,
        );
      }
      // A DIFFERENT REMOTE IS A DIFFERENT ETAG MAP, and it is emptied before
      // the configuration that renames the remote is stored - the pull this
      // Save requests must not be able to start on the old map. Compared
      // against what the FILE says rather than against the copy this window
      // loaded, because the pull running in `main` is the other writer here.
      // See {@link REMOTE_IDENTITY_FIELDS}.
      if (!namesTheSameRemote(await settings.readConfig(), config)) {
        await settings.writeEtags({});
      }
      await settings.writeConfig(config);
      setStored({
        passphrase: stored.passphrase || secrets.passphrase.length > 0,
        accessKeyId: stored.accessKeyId || secrets.accessKeyId.length > 0,
        secretAccessKey: stored.secretAccessKey || secrets.secretAccessKey.length > 0,
        webdavUsername: stored.webdavUsername || secrets.webdavUsername.length > 0,
        webdavPassword: stored.webdavPassword || secrets.webdavPassword.length > 0,
      });
      setSecrets(EMPTY_SECRETS);
      setSaved(true);
      // THE ONLY THING THAT MAKES A NEW CONFIGURATION TAKE EFFECT. Storing it
      // opens no session: `SyncState` in the Rust process is empty until `main`
      // configures it, and `main` configures it on the way into a pull.
      if (config.enabled) request("pull");
    } catch (e: unknown) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  const onToggleEnabled = async (next: boolean) => {
    const before = config;
    const updated = { ...config, enabled: next };
    setConfig(updated);
    setSaved(false);
    // Turning it ON waits for Save, because the fields beside it may be
    // half-typed. Turning it OFF must not wait for anything: off means no
    // network, and a user who switches it off and closes the window has to get
    // that, not an unsaved intention.
    if (next) return;
    setBusy(true);
    setError(null);
    try {
      await settings.writeConfig(updated);
      await invoke("sync_disable");
    } catch (e: unknown) {
      // THE SWITCH GOES BACK. It was moved optimistically, and if the write or
      // the close failed then sync is still running - a switch reading off over
      // a device that is still uploading is a worse failure than the one that
      // caused it, because the error message is the only thing contradicting it
      // and the user has no reason to read an error about a setting they can
      // see took effect.
      setConfig(before);
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  const onToggleCarry = (next: boolean) => {
    setConfig({ ...config, carrySecrets: next });
    setSaved(false);
    setPurged(null);
    setOfferPurge(!next && config.carrySecrets);
  };

  const onPurge = async () => {
    setBusy(true);
    setError(null);
    try {
      // THE TOGGLE IS SAVED FIRST, because the purge acts on the remote and the
      // next push acts on the STORED configuration - not on the switch. A user
      // who purges and then closes this window without pressing Save would
      // otherwise leave carrying on, and the very next push would put every
      // body back.
      await settings.writeConfig(config);
      setSaved(true);
      setPurged(await invoke<number>("sync_purge_secrets"));
    } catch (e: unknown) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  const providerLabel = PROVIDERS.find((p) => p.id === config.provider)?.label ?? config.provider;
  // WebDAV differs from S3 in more than a field list: it authenticates with a
  // username and a password sent on every request, and it has no conditional
  // write to offer, so both the credential fields and the Behaviour block below
  // turn on this.
  const webdav = config.provider === "webdav";

  return (
    <div className="flex flex-col gap-6">
      <SectionHeader
        title="Sync"
        description="Carry hosts, vault identities and port forwards between your devices through storage you own."
      />

      <div className="flex flex-col gap-2">
        <Label>Sync</Label>
        <SettingRow
          title="Enable sync"
          description="Off means no network: nothing is uploaded, downloaded or listed, and no credential leaves this device. On, this device reconciles with the storage below on launch, on focus and after an edit."
        >
          <Switch
            checked={config.enabled}
            disabled={busy}
            onCheckedChange={(v) => void onToggleEnabled(v)}
            aria-label="Enable sync"
          />
        </SettingRow>
      </div>

      <div className="flex flex-col gap-2">
        <Label>Storage</Label>
        <SettingRow
          title="Provider"
          description="Which kind of storage this device talks to: S3 and S3-compatible storage, or a WebDAV server such as Nextcloud or ownCloud. Each keeps its own credentials, so switching between them does not send one's secret to the other."
        >
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="h-9 justify-between gap-2 px-2.5 text-[12px]">
                <span>{providerLabel}</span>
                <ChevronDown size={12} strokeWidth={2} className="opacity-70" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-[200px]">
              {PROVIDERS.map((p) => (
                <DropdownMenuItem
                  key={p.id}
                  onSelect={() => setConfig({ ...config, provider: p.id })}
                  className="text-[12px]"
                >
                  {p.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </SettingRow>

        <Field
          id="sync-endpoint"
          label="Endpoint"
          description={
            webdav
              ? "The full URL of the collection your files hang off, not the server's home page - on Nextcloud and ownCloud that is the WebDAV address their own settings screen shows you. There is no default: this is the one field that decides whose servers your records go to."
              : "The full URL of the storage service. There is no default: this is the one field that decides whose servers your records go to."
          }
          value={config.endpoint}
          onChange={(e) => setConfig({ ...config, endpoint: e.target.value })}
        />
        {webdav && config.endpoint.trimStart().toLowerCase().startsWith("http://") ? (
          // Gated on the PROVIDER as well as the scheme, because the sentence is
          // only true of this one: a WebDAV request carries the password itself,
          // where an S3 request carries a signature computed from the secret and
          // never the secret. Allowed rather than refused - a WebDAV server on a
          // home network with no certificate is a real arrangement, and which
          // networks are worth trusting is the user's call and not this app's.
          //
          // CASE-INSENSITIVE, because the backend's url parser lowercases a
          // scheme and this warning is the only defence there is - a pasted
          // uppercase spelling would otherwise be accepted in silence.
          <div
            role="status"
            className="border-border/60 bg-card flex flex-col gap-1 rounded-lg border px-3 py-2.5"
          >
            <span className="text-[11.5px] font-semibold">
              Note: this endpoint is not encrypted
            </span>
            <span className="text-muted-foreground text-[10.5px] leading-relaxed">
              The password below is sent with every single request, in a form that can be read back,
              and anything between this device and that server can read it - other machines on the
              same network, and whatever the traffic passes through on the way. Your records
              themselves stay encrypted with the passphrase either way. Use an https:// address
              instead if the server offers one.
            </span>
          </div>
        ) : null}
        {webdav ? null : (
          <>
            <Field
              id="sync-region"
              label="Region"
              value={config.region}
              onChange={(e) => setConfig({ ...config, region: e.target.value })}
            />
            <Field
              id="sync-bucket"
              label="Bucket"
              value={config.bucket}
              onChange={(e) => setConfig({ ...config, bucket: e.target.value })}
            />
          </>
        )}
        <Field
          id="sync-prefix"
          label="Prefix"
          description="Where in that storage this inventory lives. May be left empty, which puts it at the root."
          value={config.prefix}
          onChange={(e) => setConfig({ ...config, prefix: e.target.value })}
        />
        {webdav ? (
          <>
            <Field
              id="sync-webdav-username"
              label="Username"
              description="The account on the WebDAV server. Stored in the OS keychain beside the password rather than in the settings file - it is half of a credential, and splitting the two halves across two places is how one of them gets left behind."
              autoComplete="off"
              placeholder={stored.webdavUsername ? "Stored. Leave blank to keep it." : "Not set"}
              value={secrets.webdavUsername}
              onChange={(e) => setSecrets({ ...secrets, webdavUsername: e.target.value })}
            />
            <Field
              id="sync-webdav-password"
              label="Password"
              description="Stored in the OS keychain under the sync service, never in the settings file. If your server offers app passwords, one of those is worth more here than your account password: it can be revoked on its own."
              type="password"
              autoComplete="off"
              placeholder={stored.webdavPassword ? "Stored. Leave blank to keep it." : "Not set"}
              value={secrets.webdavPassword}
              onChange={(e) => setSecrets({ ...secrets, webdavPassword: e.target.value })}
            />
          </>
        ) : (
          <>
            <Field
              id="sync-access-key-id"
              label="Access key ID"
              description="Stored in the OS keychain under the sync service, never in the settings file."
              autoComplete="off"
              placeholder={stored.accessKeyId ? "Stored. Leave blank to keep it." : "Not set"}
              value={secrets.accessKeyId}
              onChange={(e) => setSecrets({ ...secrets, accessKeyId: e.target.value })}
            />
            <Field
              id="sync-secret-access-key"
              label="Secret access key"
              description="Stored in the OS keychain under the sync service, never in the settings file."
              type="password"
              autoComplete="off"
              placeholder={stored.secretAccessKey ? "Stored. Leave blank to keep it." : "Not set"}
              value={secrets.secretAccessKey}
              onChange={(e) => setSecrets({ ...secrets, secretAccessKey: e.target.value })}
            />
          </>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <Label>Encryption</Label>
        <Field
          id="sync-passphrase"
          label="Passphrase"
          description="Everything is encrypted with this before it is uploaded, so the storage provider never sees a hostname or a key. It is stored in the OS keychain under the sync service, and every device you sync must be given the same one."
          type="password"
          autoComplete="off"
          placeholder={stored.passphrase ? "Stored. Leave blank to keep it." : "Not set"}
          value={secrets.passphrase}
          onChange={(e) => setSecrets({ ...secrets, passphrase: e.target.value })}
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label>Behaviour</Label>
        {/* TWO WHOLE RENDERINGS rather than one with the toggle conditional
            inside it. On a provider with no conditional write to offer there is
            no switch, and so the note below it cannot say "the setting above,
            which you chose" - it would be naming something that is not on the
            screen. Keeping the arms separate is also what keeps the S3 arm
            exactly the shape `scripts/sync-scheduler-verify.ts` reads, which is
            the check that the warning is reached from the toggle rather than
            merely present in this file somewhere. */}
        {webdav ? (
          // A SWITCH THE USER COULD MOVE WITH NO EFFECT WOULD BE WORSE THAN NO
          // SWITCH: it would read as a promise. WebDAV leaves the conditional
          // write to each server, so Tervia never asks for one here, and the
          // consequence is stated unconditionally because nothing about it is
          // the user's to change.
          <div
            role="status"
            className="border-border/60 bg-card flex flex-col gap-1 rounded-lg border px-3 py-2.5"
          >
            <span className="text-[11.5px] font-semibold">Note: conditional writes are off</span>
            <span className="text-muted-foreground text-[10.5px] leading-relaxed">
              Two devices that write the same record at the same moment can leave only one of the
              two writes on the remote, and the other is lost without an error. WebDAV does not
              guarantee a server can refuse a write that would do that, so Tervia never asks one to,
              and there is nothing here to turn on. This is what this provider costs, not a setting
              you got wrong.
            </span>
          </div>
        ) : (
          <>
            <SettingRow
              title="Endpoint honours conditional writes"
              description="Turn this on only if you know your storage supports a write that fails when the object changed underneath it. Tervia does not test for it."
            >
              <Switch
                checked={config.cas}
                onCheckedChange={(v) => {
                  setConfig({ ...config, cas: v });
                  setSaved(false);
                }}
                aria-label="Endpoint honours conditional writes"
              />
            </SettingRow>
            {!config.cas ? (
              // Worded as a consequence of the SETTING, not as a finding.
              // Nothing in the app probes the endpoint - `Caps` in
              // `src-tauri/src/modules/sync/provider.rs` is this toggle and
              // nothing else - so a label claiming Tervia detected anything
              // would be a claim no code backs.
              <div
                role="status"
                className="border-border/60 bg-card flex flex-col gap-1 rounded-lg border px-3 py-2.5"
              >
                <span className="text-[11.5px] font-semibold">
                  Note: conditional writes are off
                </span>
                <span className="text-muted-foreground text-[10.5px] leading-relaxed">
                  With this off, two devices that write the same record at the same moment can leave
                  only one of the two writes on the remote, and the other is lost without an error.
                  This follows from the setting above, which you chose; Tervia does not check what
                  your endpoint supports.
                </span>
              </div>
            ) : null}
          </>
        )}

        <SettingRow
          title="Carry private key bodies"
          description="Off means this device neither publishes a private key body nor accepts one that arrives, in both directions at once. On, key bodies travel with the identities that own them, encrypted with the passphrase above."
        >
          <Switch
            checked={config.carrySecrets}
            onCheckedChange={onToggleCarry}
            aria-label="Carry private key bodies"
          />
        </SettingRow>
        {offerPurge ? (
          <div
            role="status"
            className="border-border/60 bg-card flex flex-col gap-2 rounded-lg border px-3 py-2.5"
          >
            <span className="text-[11.5px] font-semibold">
              Note: key bodies already on the remote are still there
            </span>
            <span className="text-muted-foreground text-[10.5px] leading-relaxed">
              Turning this off stops new bodies going out from this device. It does not touch the
              ones already published, because a reconcile never merges key bodies - it keeps the
              winning record's and discards the loser's. Removing them is a separate pass over the
              stored objects.
            </span>
            {/* Stated because it is the difference between a removal that holds
                and one that silently does not, and the user is the only one who
                can tell which they have. */}
            <span className="text-muted-foreground text-[10.5px] leading-relaxed">
              Turn this off on every device that syncs before removing them. A device still carrying
              key bodies holds the only copy of what was stripped, so its next reconcile publishes
              them again.
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-8 px-2 text-[11px]"
                // Needs a session, and only the main window opens one - which
                // it does on the way into a pull. With sync off there is
                // nothing open and the command would answer that nothing is
                // configured, which names none of that.
                disabled={busy || !config.enabled}
                onClick={() => void onPurge()}
              >
                Remove published key bodies
              </Button>
              {!config.enabled ? (
                <span className="text-muted-foreground text-[10.5px]">
                  Turn sync on to reach the stored objects.
                </span>
              ) : null}
              {purged !== null ? (
                <span className="text-muted-foreground text-[10.5px]">
                  Removed key bodies from {purged} object{purged === 1 ? "" : "s"}.
                </span>
              ) : null}
            </div>
          </div>
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            className="h-8 px-3 text-[11px]"
            disabled={busy}
            onClick={() => void onSave()}
          >
            {busy ? "Saving…" : "Save"}
          </Button>
          {saved ? (
            <span role="status" className="text-muted-foreground text-[10.5px]">
              Saved. A pull has been requested so the new settings take effect.
            </span>
          ) : null}
        </div>
        {error ? (
          <div
            role="alert"
            className="border-destructive/40 bg-destructive/5 flex flex-col gap-1 rounded-lg border px-3 py-2.5"
          >
            <span className="text-destructive text-[11.5px] font-semibold">Error</span>
            <span className="text-[10.5px] leading-relaxed break-words whitespace-pre-wrap">
              {error}
            </span>
          </div>
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <Label>Status</Label>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2 text-[11px]"
            disabled={!config.enabled}
            onClick={() => request("pull")}
          >
            Pull now
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2 text-[11px]"
            disabled={!config.enabled}
            onClick={() => request("push")}
          >
            Push now
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2 text-[11px]"
            onClick={() => void refreshStatus()}
          >
            Refresh
          </Button>
        </div>
        <SettingRow title="Last pull">
          <span className="text-muted-foreground text-[11px]">{when(status.lastPullAt)}</span>
        </SettingRow>
        <SettingRow title="Last push">
          <span className="text-muted-foreground text-[11px]">{when(status.lastPushAt)}</span>
        </SettingRow>
        <SettingRow
          title="Waiting to be pushed"
          description="The remote is missing at least this many records from this device: what the last completed pull found, or what this device has changed and not yet uploaded, whichever is larger."
        >
          <span className="text-muted-foreground text-[11px] tabular-nums">{status.pending}</span>
        </SettingRow>

        {status.quarantine.length > 0 ? (
          <div className="border-border/60 bg-card flex flex-col gap-1.5 rounded-lg border px-3 py-2.5">
            <span className="text-[12.5px] font-medium">Unreadable remote objects</span>
            <span className="text-muted-foreground text-[10.5px] leading-relaxed">
              These could not be decrypted or parsed, so they were left alone. A wrong passphrase on
              one device is the usual cause. Nothing here is deleted.
            </span>
            <ul className="flex flex-col gap-1">
              {status.quarantine.map((q) => (
                <li key={q.name} className="font-mono text-[10.5px] break-all">
                  {q.name} - <span className="text-muted-foreground">{q.reason}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {status.stale.length > 0 ? (
          <div className="border-border/60 bg-card flex flex-col gap-1.5 rounded-lg border px-3 py-2.5">
            <span className="text-[12.5px] font-medium">Local records the remote has dropped</span>
            <span className="text-muted-foreground text-[10.5px] leading-relaxed">
              This device still holds these and the remote no longer has an object for them. They
              are reported and never deleted. Each is older than the 90-day window a deletion
              travels in, so the likeliest reading is that it was deleted on another device long
              ago. A pull does not re-publish these - edit one to send it to the remote again, or
              delete it here to accept the removal.
            </span>
            <ul className="flex flex-col gap-1">
              {status.stale.map((s) => (
                <li key={`${s.kind}:${s.id}`} className="font-mono text-[10.5px] break-all">
                  {s.kind} - <span className="text-muted-foreground">{s.id}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {status.lastError ? (
          <div
            role="alert"
            className="border-destructive/40 bg-destructive/5 flex flex-col gap-1 rounded-lg border px-3 py-2.5"
          >
            <span className="text-destructive text-[11.5px] font-semibold">
              Error on the last run
            </span>
            {/* In full. A truncated remote error is the one shape that reliably
                hides the clause naming the bucket or the missing permission. */}
            <span className="font-mono text-[10.5px] leading-relaxed break-words whitespace-pre-wrap">
              {status.lastError}
            </span>
          </div>
        ) : null}
      </div>
    </div>
  );
}
