import { useEffect } from "react";

import { defaultRuntimeDeps, startForwardAutostart } from "@/modules/forwards/controller";
import { ensureLoaded as ensureForwardsLoaded, listRules } from "@/modules/forwards/store";
import { ensureLoaded as ensureHostsLoaded, listHosts } from "@/modules/hosts/store";
import { isSshHost } from "@/modules/hosts/types";
import { ensureLoaded as ensureVaultLoaded } from "@/modules/vault/store";

/**
 * MODULE SCOPE, NOT A `useRef`. The root `ErrorBoundary`'s "Try again"
 * (`src/main.tsx`'s `reset`) remounts `<App/>`, which gives a fresh component
 * instance a fresh `useRef` the same as a genuine first mount would - a ref
 * only survives RE-RENDERS of the same mount, not a remount. `startRule`
 * itself is NOT idempotent against a rule already `running` on its own:
 * `acquireForward`'s reuse branch (`ssh/tunnel.ts`) takes a SECOND reference
 * under the SAME claim a second dial resolves into, so a remount would
 * double a claim a single Stop can only halve, and would restart every rule
 * the user had Stopped since launch. A module-scope flag survives the
 * remount and still resets on `window.location.reload()`, which also resets
 * the controller and tunnel module state this flag is guarding entry into.
 */
let launched = false;

/**
 * Bring every `startWithApp` forward rule up once, with no terminal tab open
 * to its host - the no-tab counterpart of `startWithHost` (which rides a
 * terminal's own session and dies with the tab).
 *
 * Waits for hosts, forwards and vault to finish hydrating - `startRule` (via
 * `ssh/tunnel.ts`) reads a host record and resolves its credential through
 * the vault, and this module reads the rule list itself.
 *
 * SKIPS A RULE WHOSE HOST IS DANGLING - deleted, or not (or no longer) a
 * saved SSH host, which a synced landing can leave behind if it arrives
 * ahead of the host it names. `page/RuleCard.tsx` already refuses a dangling
 * Start silently, by design; this hook fires with no dialog on screen for a
 * failure to report against, so raising an error toast (and walking the
 * backoff ladder) for a host that will never resolve would just be
 * launch-time noise for every such rule.
 */
export function useForwardsAutostart(): void {
  useEffect(() => {
    if (launched) return;
    launched = true;
    void (async () => {
      await Promise.all([ensureHostsLoaded(), ensureForwardsLoaded(), ensureVaultLoaded()]);
      const [rules, hosts] = await Promise.all([listRules(), listHosts()]);
      const sshHostIds = new Set(hosts.filter(isSshHost).map((h) => h.id));
      for (const rule of rules) {
        if (rule.startWithApp && sshHostIds.has(rule.hostId)) {
          void startForwardAutostart(rule, defaultRuntimeDeps);
        }
      }
    })().catch((e) => console.error("forwards: launch autostart failed", e));
  }, []);
}
