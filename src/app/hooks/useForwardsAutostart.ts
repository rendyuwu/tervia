import { useEffect, useRef } from "react";

import { defaultRuntimeDeps, startForwardAutostart } from "@/modules/forwards/controller";
import { ensureLoaded as ensureForwardsLoaded, listRules } from "@/modules/forwards/store";
import { ensureLoaded as ensureHostsLoaded } from "@/modules/hosts/store";
import { ensureLoaded as ensureVaultLoaded } from "@/modules/vault/store";

/**
 * Bring every `startWithApp` forward rule up once, with no terminal tab open
 * to its host - issue #77's other half of `startWithHost` (which rides a
 * terminal's own session and dies with the tab).
 *
 * Ref-guarded the same way `useStoreRecoveryNotices` is, for the same stated
 * reason: this only stops THIS mount's effect asking twice (a StrictMode
 * dev double-invoke), and a real remount would ask again - which is fine
 * here, since `startRule` itself is idempotent against a rule already
 * `running`/`starting` (the pre-dial `hostOwned`/status reads it already
 * makes) and `ssh/tunnel.ts`'s own session/forward maps single-flight a
 * second dial to the same target. Nothing new is invented for a second OS
 * process racing this one (only possible outside a release build - the
 * single-instance plugin is desktop-release-only, `src-tauri/src/lib.rs`);
 * that race rides the same existing machinery any two page Starts would.
 *
 * Waits for hosts, forwards and vault to finish hydrating - `startRule` (via
 * `ssh/tunnel.ts`) reads a host record and resolves its credential through
 * the vault, and this module reads the rule list itself.
 */
export function useForwardsAutostart(): void {
  const startedRef = useRef(false);
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    void (async () => {
      await Promise.all([ensureHostsLoaded(), ensureForwardsLoaded(), ensureVaultLoaded()]);
      const rules = await listRules();
      for (const rule of rules) {
        if (rule.startWithApp) void startForwardAutostart(rule, defaultRuntimeDeps);
      }
    })();
  }, []);
}
