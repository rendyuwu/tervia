import { useEffect, useRef } from "react";

import { toast } from "@/components/ui/toast";
import {
  ensureLoaded as ensureForwardsLoaded,
  onForwardsChanged,
  takeRecoveryNotice as takeForwardsRecoveryNotice,
} from "@/modules/forwards/store";
import {
  ensureLoaded as ensureHostsLoaded,
  onHostsChanged,
  takeRecoveryNotice as takeHostsRecoveryNotice,
} from "@/modules/hosts/store";
import {
  ensureLoaded as ensureCliAgentsLoaded,
  onCliAgentsChanged,
  takeRecoveryNotice as takeCliAgentsRecoveryNotice,
} from "@/modules/terminal/lib/cliAgents";
import {
  ensureLoaded as ensureVaultLoaded,
  onVaultChanged,
  takeRecoveryNotice as takeVaultRecoveryNotice,
} from "@/modules/vault/store";
import {
  ensureLoaded as ensureWorkspacesLoaded,
  onWorkspacesChanged,
  takeRecoveryNotice as takeWorkspacesRecoveryNotice,
} from "@/modules/workspaces/store";
import {
  announceRecovery,
  drainRecovery,
  type RecoverableStore,
  type Say,
} from "../lib/recoveryNotices";

/**
 * The stores whose recovery notice is SAID.
 *
 * Hand-maintained, and that is the whole hazard: `createRecoveredStore` produces
 * a notice for every store built on it, so a new one is silent until somebody
 * remembers this list - which is exactly how forwards stayed silent after it was
 * added. `scripts/recovery-notice-verify.ts` asserts set EQUALITY between the
 * modules under `src/modules` that export `takeRecoveryNotice` and the modules
 * named here, so the next one cannot be forgotten the same way.
 */
const STORES: RecoverableStore[] = [
  {
    label: "Saved machines",
    ensureLoaded: ensureHostsLoaded,
    takeRecoveryNotice: takeHostsRecoveryNotice,
    onChanged: onHostsChanged,
  },
  {
    label: "Vault",
    ensureLoaded: ensureVaultLoaded,
    takeRecoveryNotice: takeVaultRecoveryNotice,
    onChanged: onVaultChanged,
  },
  {
    // What the rail and the tab call this page, so the toast names the thing the
    // user would go and look at.
    label: "Port Forwarding",
    ensureLoaded: ensureForwardsLoaded,
    takeRecoveryNotice: takeForwardsRecoveryNotice,
    onChanged: onForwardsChanged,
  },
  {
    label: "Workspaces",
    ensureLoaded: ensureWorkspacesLoaded,
    takeRecoveryNotice: takeWorkspacesRecoveryNotice,
    onChanged: onWorkspacesChanged,
  },
  {
    // What the settings card that edits them is called.
    label: "Terminal AI agents",
    ensureLoaded: ensureCliAgentsLoaded,
    takeRecoveryNotice: takeCliAgentsRecoveryNotice,
    onChanged: onCliAgentsChanged,
  },
];

const say: Say = (t) => toast(t.message, { variant: t.variant });

/**
 * Tell the user when a store came back from its `.bak` - the half of crash
 * recovery that was missing. `createRecoveredStore` has always produced the
 * notice; until this hook, nothing in `src/` ever asked for it, so a recovery
 * was completely silent.
 *
 * Fired and forgotten, like the legacy-secret purge in App: it gates nothing and
 * cannot reject (see `announceRecovery`). The policy lives in
 * `app/lib/recoveryNotices.ts`; this is the mount and the real stores.
 *
 * A second toast cannot happen even across a genuine unmount/remount of App -
 * but `startedRef` is NOT why. It is a `useRef`, so a real remount gets a
 * fresh ref and would ask again; it only stops THIS mount's effect from
 * asking twice within its own lifetime (e.g. a React StrictMode dev
 * double-invoke of the same effect). What actually makes the guarantee hold
 * across a remount is store-side: `ensureLoaded()` DRAINS the notice slot
 * (`createRecoveredStore`'s `takeRecoveryNotice`, in `lib/recoveredStore.ts`)
 * before returning it, so every ask after the first - whichever ref asked -
 * finds the slot already empty and says nothing. The change listeners are
 * re-established on a remount instead, because those have to follow the
 * mount rather than the launch.
 */
export function useStoreRecoveryNotices(): void {
  const startedRef = useRef(false);
  useEffect(() => {
    if (!startedRef.current) {
      startedRef.current = true;
      for (const store of STORES) void announceRecovery(store, say);
    }

    const unlisteners: (() => void)[] = [];
    let disposed = false;
    for (const store of STORES) {
      void store
        .onChanged(() => drainRecovery(store, say))
        .then((off) => {
          if (disposed) off();
          else unlisteners.push(off);
        })
        .catch((e: unknown) => {
          console.error(`${store.label}: could not listen for changes`, e);
        });
    }

    return () => {
      disposed = true;
      for (const off of unlisteners) off();
    };
  }, []);
}
