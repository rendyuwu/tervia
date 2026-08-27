import { useEffect, useRef } from "react";

import { toast } from "@/components/ui/toast";
import {
  ensureLoaded as ensureHostsLoaded,
  onHostsChanged,
  takeRecoveryNotice as takeHostsRecoveryNotice,
} from "@/modules/hosts/store";
import {
  ensureLoaded as ensureVaultLoaded,
  onVaultChanged,
  takeRecoveryNotice as takeVaultRecoveryNotice,
} from "@/modules/vault/store";
import {
  announceRecovery,
  drainRecovery,
  type RecoverableStore,
  type Say,
} from "../lib/recoveryNotices";

/** The stores with a crash-recovery pass. Both are `createRecoveredStore`
 *  instances, so both have always produced a notice nothing ever took. */
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
 * The startup pass runs exactly once per launch - `startedRef`, not the effect's
 * empty dep array, is what guarantees that, so a remount cannot re-run it and
 * re-toast. The change listeners are re-established on a remount instead,
 * because those have to follow the mount rather than the launch.
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
