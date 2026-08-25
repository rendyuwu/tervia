import { useEffect, useMemo, useState } from "react";

import { listIdentities, listKeys, onVaultChanged } from "./store";
import type { VaultIdentity, VaultKey } from "./types";

// The vault's two record types, kept fresh across edits and across WINDOWS - the
// store broadcasts on every commit, so an identity renamed in the settings
// webview reaches a Hosts page in the main one without either side knowing about
// the other. Modelled on `modules/hosts/useHosts.ts`, which does the same for
// hosts and groups.
//
// MAPS rather than arrays because every caller looks a record up by id: a host
// names an identity, an identity names a key. The Hosts page asks both questions
// once per rendered card, and a list would make each one a linear scan inside a
// render pass. Maps are also what keeps the presence pips free of IPC - the
// `has*` flags are already on the record, so nothing here reads a secret back to
// decide what a card shows (research §5.2).

/**
 * Both collections as one value.
 *
 * A structural type, and deliberately not imported by the page's `derive.ts`
 * even though that module takes exactly this shape: `derive.ts` stays React-free
 * so a verify script can exercise it under plain node, and it declares its own
 * `VaultSnapshot` for that reason. The two are structurally identical, which is
 * what lets {@link useVault}'s result be passed straight in.
 */
export type VaultMaps = {
  identities: ReadonlyMap<string, VaultIdentity>;
  keys: ReadonlyMap<string, VaultKey>;
};

export function useVaultIdentities(): Map<string, VaultIdentity> {
  const [identities, setIdentities] = useState<Map<string, VaultIdentity>>(() => new Map());
  useEffect(() => {
    const load = () =>
      void listIdentities().then((list) => setIdentities(new Map(list.map((i) => [i.id, i]))));
    load();
    const unsub = onVaultChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return identities;
}

export function useVaultKeys(): Map<string, VaultKey> {
  const [keys, setKeys] = useState<Map<string, VaultKey>>(() => new Map());
  useEffect(() => {
    const load = () => void listKeys().then((list) => setKeys(new Map(list.map((k) => [k.id, k]))));
    load();
    const unsub = onVaultChanged(load);
    return () => {
      void unsub.then((fn) => fn());
    };
  }, []);
  return keys;
}

/**
 * Both maps as one stable value.
 *
 * The `useMemo` is load-bearing rather than an optimisation: a consumer that
 * lists this in a `useMemo` dependency array - which the Hosts page does, for
 * every derived row it builds - would otherwise re-derive on every single
 * render, because a freshly built object is never `Object.is` the last one. Same
 * class of mistake as the zustand v5 selector trap in research §12.7, and the
 * same fix: hand back a reference that only changes when the data does.
 */
export function useVault(): VaultMaps {
  const identities = useVaultIdentities();
  const keys = useVaultKeys();
  return useMemo(() => ({ identities, keys }), [identities, keys]);
}
