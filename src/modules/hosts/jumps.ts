import type { SshJumpHop } from "@/modules/ssh/bridge";
import { defaultResolveDeps, resolveSshAuth, type ResolveDeps } from "@/modules/vault/resolve";

import { isSshHost, type Host, type SshHost } from "./types";

// Walking a ProxyJump chain into the ordered hop list `openSsh` expects.
//
// Two functions: the walk, which is pure and shared with the write guard in
// `store.ts`, and the resolution on top of it. Free functions over a list rather
// than store methods, because that is what makes them testable and what lets one
// connect resolve a whole chain against a single `listHosts()` read.
//
// Credentials come from `resolveSshAuth`, so a hop bound to a vault identity and
// a hop owning its credentials inline are the same code here. That is also where
// the plaintext enters JS, once per hop - the pre-existing SSH defect
// (issues/11), unchanged by this module and not made worse by it.

/** Hard cap so a malformed chain cannot spin forever building hops. */
export const MAX_JUMP_HOPS = 16;

/**
 * The whole chain from one starting jump host, collected from the target
 * OUTWARD: `[closest-to-target, ..., entry]`. Empty when there is no jump host.
 *
 * Four refusals, all of which would otherwise surface as something else:
 *
 * `selfId` seeds cycle detection, so a host that lists itself - directly or
 * transitively - throws instead of looping.
 *
 * A hop that is not an SSH host throws. The two old stores could not express an
 * RDP jump host, one merged store can, and there is nothing to jump through.
 *
 * A missing hop throws rather than silently dropping a tunnel, which would
 * otherwise dial the target directly - past the bastion the user chose it for.
 *
 * An over-long chain throws rather than spinning on malformed data.
 *
 * Pure, synchronous and exported because the WRITE guard in `store.ts` needs
 * exactly this walk and must not carry a second copy of it. Its own
 * `assertSshTarget` covers only the first hop, so a 2-cycle (A jumps through B, B
 * through A) used to pass every write check and then fail every connect to either
 * host with the cycle error from here. Refusing at the write and at the connect
 * are both needed, for the same reason the RDP-hop refusal is checked twice:
 * neither covers a row an import or another window put there.
 */
export function jumpChain(
  startProxyJumpId: string | undefined,
  selfId: string | undefined,
  all: Host[],
): SshHost[] {
  if (!startProxyJumpId) return [];
  const byId = new Map(all.map((h) => [h.id, h]));
  const visited = new Set<string>();
  if (selfId) visited.add(selfId);

  const chain: SshHost[] = [];
  let cursor: string | undefined = startProxyJumpId;
  while (cursor) {
    if (visited.has(cursor)) throw new Error("hosts: jump host chain has a cycle");
    visited.add(cursor);
    const hop = byId.get(cursor);
    if (!hop) throw new Error("hosts: a jump host in the chain no longer exists");
    if (!isSshHost(hop)) {
      throw new Error(`hosts: "${hop.name}" is an RDP host and cannot be a jump host`);
    }
    chain.push(hop);
    if (chain.length > MAX_JUMP_HOPS) {
      throw new Error(`hosts: jump host chain too long (max ${MAX_JUMP_HOPS})`);
    }
    cursor = hop.proxyJumpId;
  }
  return chain;
}

/**
 * The ordered hops to reach a host, in CONNECT order: the publicly reachable
 * entry host first, the hop closest to the target last. Empty when there is no
 * jump host.
 *
 * Everything that can be refused about the chain is refused by
 * {@link jumpChain}; what this adds is the credential per hop.
 */
export async function resolveJumpHops(
  startProxyJumpId: string | undefined,
  selfId: string | undefined,
  all: Host[],
  deps: ResolveDeps = defaultResolveDeps,
): Promise<SshJumpHop[]> {
  // Connect order is the reverse of the walk: dial the entry host first.
  const chain = jumpChain(startProxyJumpId, selfId, all).reverse();

  const hops: SshJumpHop[] = [];
  for (const hop of chain) {
    // An agent hop reads nothing from the keychain, but the call is one path for
    // every mode, so a hop is built the same way regardless of how it authenticates.
    const { user, ...credentials } = await resolveSshAuth(hop.credential, deps);
    hops.push({
      connectionId: hop.id,
      host: hop.host,
      port: hop.port,
      user,
      ...credentials,
      expectedFingerprint: hop.lastFingerprint || undefined,
    });
  }
  return hops;
}
