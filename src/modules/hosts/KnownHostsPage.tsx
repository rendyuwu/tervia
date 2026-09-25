/**
 * The Known Hosts page: every pinned SSH host key and every pinned RDP
 * certificate, across every saved host, in one list - the read side of
 * `HostPins` (`src/modules/hosts/types.ts`) that nothing before this page ever needed, because
 * every earlier reader already held one host's own record in hand.
 *
 * A RAIL VIEW, not a pane leaf. `WorkspaceArea.tsx`'s `railView !== null`
 * branch mounts this only while the rail's Known Hosts button is pressed and
 * unmounts it on the way out - see `VaultPage.tsx`'s header for the fuller
 * reasoning behind that shape. Unlike Vault and Port Forwarding, this page
 * claims no caret on mount: it has no search box, and no other input either.
 *
 * Revoking a row commits immediately through `forgetPin` (`store.ts`), the
 * same `withPins`/`nextPins` path the host editor's own `PinnedKeyRow` Forget
 * button commits through on Save - there is one `pins` map per host, and
 * this page only ever reads and writes it, never a copy of it.
 */
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/toast";
import { useCallback, useMemo, type ReactNode } from "react";

import { forgetPin } from "./store";
import { knownHostRows, type KnownHostRow } from "./types";
import { useHosts } from "./useHosts";

const PROTOCOL_LABEL: Record<KnownHostRow["protocol"], string> = {
  ssh: "SSH host key",
  rdp: "RDP certificate",
};

export function KnownHostsPage(): ReactNode {
  const hostsById = useHosts();

  // A fresh array per render - see the row-builder memo comment in
  // `VaultPage.tsx` above its own `hosts`/`identities`/`keys` memos for why
  // this has to live in a memo and never inside a store selector.
  const rows = useMemo(() => knownHostRows(Array.from(hostsById.values())), [hostsById]);

  const onForget = useCallback((row: KnownHostRow) => {
    void forgetPin(row.hostId, row.address).catch((e: unknown) =>
      toast(e instanceof Error ? e.message : String(e), { variant: "error" }),
    );
  }, []);

  return (
    <div className="bg-background flex h-full w-full min-w-0 flex-col">
      <div className="border-b p-3">
        <p className="text-muted-foreground text-[11px] leading-relaxed">
          Pins are stored on this device only, and never sync to another one. Forgetting a pin here
          means the next connect to that address asks you to trust its key or certificate again.
        </p>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {rows.length === 0 ? (
          <div className="text-muted-foreground flex flex-col gap-1 rounded-lg border border-dashed p-6 text-center">
            <span className="text-foreground text-sm font-medium">
              No pinned keys or certificates yet.
            </span>
            <span className="mx-auto max-w-72 text-[11px] leading-relaxed opacity-70">
              A host earns one the first time you accept its server key or certificate.
            </span>
          </div>
        ) : (
          <div className="flex flex-col gap-1.5">
            {rows.map((row) => (
              <KnownHostRowView
                key={`${row.hostId}::${row.address}`}
                row={row}
                onForget={onForget}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function KnownHostRowView({
  row,
  onForget,
}: {
  row: KnownHostRow;
  onForget: (row: KnownHostRow) => void;
}): ReactNode {
  return (
    <div className="border-border/60 bg-muted/30 flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <div className="flex min-w-0 items-center gap-1.5 text-xs">
          <span className="truncate font-medium">{row.hostName}</span>
          <span className="text-muted-foreground">·</span>
          <span className="text-muted-foreground truncate">{PROTOCOL_LABEL[row.protocol]}</span>
        </div>
        <div className="flex min-w-0 flex-wrap items-baseline gap-x-2 text-[10.5px]">
          <span className="text-muted-foreground truncate">{row.address}</span>
          <span
            className="text-muted-foreground/80 truncate font-mono select-all"
            title={row.fingerprint}
          >
            {row.fingerprint}
          </span>
        </div>
      </div>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="h-6 shrink-0 px-2 text-[10.5px]"
        aria-label={`Forget ${row.hostName} (${row.address})`}
        onClick={() => onForget(row)}
      >
        Forget
      </Button>
    </div>
  );
}
