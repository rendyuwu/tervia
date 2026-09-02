import { ForwardsPage } from "@/modules/forwards/ForwardsPage";
import { type RailViewKind } from "@/modules/tabs";
import { VaultPage } from "@/modules/vault/VaultPage";

/**
 * The body of a rail view - a page shown OVER the tab area instead of in it
 * (DCR-1). Vault and Port Forwarding land here; Hosts does not, because it is a
 * tab (see `tabs/lib/pages.ts`).
 *
 * A view, not a leaf, so it carries no pane header: there is no split, drag,
 * float or close for a surface that is one of two things the rail can show. The
 * tab strip stays visible above it and clicking any tab comes back, which is why
 * this can be a plain overlay rather than something the pane tree has to model.
 *
 * `switch` on the union rather than a lookup table so 6e/6f each replace one
 * branch and the compiler names the other if a third rail view is ever added.
 */
export function RailViewArea({ view }: { view: RailViewKind }) {
  switch (view) {
    case "vault":
      // No props: mounted only while this view is shown (`WorkspaceArea.tsx:142`)
      // - see `VaultPage.tsx` for why its caret claim is keyed on `[]`, not onScreen.
      return <VaultPage />;
    case "forwards":
      // No props, for the same reason `case "vault"` above has none - see
      // `ForwardsPage.tsx` for why its caret claim is keyed on `[]`, not onScreen.
      return <ForwardsPage />;
  }
}
