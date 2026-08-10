import { lazy } from "react";

/**
 * Code-split panels shared across the App layout components. Defining each
 * `lazy()` wrapper once (rather than per consumer) keeps a single chunk +
 * single component identity even when a panel is rendered from more than one
 * slot.
 *
 * Each chunk loads only when its UI is first opened:
 *   - SFTP panel + its russh-sftp wrappers load only once an SSH leaf connects
 */
export const SshFileExplorer = lazy(() =>
  import("@/modules/ssh/SshFileExplorer").then((m) => ({ default: m.SshFileExplorer })),
);
