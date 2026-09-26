/**
 * Self-check for the Remote tree's drag-move and drop-target helpers.
 * Run: `npx tsx scripts/sftp-move-verify.ts`.
 *
 * `remoteMoveTarget` decides where an SFTP RENAME sends a dragged entry; a
 * wrong answer moves a folder into itself or onto its own path. `remoteDropDir`
 * picks the folder a drop targets. `unsafeOnWindows` guards a server-supplied
 * name before it is joined onto a local folder for a drag-download.
 */
import { remoteDropDir, remoteMoveTarget, unsafeOnWindows } from "../src/modules/ssh/remotePath";

let failed = 0;
function check(label: string, got: unknown, want: unknown): void {
  if (JSON.stringify(got) === JSON.stringify(want)) {
    console.log(`  ok: ${label}`);
  } else {
    console.error(`  FAIL: ${label} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    failed++;
  }
}

console.log("[remoteMoveTarget]");
check(
  "file into a sibling folder",
  remoteMoveTarget("/home/u/a.txt", "/home/u/docs"),
  "/home/u/docs/a.txt",
);
check("file into its own folder", remoteMoveTarget("/home/u/a.txt", "/home/u"), null);
check(
  "file into its own folder, trailing slash",
  remoteMoveTarget("/home/u/a.txt", "/home/u/"),
  null,
);
check("root file onto the root", remoteMoveTarget("/a.txt", "/"), null);
check("file into the root", remoteMoveTarget("/home/u/a.txt", "/"), "/a.txt");
check("folder onto itself", remoteMoveTarget("/home/u/docs", "/home/u/docs"), null);
check(
  "folder into its descendant",
  remoteMoveTarget("/home/u/docs", "/home/u/docs/sub/deeper"),
  null,
);
check(
  "folder into a prefix-named sibling",
  remoteMoveTarget("/home/u/doc", "/home/u/docs"),
  "/home/u/docs/doc",
);

console.log("[remoteDropDir]");
const row = (path: string, kind: string) => ({
  getAttribute: (name: string) =>
    name === "data-fs-path" ? path : name === "data-fs-kind" ? kind : null,
});
check(
  "folder row targets itself",
  remoteDropDir(row("/home/u/docs", "dir"), "/home/u"),
  "/home/u/docs",
);
check(
  "file row targets its parent",
  remoteDropDir(row("/home/u/docs/a.txt", "file"), "/home/u"),
  "/home/u/docs",
);
check("no row targets the root", remoteDropDir(null, "/home/u"), "/home/u");

console.log("[unsafeOnWindows]");
check("backslash traversal", unsafeOnWindows("..\\..\\Startup\\x.bat"), true);
check("NTFS stream", unsafeOnWindows("a:stream"), true);
check("device name", unsafeOnWindows("NUL"), true);
check("device name with an extension", unsafeOnWindows("com1.txt"), true);
check("console device name", unsafeOnWindows("CONIN$"), true);
check("device name with a trailing space", unsafeOnWindows("aux "), true);
check("device-prefixed ordinary name", unsafeOnWindows("console.log"), false);
check("plain name", unsafeOnWindows("report.pdf"), false);

process.exit(failed === 0 ? 0 : 1);
