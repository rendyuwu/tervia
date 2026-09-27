// POSIX helpers for the Remote tree; remote paths are forward-slash whatever
// the local OS. No imports, so plain `tsx` verify scripts can load this file.

export function remoteJoin(dir: string, name: string): string {
  return dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`;
}

export function remoteDirname(path: string): string {
  const i = path.lastIndexOf("/");
  return i <= 0 ? "/" : path.slice(0, i);
}

export function remoteBasename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

/** Folder a drop onto `row` targets, in either tree: a folder row is itself, any
 *  other row (file, symlink) its parent, no row (the tree body, `null`) the root.
 *  The local Files tree also joins child paths with `/` (`useFileTree.joinPath`),
 *  so one rule serves both. A parent shorter than the root is that root minus its
 *  trailing slash (`C:/`, `/srv/`), so the root is returned as written: it is the
 *  key the tree refreshes by. */
export function treeDropDir(row: Pick<Element, "getAttribute"> | null, rootPath: string): string {
  const p = row?.getAttribute("data-fs-path");
  if (!p) return rootPath;
  if (row?.getAttribute("data-fs-kind") === "dir") return p;
  const parent = remoteDirname(p);
  return parent.length < rootPath.length ? rootPath : parent;
}

/** Where moving `from` into `toDir` lands it, or null for a no-op or impossible
 *  move: its own folder, or a folder into itself or a descendant. */
export function remoteMoveTarget(from: string, toDir: string): string | null {
  if (toDir === from || toDir.startsWith(`${from}/`)) return null;
  const to = remoteJoin(toDir, remoteBasename(from));
  return to === from ? null : to;
}

/** True when a remote file name cannot be one Windows path component: `\` is a
 *  separator there and `:` opens an NTFS stream, so joining it onto a local
 *  folder would write outside that folder, and a device name (`NUL`, `COM1`,
 *  with any extension, or trailing dots/spaces Windows strips) opens the device
 *  instead of a file. The name comes from the server, which may be hostile. */
export function unsafeOnWindows(name: string): boolean {
  return (
    /[\\:]/.test(name) || /^(con|prn|aux|nul|com\d|lpt\d|conin\$|conout\$)([. ].*)?$/i.test(name)
  );
}
