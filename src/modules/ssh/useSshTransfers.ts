import { useCallback, useRef, useState } from "react";
import { toast } from "@/components/ui/toast";
import { describeError } from "@/lib/describeError";
import { dispatchFsRefreshForFile } from "@/modules/explorer/lib/fsRefresh";
import { remoteBasename, remoteJoin } from "./remotePath";
import { localBasename, sftpDownload, sftpUpload } from "./sftp";

/** In-flight transfer progress, or null when idle. Drives the explorer's
 *  progress strip. `index`/`count` are 1-based for display. */
export type SshTransferState = {
  verb: "Uploading" | "Downloading";
  name: string;
  index: number;
  count: number;
  written: number;
  total: number;
};

// Uploads (OS drop, paste, drag from the Files tree) and downloads (Download…,
// drag onto the Files tree) for the Remote tree, sharing one progress strip.
export function useSshTransfers(sessionId: number | null, onUploaded: (remoteDir: string) => void) {
  const onUploadedRef = useRef(onUploaded);
  onUploadedRef.current = onUploaded;

  // ponytail: one strip for every transfer, so a second one started mid-way
  // takes it over and the first to finish clears it. Queue transfers if
  // concurrent ones become common.
  const [transfer, setTransfer] = useState<SshTransferState | null>(null);

  const uploadFiles = useCallback(
    async (paths: string[], dir: string, overwrite: boolean) => {
      if (sessionId === null || paths.length === 0) return;
      const failures: string[] = [];
      for (let i = 0; i < paths.length; i++) {
        const local = paths[i];
        const name = localBasename(local);
        const base = { verb: "Uploading", name, index: i + 1, count: paths.length } as const;
        setTransfer({ ...base, written: 0, total: 0 });
        try {
          await sftpUpload(sessionId, local, remoteJoin(dir, name), overwrite, (p) =>
            setTransfer({ ...base, ...p }),
          );
        } catch (e) {
          failures.push(`${name}: ${String(e)}`);
        }
      }
      setTransfer(null);
      onUploadedRef.current(dir);
      const ok = paths.length - failures.length;
      if (failures.length === 0) {
        toast(`Uploaded ${ok} file${ok === 1 ? "" : "s"} to ${dir}`, { variant: "success" });
      } else {
        console.error("ssh upload failures:", failures);
        toast(`Uploaded ${ok}/${paths.length} - ${failures.length} failed (${failures[0]})`, {
          variant: "warning",
        });
      }
    },
    [sessionId],
  );

  const downloadFile = useCallback(
    async (remotePath: string, localPath: string, overwrite: boolean) => {
      if (sessionId === null) return;
      const name = remoteBasename(remotePath);
      const base = { verb: "Downloading", name, index: 1, count: 1 } as const;
      setTransfer({ ...base, written: 0, total: 0 });
      try {
        await sftpDownload(sessionId, remotePath, localPath, overwrite, (p) =>
          setTransfer({ ...base, ...p }),
        );
        // Refreshes a local Files folder showing it and reloads an open local
        // editor on that file.
        dispatchFsRefreshForFile(localPath);
        toast(`Downloaded ${name} to ${localPath}`, { variant: "success" });
      } catch (e) {
        console.error("ssh download failed:", e);
        toast(`Download failed: ${describeError(e)}`, { variant: "error" });
      } finally {
        setTransfer(null);
      }
    },
    [sessionId],
  );

  return { transfer, uploadFiles, downloadFile };
}
