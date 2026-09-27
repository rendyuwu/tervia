//! SFTP file operations over an existing SSH session.
//!
//! Reuses the russh `Handle` held by `SshSession` to open a fresh `sftp`
//! subsystem channel on demand and forwards browse/read/write commands
//! through it. The remote SSH user owns the channel, so every operation is
//! constrained by their unix permissions on the remote box. A
//! `permission denied` response bubbles up as a structured error the
//! frontend renders in-tree without crashing the panel.

use std::sync::Arc;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileType, OpenFlags, StatusCode};
use serde::Serialize;
use tauri::ipc::Channel;

use super::session::SshSession;
use super::{ssh_runtime, SshState};

/// Directory entry pushed to the frontend. Shape matches the local
/// `fs::DirEntry` so the frontend tree can reuse its renderer without
/// branching on local vs remote.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    /// `"file"`, `"dir"`, or `"symlink"`. Everything else (block, char,
    /// fifo, unknown) collapses to `"file"` so the tree still renders.
    pub kind: String,
    pub size: u64,
    /// Unix seconds; `0` when the server did not report mtime.
    pub mtime: u64,
    /// `"rwxr-xr-x"` style permission summary, or empty when the server
    /// did not report a mode. Surfaced as a tooltip so users see why a
    /// directory is read-only before they try to write.
    pub permissions: String,
}

/// Look up an SSH session by id and clone its `Arc<SshSession>`. Every
/// command starts with this prelude.
async fn get_session(
    state: &tauri::State<'_, SshState>,
    id: u32,
) -> Result<Arc<SshSession>, String> {
    state
        .sessions
        .read()
        .await
        .get(&id)
        .cloned()
        .ok_or_else(|| {
            log::warn!("ssh_sftp: unknown session id={id}");
            "no ssh session".to_string()
        })
}

/// Shared SFTP command scaffolding: resolve the session, open the sftp
/// subsystem, and run `f` on the daemon runtime, mapping the join error.
async fn on_sftp<F, Fut, T>(state: &tauri::State<'_, SshState>, id: u32, f: F) -> Result<T, String>
where
    F: FnOnce(Arc<SftpSession>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + Send,
    T: Send + 'static,
{
    let session = get_session(state, id).await?;
    ssh_runtime()
        .spawn(async move {
            let sftp = session.ensure_sftp().await?;
            f(sftp).await
        })
        .await
        .map_err(|e| format!("ssh task join failed: {e}"))?
}

/// Translate an SFTP error to a short user-facing string while preserving
/// the permission/no-such-file distinction so the explorer renders the
/// right empty state. Other errors collapse to a generic message with the
/// underlying display.
fn humanize(err: SftpError) -> String {
    match &err {
        SftpError::Status(s) => match s.status_code {
            StatusCode::PermissionDenied => "permission denied".to_string(),
            StatusCode::NoSuchFile => "no such file or directory".to_string(),
            StatusCode::OpUnsupported => "operation not supported by remote".to_string(),
            _ => {
                if s.error_message.is_empty() {
                    format!("sftp: {}", s.status_code)
                } else {
                    format!("sftp: {}", s.error_message)
                }
            }
        },
        _ => format!("sftp: {err}"),
    }
}

/// Byte-level transfer progress streamed to the frontend so the SSH explorer
/// shows a moving percentage for an upload or a download.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub written: u64,
    pub total: u64,
}

fn map_file_type(ft: FileType) -> &'static str {
    if ft.is_dir() {
        "dir"
    } else if ft.is_symlink() {
        "symlink"
    } else {
        "file"
    }
}

#[tauri::command]
pub async fn ssh_sftp_home(state: tauri::State<'_, SshState>, id: u32) -> Result<String, String> {
    on_sftp(&state, id, |sftp| async move {
        sftp.canonicalize(".").await.map_err(humanize)
    })
    .await
}

#[tauri::command]
pub async fn ssh_sftp_read_dir(
    state: tauri::State<'_, SshState>,
    id: u32,
    path: String,
    include_hidden: bool,
) -> Result<Vec<SftpEntry>, String> {
    on_sftp(&state, id, move |sftp| async move {
        let read = sftp.read_dir(path.clone()).await.map_err(humanize)?;
        let mut entries: Vec<SftpEntry> = read
            .filter(|e| include_hidden || !e.file_name().starts_with('.'))
            .map(|e| {
                let metadata = e.metadata();
                let ft = metadata.file_type();
                SftpEntry {
                    name: e.file_name(),
                    kind: map_file_type(ft).to_string(),
                    size: metadata.len(),
                    mtime: metadata.mtime.map(u64::from).unwrap_or(0),
                    permissions: format_permissions(&metadata),
                }
            })
            .collect();
        // Match fs::tree: directories first, then files, both alphabetical
        // case-insensitive. Stable across sessions and matches the local
        // explorer.
        entries.sort_by(|a, b| {
            let ad = a.kind == "dir";
            let bd = b.kind == "dir";
            if ad != bd {
                return bd.cmp(&ad); // dirs first
            }
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        });
        Ok(entries)
    })
    .await
}

#[tauri::command]
pub async fn ssh_sftp_read_file(
    state: tauri::State<'_, SshState>,
    id: u32,
    path: String,
) -> Result<String, String> {
    on_sftp(&state, id, move |sftp| async move {
        // Cap the read so a huge (or maliciously oversized) remote file can't
        // OOM the app by being slurped whole into memory + an IPC string.
        // Mirrors the local fs_read_file size guard.
        const MAX_SFTP_READ_BYTES: u64 = 16 * 1024 * 1024;
        if let Ok(meta) = sftp.metadata(path.clone()).await {
            if meta.len() > MAX_SFTP_READ_BYTES {
                return Err(format!(
                    "file too large to open: {} bytes (cap {} bytes)",
                    meta.len(),
                    MAX_SFTP_READ_BYTES
                ));
            }
        }
        let bytes = sftp.read(path).await.map_err(humanize)?;
        // Mirror fs::file::fs_read_file: return UTF-8 text. Binary files
        // explode any editor pane anyway; rejecting up front with a clear
        // message beats handing junk to CodeMirror.
        String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8".to_string())
    })
    .await
}

#[tauri::command]
pub async fn ssh_sftp_write_file(
    state: tauri::State<'_, SshState>,
    id: u32,
    path: String,
    contents: String,
) -> Result<(), String> {
    on_sftp(&state, id, move |sftp| async move {
        // CREATE | TRUNCATE | WRITE matches local fs_write_file's "rewrite
        // in place" contract. The file is replaced atomically from the
        // editor's view even when the server lacks atomic rename-into-place.
        let mut file = sftp
            .open_with_flags(
                path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .map_err(humanize)?;
        use tokio::io::AsyncWriteExt;
        file.write_all(contents.as_bytes())
            .await
            .map_err(|e| format!("sftp write: {e}"))?;
        file.shutdown()
            .await
            .map_err(|e| format!("sftp close: {e}"))?;
        Ok(())
    })
    .await
}

/// Upload a local file to the remote over SFTP. Reads `local_path` off the
/// async runtime (a big file must not block it) and streams the bytes into
/// `remote_path`. `overwrite: true` replaces an existing file in place (OS
/// drop, paste); `overwrite: false` refuses one (a drag from the Files tree,
/// easy to drop in the wrong place). Directories are rejected up front -
/// recursive upload is a separate feature. The remote kernel enforces write
/// permission on the target dir; a denial surfaces as `permission denied`.
/// `on_progress` emits `{written, total}` as each chunk lands so the explorer
/// can render a percentage instead of jumping 0% -> 100%.
#[tauri::command]
pub async fn ssh_sftp_upload(
    state: tauri::State<'_, SshState>,
    id: u32,
    local_path: String,
    remote_path: String,
    overwrite: bool,
    on_progress: Channel<TransferProgress>,
) -> Result<(), String> {
    // Cap the whole-file read so a huge drop can't OOM the app. Matches the
    // read-file guard's intent; uploads get a larger ceiling.
    const MAX_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;
    let read_path = local_path.clone();
    let bytes = tokio::task::spawn_blocking(move || {
        let meta = std::fs::metadata(&read_path).map_err(|e| format!("read local file: {e}"))?;
        if meta.is_dir() {
            return Err("cannot upload a folder (files only)".to_string());
        }
        if meta.len() > MAX_UPLOAD_BYTES {
            return Err(format!(
                "file too large to upload: {} bytes (cap {} bytes)",
                meta.len(),
                MAX_UPLOAD_BYTES
            ));
        }
        std::fs::read(&read_path).map_err(|e| format!("read local file: {e}"))
    })
    .await
    .map_err(|e| format!("read task join failed: {e}"))??;

    on_sftp(&state, id, move |sftp| async move {
        ssh_sftp_upload_inner(&sftp, &bytes, remote_path, overwrite, &on_progress).await
    })
    .await
}

/// Write `bytes` to `remote_path` for `ssh_sftp_upload`, reporting
/// `{written, total}` per chunk. `overwrite: false` refuses an existing path,
/// a symlink included: the LSTAT gives a clear "already exists" in place of
/// whatever status the server returns (as in `ssh_sftp_rename_inner`), and
/// `EXCLUDE` refuses atomically a file created in between.
pub(super) async fn ssh_sftp_upload_inner(
    sftp: &SftpSession,
    bytes: &[u8],
    remote_path: String,
    overwrite: bool,
    on_progress: &Channel<TransferProgress>,
) -> Result<(), String> {
    let flags = if overwrite {
        OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE
    } else {
        if unless_gone(sftp.symlink_metadata(remote_path.clone()).await)
            .map_err(humanize)?
            .is_some()
        {
            return Err(format!("{remote_path} already exists"));
        }
        OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE
    };
    let total = bytes.len() as u64;
    let mut file = sftp
        .open_with_flags(remote_path, flags)
        .await
        .map_err(humanize)?;
    use tokio::io::AsyncWriteExt;
    // Chunk the write so a large file reports a moving percentage. 256 KiB
    // keeps the event count bounded (<=1024 for the 256 MiB cap) while
    // still feeling live. Send an initial 0% so the bar appears at once.
    const CHUNK: usize = 256 * 1024;
    let _ = on_progress.send(TransferProgress { written: 0, total });
    let mut written: u64 = 0;
    for chunk in bytes.chunks(CHUNK) {
        file.write_all(chunk)
            .await
            .map_err(|e| format!("sftp write: {e}"))?;
        written += chunk.len() as u64;
        let _ = on_progress.send(TransferProgress { written, total });
    }
    file.shutdown()
        .await
        .map_err(|e| format!("sftp close: {e}"))?;
    Ok(())
}

/// Read a whole remote file into memory for `ssh_sftp_download`, reporting
/// `{written, total}` as each chunk arrives. Regular files only; a folder or
/// a device (which stats at 0 bytes and never ends) is refused.
pub(super) async fn ssh_sftp_download_inner(
    sftp: &SftpSession,
    remote_path: String,
    on_progress: &Channel<TransferProgress>,
) -> Result<Vec<u8>, String> {
    // The whole file is buffered before the local write; this bounds that
    // buffer, mirroring the upload cap.
    const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
    let meta = sftp.metadata(remote_path.clone()).await.map_err(humanize)?;
    match meta.file_type() {
        FileType::File => {}
        FileType::Dir => return Err("cannot download a folder (files only)".to_string()),
        // A server that omits the mode, or sends one with no file-type bits,
        // reports every entry as `Other`; let the read decide rather than
        // refuse every download there.
        _ if meta.permissions.is_none_or(|m| m & 0o170000 == 0) => {}
        _ => return Err("cannot download a device or special file (files only)".to_string()),
    }
    let total = meta.len();
    if total > MAX_DOWNLOAD_BYTES {
        return Err(format!(
            "file too large to download: {total} bytes (cap {MAX_DOWNLOAD_BYTES} bytes)"
        ));
    }
    let mut file = sftp.open(remote_path).await.map_err(humanize)?;
    use tokio::io::AsyncReadExt;
    const CHUNK: u64 = 256 * 1024;
    let mut bytes = Vec::with_capacity(total as usize);
    let _ = on_progress.send(TransferProgress { written: 0, total });
    // ponytail: russh-sftp's AsyncRead issues one READ per round trip; pipeline
    // offset reads if large downloads over high-latency links are too slow.
    loop {
        let n = (&mut file)
            .take(CHUNK)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| format!("sftp read: {e}"))?;
        if n == 0 {
            break;
        }
        if bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
            return Err(format!(
                "file grew past the download cap ({MAX_DOWNLOAD_BYTES} bytes)"
            ));
        }
        let _ = on_progress.send(TransferProgress {
            written: bytes.len() as u64,
            total,
        });
    }
    Ok(bytes)
}

/// Write a finished download to `path`. `overwrite: true` stages and renames
/// over the target, so a failed write leaves the original intact.
/// `overwrite: false` refuses an existing file atomically (`create_new`), and
/// a failed write removes the partial file: it would look like a finished
/// download.
fn write_local_file(path: &str, bytes: &[u8], overwrite: bool) -> Result<(), String> {
    use std::io::Write;
    if overwrite {
        return crate::modules::fs::atomic::atomic_write(std::path::Path::new(path), bytes)
            .map_err(|e| format!("write local file: {e}"));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{path} already exists")
            } else {
                format!("write local file: {e}")
            }
        })?;
    if let Err(e) = file.write_all(bytes) {
        // Close first: Windows cannot delete an open file.
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("write local file: {e}"));
    }
    Ok(())
}

/// Download a remote file to `local_path`, the mirror of `ssh_sftp_upload`:
/// bytes stay in Rust, so binary files arrive intact. The remote read
/// finishes before the local file is opened, so a failed read leaves an
/// existing local file untouched. Files only. `overwrite: false` is checked
/// up front and again atomically by `create_new`; the save-dialog path passes
/// `true` because the OS dialog already confirmed the replace.
#[tauri::command]
pub async fn ssh_sftp_download(
    state: tauri::State<'_, SshState>,
    id: u32,
    remote_path: String,
    local_path: String,
    overwrite: bool,
    on_progress: Channel<TransferProgress>,
) -> Result<(), String> {
    if !overwrite {
        let check = local_path.clone();
        let exists = tokio::task::spawn_blocking(move || std::fs::symlink_metadata(&check).is_ok())
            .await
            .map_err(|e| format!("local check join failed: {e}"))?;
        if exists {
            return Err(format!("{local_path} already exists"));
        }
    }
    let bytes = on_sftp(&state, id, move |sftp| async move {
        ssh_sftp_download_inner(&sftp, remote_path, &on_progress).await
    })
    .await?;
    tokio::task::spawn_blocking(move || write_local_file(&local_path, &bytes, overwrite))
        .await
        .map_err(|e| format!("write task join failed: {e}"))?
}

#[tauri::command]
pub async fn ssh_sftp_create_file(
    state: tauri::State<'_, SshState>,
    id: u32,
    path: String,
) -> Result<(), String> {
    on_sftp(&state, id, move |sftp| async move {
        // EXCL so we do not silently clobber a file the user did not see
        // (e.g. created moments ago by another process).
        let mut file = sftp
            .open_with_flags(
                path,
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            )
            .await
            .map_err(humanize)?;
        use tokio::io::AsyncWriteExt;
        file.shutdown()
            .await
            .map_err(|e| format!("sftp close: {e}"))?;
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn ssh_sftp_create_dir(
    state: tauri::State<'_, SshState>,
    id: u32,
    path: String,
) -> Result<(), String> {
    on_sftp(&state, id, move |sftp| async move {
        sftp.create_dir(path).await.map_err(humanize)
    })
    .await
}

#[tauri::command]
pub async fn ssh_sftp_rename(
    state: tauri::State<'_, SshState>,
    id: u32,
    from: String,
    to: String,
) -> Result<(), String> {
    on_sftp(&state, id, move |sftp| async move {
        ssh_sftp_rename_inner(&sftp, from, to).await
    })
    .await
}

/// Rename or move `from` to `to`, refusing an existing `to`. The LSTAT gives
/// a clear "already exists" in place of whatever status the server returns,
/// and refuses on a server whose RENAME would overwrite. A case-only rename
/// (same folder, name differing only by case) skips the check: on a
/// case-insensitive remote (Windows OpenSSH) the LSTAT finds the source itself.
pub(super) async fn ssh_sftp_rename_inner(
    sftp: &SftpSession,
    from: String,
    to: String,
) -> Result<(), String> {
    let case_only = match (from.rsplit_once('/'), to.rsplit_once('/')) {
        (Some((from_dir, from_name)), Some((to_dir, to_name))) => {
            from_dir == to_dir && from_name.to_lowercase() == to_name.to_lowercase()
        }
        _ => false,
    };
    if !case_only
        && unless_gone(sftp.symlink_metadata(to.clone()).await)
            .map_err(humanize)?
            .is_some()
    {
        return Err(format!("{to} already exists"));
    }
    sftp.rename(from, to).await.map_err(humanize)
}

/// Requests the recursive delete keeps in flight. Enough to hide the round
/// trip on a slow link. Bounded because the server answers one at a time and
/// russh-sftp's 10 s response timeout starts when a request is queued.
const DELETE_IN_FLIGHT: usize = 64;

/// Delete `path` over SFTP; a directory goes with everything under it.
/// SFTP `RMDIR` only removes an EMPTY directory, so the tree is walked first,
/// one depth level at a time: every directory of the level is listed, then
/// every listed non-directory is removed and every subdirectory becomes the
/// next level. Each step keeps up to `DELETE_IN_FLIGHT` requests in flight, so
/// a big tree costs about one round trip per `DELETE_IN_FLIGHT` entries, not
/// one per entry. Levels are then removed deepest first, so each child goes
/// before its parent. Symlinks are removed as links, their targets left alone:
/// the top-level check is LSTAT, and an entry READDIR reports as a directory
/// is LSTATed again before the walk goes into it, because READDIR attributes
/// are lstat results on OpenSSH but may be followed-stat results elsewhere. A
/// directory swapped for a link between that LSTAT and the READDIR is still
/// followed; SFTP has no `openat`-style call to close that race. A child that
/// vanishes mid-walk (a second Delete, another client) counts as removed, as
/// in `std::fs::remove_dir_all`. Any other failure stops the walk and leaves
/// whatever was not removed yet; requests already in flight may still land.
pub(super) async fn ssh_sftp_delete_inner(
    sftp: &SftpSession,
    path: String,
) -> Result<(), SftpError> {
    if !sftp
        .symlink_metadata(path.clone())
        .await?
        .file_type()
        .is_dir()
    {
        return sftp.remove_file(path).await;
    }
    // ponytail: no progress or cancel. Stream counts over a `Channel` like
    // `ssh_sftp_upload` if huge trees make the wait opaque.
    let mut levels = vec![vec![path]];
    loop {
        // Every listing runs to the end before an error is returned: dropping
        // a `read_dir` between its OPENDIR and CLOSE leaks a server handle.
        let listings: Vec<_> = stream::iter(levels[levels.len() - 1].clone())
            .map(|dir| async move { unless_gone(sftp.read_dir(dir).await) })
            .buffer_unordered(DELETE_IN_FLIGHT)
            .collect()
            .await;
        let listings = listings.into_iter().collect::<Result<Vec<_>, _>>()?;
        let subdirs: Vec<_> = stream::iter(listings.into_iter().flatten().flatten())
            .map(|entry| async move {
                let child = entry.path();
                if entry.file_type().is_dir() {
                    match unless_gone(sftp.symlink_metadata(child.clone()).await)? {
                        Some(meta) if meta.file_type().is_dir() => return Ok(Some(child)),
                        Some(_) => {}
                        None => return Ok(None),
                    }
                }
                unless_gone(sftp.remove_file(child).await)?;
                Ok::<_, SftpError>(None)
            })
            .buffer_unordered(DELETE_IN_FLIGHT)
            .try_collect()
            .await?;
        let subdirs: Vec<String> = subdirs.into_iter().flatten().collect();
        if subdirs.is_empty() {
            break;
        }
        levels.push(subdirs);
    }
    for level in levels.into_iter().rev() {
        stream::iter(level)
            .map(|dir| async move { unless_gone(sftp.remove_dir(dir).await).map(drop) })
            .buffer_unordered(DELETE_IN_FLIGHT)
            .try_collect::<()>()
            .await?;
    }
    Ok(())
}

/// `Ok(None)` when the server says the path no longer exists.
fn unless_gone<T>(result: Result<T, SftpError>) -> Result<Option<T>, SftpError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(SftpError::Status(s)) if s.status_code == StatusCode::NoSuchFile => Ok(None),
        Err(e) => Err(e),
    }
}

#[tauri::command]
pub async fn ssh_sftp_delete(
    state: tauri::State<'_, SshState>,
    id: u32,
    path: String,
) -> Result<(), String> {
    on_sftp(&state, id, move |sftp| async move {
        ssh_sftp_delete_inner(&sftp, path).await.map_err(humanize)
    })
    .await
}

/// Render `rwxr-xr-x` permissions from the SFTP metadata's mode bits.
/// Empty when the server omitted permissions (some non-OpenSSH servers do).
fn format_permissions(metadata: &russh_sftp::protocol::FileAttributes) -> String {
    if metadata.permissions.is_none() {
        return String::new();
    }
    metadata.permissions().to_string()
}

/// Open the SFTP subsystem if not already open. Exposed via SshSession so
/// the mod.rs commands stay decoupled from the SSH handshake details.
pub(super) async fn open_sftp_on_handle(session: &SshSession) -> Result<Arc<SftpSession>, String> {
    let handle_guard = session.handle.lock().await;
    let handle = handle_guard
        .as_ref()
        .ok_or_else(|| "ssh session is closed".to_string())?;
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("ssh: open sftp channel failed: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("ssh: request sftp subsystem failed: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("ssh: sftp handshake failed: {e}"))?;
    Ok(Arc::new(sftp))
}

#[cfg(test)]
mod tests {
    use super::write_local_file;

    #[test]
    fn write_local_file_refuses_to_replace_unless_asked() {
        let dir = std::env::temp_dir().join(format!("tervia-sftp-dl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.bin");
        let path = path.to_str().unwrap();

        write_local_file(path, b"one", false).unwrap();
        let err = write_local_file(path, b"two", false).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(std::fs::read(path).unwrap(), b"one");

        write_local_file(path, b"three", true).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"three");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
