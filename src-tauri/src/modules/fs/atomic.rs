//! Crash-safe file writes: stage into a sibling temp file, fsync, then
//! rename over the target.
//!
//! A torn write (crash / power loss between `open` and the last byte) would
//! otherwise leave a half-written file. Several callers persist data whose
//! readers fall back to defaults on a parse error, so a torn write would
//! silently wipe user state - worth the extra fsync to avoid.
//!
//! The temp file is created in the SAME directory as the target so the final
//! `rename` is same-filesystem (atomic) and never a cross-device copy. On any
//! failure the temp is removed best-effort so a crash mid-write does not leave
//! a stray `.tmp` behind.
//!
//! The temp name is DERIVED FROM THE TARGET and therefore shared by every write
//! to that target, so writes to one path are serialized here - see
//! [`target_lock`]. Two concurrent writers staging into one temp file is not a
//! torn file, it is a failed write: whichever `rename` lands first consumes the
//! temp and the next one fails with `ENOENT` / `ERROR_FILE_NOT_FOUND`. That is
//! what made SSH host delete report `os error 2` and never complete, while RDP
//! host delete - one account, so one write - always worked.
//!
//! Callers that need a specific final byte stream (DPAPI-encrypted, 0600
//! perms, pretty-printed JSON) compose AROUND this: produce the bytes, then
//! call [`atomic_write`]. This helper owns only the staging/rename mechanics,
//! never the encoding.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

/// Atomically replace `path` with `bytes`.
///
/// Stages into `<dir>/.<filename>.tervia.tmp`, fsyncs it, then renames over
/// `path`. Removes the temp on any failure. Returns the underlying
/// [`io::Error`] so callers can map it to their own error type.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_staged(path, bytes, |tmp| fs::File::create(tmp))
}

/// Unix-only [`atomic_write`] variant that creates the staging temp with the
/// given permission `mode` BEFORE any bytes are written, so the contents are
/// never briefly world-readable. Used for the Linux secrets file (mode
/// `0o600`) where the plaintext must never touch disk with loose perms.
#[cfg(unix)]
pub fn atomic_write_mode(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    write_staged(path, bytes, move |tmp| {
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(tmp)
    })
}

/// One lock per TARGET PATH, held across the whole stage-fsync-rename sequence.
///
/// Two concurrent writes to the same target share one staging temp, because the
/// temp name is derived from the target. The first `rename` consumes it and the
/// second fails with `os error 2` - a write that reports failure while the file
/// on disk is fine, which is far more confusing than a torn file. Serializing
/// per target makes the shared name safe; a unique name per write would too, but
/// it would leave one orphan temp per crash instead of one per target, and the
/// secrets file's temp is plaintext at mode 0600 on Linux. A rotated secret
/// surviving indefinitely in a file nothing ever overwrites is the worse trade.
///
/// PER PATH rather than one global lock: `fs_write_file` saves editor buffers
/// through here and a large save must not hold up a store commit.
///
/// Only in-process concurrency is covered, which is all there is: `lib.rs`
/// registers `tauri-plugin-single-instance`, so a second launch forwards its
/// argv and exits rather than becoming a second writer.
///
/// Four call sites reach this, and three of them could already race:
/// `secrets.rs`'s `write_store` (the reported failure - `deleteHost` fans out one
/// delete per account); `fs/file.rs`'s `fs_write_file` and `fs/grep.rs`'s two
/// replace commands (Tauri commands, so two invocations naming one file overlap);
/// and `pty/shell_init.rs`'s `write_if_changed`, whose own comment is about two
/// shells starting at once. `secrets.rs` also serializes one level up, because
/// its cache and its file have to move together.
static TARGET_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The lock for one target, creating it on first use.
fn target_lock(path: &Path) -> Arc<Mutex<()>> {
    // Poison carries no meaning for either lock: nothing is guarded except the
    // ORDER of the writes, so there is no invariant a panicking writer could have
    // left half-applied. Recovering beats making every later write to that path
    // fail forever.
    let mut map = TARGET_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let lock = Arc::clone(map.entry(path.to_path_buf()).or_default());
    // Forget the locks nobody holds. An `Arc` the map alone owns has no waiter, so
    // a later writer building a fresh one is equivalent - and this keeps the map
    // bounded by the writes IN FLIGHT rather than by every path ever written,
    // which for the editor's save path is every file touched in a session. Ours is
    // already cloned, so it survives.
    map.retain(|_, held| Arc::strong_count(held) > 1);
    lock
}

/// Stage `bytes` into `<dir>/.<filename>.tervia.tmp` (opened via `open_tmp`),
/// fsync, then rename over `path`. Removes the temp on any failure.
///
/// Serialized per target by [`TARGET_LOCKS`], because that temp name is shared by
/// every write to this target.
fn write_staged<F>(path: &Path, bytes: &[u8], open_tmp: F) -> io::Result<()>
where
    F: FnOnce(&Path) -> io::Result<fs::File>,
{
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;

    // Temp lives beside the target so `rename` stays on one filesystem.
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(".tervia.tmp");
    let tmp = parent.join(tmp_name);

    // Taken BEFORE the temp is opened and held past the rename, so no other
    // writer to this target can be between its own open and its own rename.
    let ordered = target_lock(path);
    let _held = ordered
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Wrap the body so a single `?` short-circuit funnels through the cleanup
    // below; we must not leave the staged temp behind on failure.
    let result = (|| -> io::Result<()> {
        let mut f = open_tmp(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // Drop the handle before renaming: Windows refuses to rename a file
        // with an open handle in some configurations.
        drop(f);
        fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// The concurrency contract, against the real filesystem.
///
/// The reported failure was not a torn file: it was `os error 2` from
/// `fs::rename`, because the staging temp is named after the target and a
/// concurrent writer had already renamed it away. Nothing in a diff shows that,
/// and a single-threaded test cannot reach it - the loop below is the whole point.
#[cfg(test)]
mod tests {
    use super::atomic_write;
    use std::sync::{Arc, Barrier};

    /// A private directory under the system temp dir, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "tervia-atomic-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id(),
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // The reproduction. Three writers, one target - `deleteHost`'s fan-out is one
    // `secrets_delete` per account, three for an SSH host and one for RDP, which is
    // exactly why SSH host delete failed and RDP host delete did not.
    #[test]
    fn concurrent_writes_to_one_target_all_succeed() {
        let dir = TempDir::new("concurrent");
        let target = dir.0.join("secrets.json");
        // Every writer starts inside the staging window together, so the second
        // `rename` has a temp to lose.
        let gate = Arc::new(Barrier::new(3));

        let errors: Vec<String> = (0..3)
            .map(|i| {
                let target = target.clone();
                let gate = Arc::clone(&gate);
                std::thread::spawn(move || {
                    gate.wait();
                    atomic_write(&target, format!("writer-{i}").as_bytes())
                        .err()
                        .map(|e| e.to_string())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|h| h.join().expect("thread"))
            .collect();

        // `os error 2` here is the bug, not a flake: one writer's temp was renamed
        // away by another before it got there.
        assert!(errors.is_empty(), "a concurrent write failed: {errors:?}");
        // And the survivor is one whole writer's bytes, not a splice of several.
        let got = std::fs::read_to_string(&target).expect("read target");
        assert!(
            ["writer-0", "writer-1", "writer-2"].contains(&got.as_str()),
            "the target holds neither writer's bytes: {got:?}",
        );
    }

    #[test]
    fn the_staging_temp_is_gone_once_the_write_lands() {
        let dir = TempDir::new("nostray");
        let target = dir.0.join("hosts.json");
        atomic_write(&target, b"{}").expect("write");
        assert_eq!(std::fs::read(&target).expect("read"), b"{}");
        // Named after the target, so a leftover would be picked up - and shared -
        // by the next write to the same path.
        assert!(!dir.0.join(".hosts.json.tervia.tmp").exists());
    }

    /// Wait, with a deadline, for `expected` threads to reach this point.
    ///
    /// A `Barrier` would be the obvious tool and is the wrong one: the case below
    /// exists to catch ONE GLOBAL LOCK, under which the second thread never
    /// arrives, and a barrier would then hang the test rather than fail it. That
    /// reads as a CI timeout instead of a finding, so the timeout is a `false` here.
    fn rendezvous(arrived: &std::sync::atomic::AtomicUsize, expected: usize) -> bool {
        use std::sync::atomic::Ordering;
        arrived.fetch_add(1, Ordering::SeqCst);
        let started = std::time::Instant::now();
        while arrived.load(Ordering::SeqCst) < expected {
            if started.elapsed() > std::time::Duration::from_secs(3) {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        true
    }

    #[test]
    fn writes_to_different_targets_do_not_block_on_each_other() {
        // Per TARGET rather than one global lock: `fs_write_file` saves editor
        // buffers through here, and a large save must not hold up a store commit.
        //
        // Driven through `write_staged` rather than `atomic_write` so the
        // rendezvous happens INSIDE the locked region - two `atomic_write` calls
        // meeting between them would prove nothing, because a global lock would
        // satisfy that just as well.
        let dir = TempDir::new("independent");
        let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handles: Vec<_> = ["a.json", "b.json"]
            .into_iter()
            .map(|name| {
                let path = dir.0.join(name);
                let arrived = Arc::clone(&arrived);
                std::thread::spawn(move || {
                    let mut met = false;
                    let wrote = super::write_staged(&path, b"body", |tmp| {
                        met = rendezvous(&arrived, 2);
                        std::fs::File::create(tmp)
                    });
                    (met, wrote.is_ok())
                })
            })
            .collect();
        for h in handles {
            let (met, wrote) = h.join().expect("thread");
            assert!(
                met,
                "the other target's write could not enter: one lock for all"
            );
            assert!(wrote, "the write itself failed");
        }
        for name in ["a.json", "b.json"] {
            assert_eq!(std::fs::read(dir.0.join(name)).expect("read"), b"body");
        }
    }
}
