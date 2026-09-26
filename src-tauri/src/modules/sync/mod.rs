//! Cross-device sync: the wire format, the merge, the crypto that wraps both,
//! and the port to whatever storage the user chose.
//!
//! WHAT IS NOT HERE, and is not an oversight. No store write and no keychain
//! write: `KNOWN-LIMITS.md` records that every integrity rule lives in the
//! store layer and that a pull has to go through it, and the stores are
//! TypeScript - so this module decides and `src/modules/sync/` applies. No
//! settings surface either: `sync_configure` in
//! `src-tauri/src/modules/sync/engine.rs` is handed a passphrase and a provider
//! configuration, and never goes looking for them. `SyncState` there is empty
//! on every launch and nothing persists it, so every other command answers "no
//! configuration" until a caller has opened one.
//!
//! `engine.rs` is where an object key is composed, which `crypto.rs` and
//! `provider.rs` both decline for their own reasons.
//!
//! `src-tauri/src/modules/sync/model.rs` and
//! `src-tauri/src/modules/sync/crypto.rs` are pure, and so is every decision in
//! `src-tauri/src/modules/sync/providers/sigv4.rs`. A provider is the one thing
//! here that opens a socket, and even there the split is deliberate: what to
//! send and what a response means are plain functions, and the async bodies
//! only call them.
//!
//! The device id below is this FILE's only I/O, and it lives here because this
//! file is the impure layer of the module proper.

pub mod crypto;
pub mod engine;
pub mod model;
pub mod provider;
pub mod providers;

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;

use uuid::Uuid;

/// Name of the file holding this installation's device id, inside the app data
/// directory.
const DEVICE_ID_FILE: &str = "sync-device-id";

/// This installation's device id, creating it on first call.
///
/// Stamped on every envelope as provenance. Never transmitted outside a sealed
/// envelope, and never used as an ordering input - see `ordering_key` in
/// `src-tauri/src/modules/sync/model.rs` for why the merge must not read it.
///
/// Split from [`device_id`] so the logic and the race are testable without a
/// real app data directory.
///
/// CREATE FIRST, READ SECOND, with no read fast path. That looks backwards and
/// is the point: a read-first path returns before `create_new` is ever reached
/// whenever the file exists, so the `AlreadyExists` arm - the branch most
/// likely to be written wrong, since returning the locally generated uuid
/// instead of re-reading the winner's produces TWO device ids under a real
/// race - would be unreachable from any single-threaded test. Going for
/// `create_new` first makes that arm the ordinary path for an existing file,
/// so one plain test enters it deterministically. The cost is one failed
/// syscall per call, and there is one branch less.
///
/// ONE BOUNDED RECOVERY. A process that dies between `create_new` and the
/// write leaves an EMPTY file, which would otherwise be a permanent stuck
/// state with an opaque symptom. So a file that does not hold a parseable uuid
/// is removed and the whole thing retried exactly once. Two processes both
/// finding the empty file both remove and both create; one wins and the other
/// reads the winner, so the recovery converges the same way the normal path
/// does.
pub fn device_id_at(dir: &Path) -> Result<String, String> {
    match create_or_read(dir)? {
        Some(id) => Ok(id),
        None => create_or_read(dir)?.ok_or_else(|| {
            "sync: the device id file could not be initialized after one retry".to_string()
        }),
    }
}

/// `Ok(None)` means "the file was unusable and has been cleared, try again".
fn create_or_read(dir: &Path) -> Result<Option<String>, String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("sync: could not create the app data directory: {e}"))?;
    let path = dir.join(DEVICE_ID_FILE);

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            let id = Uuid::new_v4().to_string();
            file.write_all(id.as_bytes())
                .map_err(|e| format!("sync: could not write the device id: {e}"))?;
            Ok(Some(id))
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            // Whatever is on disk WINS, including over the id this call would
            // have generated. That is the entire content of the race arm.
            //
            // A read that FAILS is propagated rather than treated as unusable
            // content. The difference is destructive: an EACCES or EIO on a
            // perfectly good file would otherwise fall through to the clearing
            // below and DELETE it over a transient fault. `NotFound` is the
            // one exception, because it means another process cleared the file
            // between the failed create and this read, which is a retry.
            let found = match fs::read_to_string(&path) {
                Ok(found) => found,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(format!("sync: could not read the device id: {e}")),
            };
            let found = found.trim();
            if Uuid::parse_str(found).is_ok() {
                return Ok(Some(found.to_string()));
            }
            // Unusable. Clearing it is what makes the crash state recoverable;
            // another process having cleared it first is the same outcome, not
            // a failure.
            match fs::remove_file(&path) {
                Ok(()) => Ok(None),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!(
                    "sync: could not clear an unusable device id file: {e}"
                )),
            }
        }
        Err(e) => Err(format!("sync: could not create the device id file: {e}")),
    }
}

/// [`device_id_at`] rooted at the real per-user app data directory.
///
/// The `None` arm of `app_data_dir` in `src-tauri/src/modules/ids.rs` - the OS
/// data directory cannot be resolved - becomes an error rather than a panic or
/// a silent default, because a default would have every such machine share one
/// device id.
///
/// No caching. A `OnceLock` belongs here the day a push path calls this per
/// record rather than per run.
pub fn device_id() -> Result<String, String> {
    let dir = crate::modules::ids::app_data_dir()
        .ok_or_else(|| "sync: the OS data directory could not be resolved".to_string())?;
    device_id_at(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory that does not exist yet, so every test also covers the
    /// `create_dir_all`. No `[dev-dependencies]` in this crate, hence
    /// `temp_dir` plus a uuid rather than a temp-directory crate.
    fn scratch() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tervia-sync-{}", Uuid::new_v4()))
    }

    #[test]
    fn a_fresh_directory_gets_a_new_id_that_is_actually_on_disk() {
        let dir = scratch();
        let id = device_id_at(&dir).unwrap();
        assert!(Uuid::parse_str(&id).is_ok(), "not a uuid: {id}");
        // The clause that catches the race arm's likely bug - returning the
        // locally generated uuid instead of what is on disk - without needing
        // a race to do it.
        assert_eq!(fs::read_to_string(dir.join(DEVICE_ID_FILE)).unwrap(), id);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_existing_id_is_returned_and_not_overwritten() {
        // Because there is no read-first path, this enters the AlreadyExists
        // arm deterministically.
        let dir = scratch();
        let first = device_id_at(&dir).unwrap();
        let second = device_id_at(&dir).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            fs::read_to_string(dir.join(DEVICE_ID_FILE)).unwrap(),
            first,
            "the second call rewrote the file"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_file_left_by_a_crash_recovers() {
        // What a process that died between `create_new` and the write leaves
        // behind. Without the recovery this is a permanent stuck state whose
        // only symptom is an empty device id on every envelope.
        let dir = scratch();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(DEVICE_ID_FILE), "").unwrap();

        let id = device_id_at(&dir).unwrap();
        assert!(Uuid::parse_str(&id).is_ok(), "not a uuid: {id}");
        assert_eq!(fs::read_to_string(dir.join(DEVICE_ID_FILE)).unwrap(), id);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn junk_in_the_file_recovers_the_same_way_and_does_not_loop() {
        let dir = scratch();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(DEVICE_ID_FILE), "not a uuid at all").unwrap();

        let id = device_id_at(&dir).unwrap();
        assert!(Uuid::parse_str(&id).is_ok(), "not a uuid: {id}");
        assert_eq!(fs::read_to_string(dir.join(DEVICE_ID_FILE)).unwrap(), id);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_recovery_is_one_retry_and_not_a_loop() {
        // Asserted on `create_or_read` directly, because the bound is not
        // visible from `device_id_at`'s return value: a loop and a single
        // retry both succeed here. What makes it bounded is that ONE call
        // clears the unusable file and reports `None` exactly once, and the
        // next call then takes the ordinary create path.
        let dir = scratch();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(DEVICE_ID_FILE), "not a uuid at all").unwrap();

        assert_eq!(create_or_read(&dir).unwrap(), None, "the first call clears");
        assert!(
            !dir.join(DEVICE_ID_FILE).exists(),
            "the unusable file was left behind"
        );
        let id = create_or_read(&dir)
            .unwrap()
            .expect("the second call creates");
        assert!(Uuid::parse_str(&id).is_ok(), "not a uuid: {id}");
        fs::remove_dir_all(&dir).ok();
    }
}
