//! The two round trips: reconcile what the remote holds against what this
//! device holds, and publish what the remote is missing.
//!
//! WHAT IS DELIBERATELY NOT HERE. No store write, no keychain write, no
//! settings surface. This layer decides, and the TypeScript side applies -
//! forced rather than chosen: `KNOWN-LIMITS.md` records that every integrity
//! rule lives in the store layer and a pull has to go through it, and the
//! stores are TypeScript. So a pull ends with a list of dispositions and an
//! etag map, and the caller is what turns those into records.
//!
//! NO ETAG CACHE. The map round-trips through the caller instead, which looks
//! like extra plumbing and is the whole safety property: a cache here would
//! advance the moment the pull returned, while the apply happens later in
//! TypeScript, so anything in between - a refusal, a contended write, the
//! window closing - would lose those landings permanently to the next pull's
//! etag skip.
//!
//! NO STATUS EITHER. The pending count and the quarantine list are returned,
//! never stored: the window that renders them is not the window that pulls.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::crypto::{
    new_keyfile, object_name, open_keyfile, open_record, seal_record, Keyfile, SealedRecord,
    SyncKeys,
};
use super::model::{content_differs, merge, strip_device_local, Envelope, WIRE_VERSION};
use super::provider::{build, ProviderError, SyncProvider};

/// How long a tombstone stays meaningful, in milliseconds.
///
/// MIRRORS `TOMBSTONE_TTL_MS` in `src/lib/tombstones.ts`, which is the side
/// that owns it: that file decides when a local tombstone stops being read, and
/// this one decides when a REMOTE tombstone object is removed. Two different
/// windows would leave objects on the remote that no device still reads, or -
/// worse, in the other direction - remove objects devices are still comparing
/// against. `scripts/sync-scheduler-verify.ts` reads both spellings and refuses
/// a drift.
const TOMBSTONE_TTL_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// What a command answers when no configuration has been opened.
///
/// Reachable on every launch, not only on a device that never configured:
/// [`SyncState`] starts empty and [`sync_configure`] is what fills it, so a
/// stored configuration is worth nothing until the caller has opened it again.
const NOT_CONFIGURED: &str = "sync: no sync configuration is open on this device";

const POISONED: &str = "sync: the sync state lock is poisoned";

// ---------------------------------------------------------------------------
// Object layout
// ---------------------------------------------------------------------------

// `<prefix>/v1/obj/<name>`, composed HERE rather than in a provider or in
// `crypto.rs`: a provider sees keys and bytes and has no idea what a record is,
// and `crypto.rs` says in its own header that it produces the `<name>` half and
// builds no path. The `v1` segment is the wire format's version expressed in
// the object namespace, so a format break lands beside the old objects instead
// of on top of them.

/// The user's prefix with the separators normalized away, so `"tervia"`,
/// `"/tervia"` and `"tervia/"` name one place rather than three.
fn root(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        "v1".into()
    } else {
        format!("{trimmed}/v1")
    }
}

/// What a LIST is asked for. The trailing slash is load bearing: without it a
/// sibling prefix sharing this one's first characters would be listed too.
fn object_prefix(prefix: &str) -> String {
    format!("{}/obj/", root(prefix))
}

fn object_key(prefix: &str, name: &str) -> String {
    format!("{}{name}", object_prefix(prefix))
}

/// Where the keyfile sits: beside the object namespace, not inside it.
///
/// OUTSIDE `obj/` deliberately. The pull lists that prefix and hands every key
/// it finds to `open_envelope`, and a keyfile is not a sealed record - it would
/// quarantine on every pull, forever, and the quarantine list is a user-facing
/// surface. Composed here for the reason [`object_key`] is: `crypto.rs` says in
/// its own header that it builds no path, and a provider has no idea what a
/// keyfile is.
fn keyfile_key(prefix: &str) -> String {
    format!("{}/keyfile", root(prefix))
}

/// The `<name>` half of a listed key, which is what the etag map is matched on.
fn name_of(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

/// Where one record sits in the etag map: `kind:id`.
///
/// NOT the object name, and that is the point. The caller stores this map and
/// hands it back on the next pull, and an object name is an HMAC under a key
/// the caller never sees. `kind:id` it can compute, so the exclusion the apply
/// path owes - drop every refused record from the map - is a plain lookup
/// rather than a round trip.
///
/// The `:` separates unambiguously for the reason `object_name` gives: no
/// `kind` in use contains one.
fn slot(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

// ---------------------------------------------------------------------------
// What a pull answers
// ---------------------------------------------------------------------------

/// What this pull decided about one record.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase", tag = "outcome")]
pub enum Outcome {
    /// Both sides had a copy.
    #[serde(rename_all = "camelCase")]
    Merged {
        envelope: Envelope,
        /// The store write. See `Merged` in
        /// `src-tauri/src/modules/sync/model.rs`.
        changed: bool,
        /// The keychain write, which the settings surface gates.
        secrets_changed: bool,
        /// Whether the remote object still has to be brought up to the winner.
        ///
        /// NOT `winner == Local`. The two vault exceptions mutate the winner
        /// after the side is decided, so a REMOTE win can differ from the
        /// remote copy - an `encrypted` answer backfilled out of the local
        /// loser is the live case, and reading the side would leave it on this
        /// device forever.
        republish: bool,
    },
    /// The remote had a copy and this device has neither a record nor a living
    /// tombstone for it.
    #[serde(rename_all = "camelCase")]
    RemoteOnly { envelope: Envelope },
    /// This device has a copy and the remote has no object for it at all.
    #[serde(rename_all = "camelCase")]
    LocalOnly {
        /// Older than the tombstone window, so the absence is most likely a
        /// delete whose tombstone has already expired everywhere.
        ///
        /// REPORTED, NEVER DELETED. Deleting a local record because an object
        /// is missing from a listing is data loss driven by an inference: a
        /// truncated page, an eventually-consistent endpoint and a
        /// provider-side accident all present as absence, and
        /// `ProviderError::Protocol` exists in this tree precisely because a
        /// listing can misbehave. The user resolves it with a manual push or a
        /// local delete.
        ///
        /// NEVER SET WHEN THE LISTING WAS EMPTY, and an empty listing is not
        /// the same claim as a short one. A page that lost some objects says
        /// nothing about the ones it did return; a prefix holding zero objects
        /// says the remote has never taken this inventory at all - a keyfile
        /// minted seconds ago, or a second provider being set up - and the
        /// stale rule there withholds the whole inventory from the remote it
        /// was pointed at, reporting nothing pending and no error. So the
        /// empty case is read as "never held" and everything publishes.
        ///
        /// THE KNOWN FALSE POSITIVE IS WEBDAV'S 404. `classify_list`
        /// (`providers/webdav.rs`) maps a missing collection to an empty
        /// listing, because a prefix whose collections have not been created is
        /// exactly the fresh-remote case. A mistyped prefix therefore presents
        /// as a fresh remote and takes a copy of the inventory. That is a
        /// write, never a delete, and the local records are untouched.
        stale: bool,
    },
}

/// One record's disposition, named the way the caller names records.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Reconciled {
    pub kind: String,
    pub id: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// A remote object this device could not read.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Quarantined {
    /// The object's own name - opaque hex, and necessarily so: an object that
    /// did not open is one whose kind and id are not known.
    pub name: String,
    pub reason: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PullReport {
    pub records: Vec<Reconciled>,
    /// `kind:id` to etag, for every remote object this pull read or skipped.
    ///
    /// An object that quarantined is NOT in here, so the next pull reads it
    /// again rather than recording a landing that never happened.
    pub etags: BTreeMap<String, String>,
    pub quarantined: Vec<Quarantined>,
    /// Remote tombstone objects this device published and has now removed.
    pub pruned: usize,
    /// How many records the remote does not yet hold this device's copy of.
    ///
    /// The pull's own count, and it deliberately excludes an etag-skipped
    /// object: the remote's copy of that one has not moved since the last pull,
    /// so this pass has nothing to say about it.
    ///
    /// THAT MAKES THE PULL STRUCTURALLY BLIND TO LOCAL CHANGE behind the skip,
    /// and the only thing carrying a local edit past it is the caller's dirty
    /// set - which is why that set is written to the caller's store file on
    /// every mark rather than held in memory. In memory alone, a quit inside
    /// the push debounce loses the edit with no error and a pending count of
    /// zero. See `readDirty` in `src/modules/sync/store.ts`.
    pub pending: usize,
}

/// One record a push could not place.
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PushFailure {
    pub kind: String,
    pub id: String,
    pub reason: String,
}

#[derive(Serialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PushReport {
    /// `kind:id` to the etag the remote gave the object this push wrote.
    pub etags: BTreeMap<String, String>,
    /// PER OBJECT, and nothing throws: one record the remote refused must not
    /// take the rest of the inventory with it, which is the disposition
    /// `MergeError` already mandates one layer up.
    pub failed: Vec<PushFailure>,
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

fn open_envelope(keys: &SyncKeys, bytes: &[u8]) -> Result<Envelope, String> {
    let sealed: SealedRecord = serde_json::from_slice(bytes)
        .map_err(|_| "sync: the object is not a sealed record".to_string())?;
    let plain = open_record(keys, sealed)?;
    serde_json::from_str(&plain)
        .map_err(|_| "sync: the sealed record is not an envelope".to_string())
}

/// Seal one envelope, stripping the device-local fields on the way out.
///
/// THE STRIP IS ALSO DONE BY THE CALLER, and the duplication is deliberate
/// rather than sloppy. The caller has to strip, because `Merged::changed`
/// compares the local envelope against the winner and a local envelope still
/// carrying this device's `pins` would differ from every stripped remote copy
/// on every pull. This side strips as well so that no future caller can publish
/// a trust pin by forgetting to - which is the failure that costs something
/// rather than a rewrite.
fn seal_envelope(keys: &SyncKeys, envelope: &Envelope) -> Result<Vec<u8>, String> {
    let mut envelope = envelope.clone();
    strip_device_local(&mut envelope.record);
    let plain = serde_json::to_string(&envelope)
        .map_err(|_| "sync: the envelope could not be serialized".to_string())?;
    let sealed = seal_record(keys, &plain)?;
    serde_json::to_vec(&sealed).map_err(|_| "sync: the sealed record could not be written".into())
}

// ---------------------------------------------------------------------------
// The pull
// ---------------------------------------------------------------------------

/// Reconcile the remote inventory against `locals`, pruning as it goes.
///
/// `locals` is records PLUS living tombstones, which is what lets a local
/// delete pair with its remote counterpart and resolve through the merge like
/// any other disagreement. Without the tombstones a deleted record would read
/// as `RemoteOnly` and land again on the device that deleted it.
///
/// `etags` is what the previous pull returned, minus anything the apply
/// refused.
#[allow(clippy::too_many_arguments)]
pub async fn pull(
    provider: &dyn SyncProvider,
    keys: &SyncKeys,
    prefix: &str,
    device: &str,
    locals: Vec<Envelope>,
    etags: BTreeMap<String, String>,
    now: u64,
) -> Result<PullReport, ProviderError> {
    let entries = provider.list(&object_prefix(prefix)).await?;

    // A REMOTE THAT HOLDS NOTHING AT ALL HAS NEVER HELD THIS INVENTORY, and
    // that is what lifts the stale rule at the bottom of this function. See
    // `Outcome::LocalOnly::stale` for why an empty listing is read differently
    // from a short one.
    let remote_is_empty = entries.is_empty();

    // The map arrives keyed by `kind:id`; the listing speaks object names. One
    // HMAC per known record turns one into the other.
    let mut named: BTreeMap<String, String> = BTreeMap::new();
    for key in etags.keys() {
        if let Some((kind, id)) = key.split_once(':') {
            named.insert(object_name(keys, kind, id), key.clone());
        }
    }

    let mut report = PullReport::default();
    let mut remotes: BTreeMap<String, Envelope> = BTreeMap::new();
    let mut skipped: BTreeSet<String> = BTreeSet::new();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();

    for entry in entries {
        let name = name_of(&entry.key).to_string();

        // THE PRUNE, step one: candidates come off the LISTING, outside the
        // etag skip below. `Entry::modified_at` is the remote's own stamp and
        // is the only reading of "old" available before a GET - and it has to
        // be, because a tombstone object never changes, so its etag matches
        // from the second pull onward and a filter reading `updatedAt` from
        // inside the envelope would be unreachable after the first run.
        let candidate = entry
            .modified_at
            .is_some_and(|m| now.saturating_sub(m) >= TOMBSTONE_TTL_MS);

        if !candidate {
            if let Some(known) = named.get(&name) {
                if etags.get(known) == Some(&entry.etag) {
                    skipped.insert(known.clone());
                    seen.insert(known.clone(), entry.etag);
                    continue;
                }
            }
        }

        // Step two: a candidate is fetched whether or not its etag moved,
        // because reading `Envelope::device` is the only way to answer step
        // three. By definition these are a handful.
        let Some(object) = provider.get(&entry.key).await? else {
            // Raced a delete by another device. Nothing to reconcile.
            continue;
        };
        let envelope = match open_envelope(keys, &object.bytes) {
            Ok(envelope) => envelope,
            Err(reason) => {
                report.quarantined.push(Quarantined { name, reason });
                continue;
            }
        };

        // THE VERSION CHECK, HERE RATHER THAN IN THE MERGE, AND BEFORE THE
        // PRUNE. `merge` refuses a version it does not know, but a `RemoteOnly`
        // object never reaches the merge - there is no local copy to merge it
        // with - so an object from a newer build would otherwise be handed to
        // the apply path unexamined, and its record shape written straight into
        // this device's store. That is exactly what `WIRE_VERSION` was minted
        // to prevent.
        //
        // BEFORE the prune rather than after, because the prune's decision is
        // an irreversible DELETE authorized by `deleted` and `device` - two
        // fields read through a schema this build has just said it cannot
        // interpret. The ordering costs nothing: `root` puts every object under
        // a `v1` path segment, so a v2 envelope at a v1 key is not a state the
        // layout produces.
        if envelope.v != WIRE_VERSION {
            report.quarantined.push(Quarantined {
                name,
                reason: format!(
                    "sync: this object was written by a newer build (wire version {}, this build reads {WIRE_VERSION})",
                    envelope.v
                ),
            });
            continue;
        }

        // Step three: delete only what THIS device published.
        //
        // A prune is destructive to every device, unlike a local expiry. A
        // device whose clock runs 100 days fast would otherwise delete every
        // remote tombstone on its first pull, and every other device would then
        // re-push any record edited inside the window. Locally a bad clock
        // skews one device's view and nobody else's.
        //
        // This is the first legitimate read of `Envelope::device`.
        // `ordering_key`'s prohibition is about the MERGE - a device id there
        // would make the winner depend on who pushed last - and says nothing
        // about a prune, where provenance is exactly the question being asked.
        //
        // The candidacy is re-asked against the envelope's OWN stamp rather
        // than taken from the listing, because that stamp is the `deletedAt`
        // every device filters by and the listing's is only when the object was
        // last written.
        let expired = envelope
            .updated_at
            .is_some_and(|u| now.saturating_sub(u) >= TOMBSTONE_TTL_MS);
        if candidate && envelope.deleted && expired {
            // A REFUSED DELETE IS NOT A FAILED PULL. A bucket with read-only
            // credentials, an object lock or a lifecycle policy refuses every
            // one of these, and propagating that would make the FIRST expired
            // tombstone abort the whole reconcile - no landings, no pushes,
            // forever, over an object whose only cost is the bytes it occupies.
            if envelope.device == device && provider.delete(&entry.key).await.is_ok() {
                report.pruned += 1;
            }
            // SKIPPED EITHER WAY, and that is not tidiness. An expired
            // tombstone is older than the window every device filters reads by,
            // so landing it writes a row that every subsequent read discards -
            // one store commit per expired tombstone per pull, forever, on any
            // remote holding one this device cannot remove.
            continue;
        }

        let key = slot(&envelope.kind, &envelope.id);
        seen.insert(key.clone(), object.etag);
        remotes.insert(key, envelope);
    }

    // LAST WINS on a duplicate slot, and the caller sends tombstones after
    // records, so a store that somehow held both a live record and a living
    // tombstone for one id would present the TOMBSTONE here. That is the
    // conservative side and the same one `ordering_key` takes on an exact tie:
    // a lost delete re-spreads data the user removed, a lost resurrection costs
    // one re-create. `withoutTombstone` should make the case unreachable; this
    // says which way it falls if it ever is not.
    let mut mine: BTreeMap<String, Envelope> = locals
        .into_iter()
        .map(|e| (slot(&e.kind, &e.id), e))
        .collect();

    for (key, remote) in remotes {
        let (kind, id) = (remote.kind.clone(), remote.id.clone());
        let Some(local) = mine.remove(&key) else {
            report.records.push(Reconciled {
                kind,
                id,
                outcome: Outcome::RemoteOnly { envelope: remote },
            });
            continue;
        };
        match merge(&local, &remote) {
            Ok(merged) => {
                let republish = content_differs(&merged.envelope, &remote);
                if republish {
                    report.pending += 1;
                }
                report.records.push(Reconciled {
                    kind,
                    id,
                    outcome: Outcome::Merged {
                        envelope: merged.envelope,
                        changed: merged.changed,
                        secrets_changed: merged.secrets_changed,
                        republish,
                    },
                });
            }
            Err(reason) => {
                // Out of the etag map as well as out of the record list, or the
                // next pull records a landing that never happened.
                seen.remove(&key);
                report.quarantined.push(Quarantined {
                    name: object_name(keys, &kind, &id),
                    reason: format!("sync: the two copies could not be merged ({reason:?})"),
                });
            }
        }
    }

    for (key, local) in mine {
        if skipped.contains(&key) {
            continue;
        }
        // An UNSTAMPED local record is not stale. Absent means "written before
        // the field existed", which is the one record that has certainly never
        // been published - so it is pushed, not reported.
        //
        // NOTHING IS STALE ON AN EMPTY REMOTE. The rule reads absence as a
        // delete whose tombstone has expired, and that reading needs a remote
        // that once held the record. A prefix with no objects at all is the one
        // shape where it cannot be true of every record at once.
        let stale = !remote_is_empty
            && local
                .updated_at
                .is_some_and(|u| now.saturating_sub(u) >= TOMBSTONE_TTL_MS);
        if !stale {
            report.pending += 1;
        }
        report.records.push(Reconciled {
            kind: local.kind,
            id: local.id,
            outcome: Outcome::LocalOnly { stale },
        });
    }

    report.etags = seen;
    Ok(report)
}

// ---------------------------------------------------------------------------
// The push
// ---------------------------------------------------------------------------

/// Publish `envelopes`, conditionally where the provider honours it.
///
/// `etags` supplies the `If-Match`. A record with no entry is a create, which
/// goes out with no condition at all: there is no etag to match. On a
/// compare-and-swap provider that is a create-if-absent race with another
/// device publishing the same id - the loser's write is overwritten and
/// recovered on the next pull, because the merge is content-ordered.
///
/// THE DEVICE ID IS STAMPED HERE, over whatever the caller sent. It is the one
/// field on an envelope that is not a fact about the record, and the prune
/// deletes remote objects on the strength of it - so the frontend is not
/// allowed a say in what it says, and does not need a command to ask what this
/// device is called.
pub async fn push(
    provider: &dyn SyncProvider,
    keys: &SyncKeys,
    prefix: &str,
    device: &str,
    envelopes: Vec<Envelope>,
    etags: BTreeMap<String, String>,
) -> PushReport {
    let cas = provider.capabilities().cas;
    let mut report = PushReport::default();
    for mut envelope in envelopes {
        envelope.device = device.to_string();
        let key = slot(&envelope.kind, &envelope.id);
        let object = object_key(prefix, &object_name(keys, &envelope.kind, &envelope.id));
        let condition = if cas { etags.get(&key).cloned() } else { None };
        match put_one(provider, keys, &object, &envelope, condition.as_deref()).await {
            Ok(etag) => {
                report.etags.insert(key, etag);
            }
            Err(reason) => report.failed.push(PushFailure {
                kind: envelope.kind,
                id: envelope.id,
                reason,
            }),
        }
    }
    report
}

async fn put_one(
    provider: &dyn SyncProvider,
    keys: &SyncKeys,
    object: &str,
    envelope: &Envelope,
    condition: Option<&str>,
) -> Result<String, String> {
    let bytes = seal_envelope(keys, envelope)?;
    match provider.put(object, bytes, condition).await {
        Ok(etag) => Ok(etag),
        Err(ProviderError::PreconditionFailed) => retry_merged(provider, keys, object, envelope)
            .await
            .map_err(|e| e.to_string()),
        Err(other) => Err(other.to_string()),
    }
}

/// ONE retry, and it goes back through the merge rather than forcing the write.
///
/// `PreconditionFailed` says the remote copy moved after the etag in hand was
/// read. A forced overwrite would discard whatever the other device just
/// published; the winner of the two copies is the only thing safe to write, and
/// computing it is what the merge is for. The failure is not surfaced to the
/// user: this is the ordinary shape of two devices editing at once.
async fn retry_merged(
    provider: &dyn SyncProvider,
    keys: &SyncKeys,
    object: &str,
    envelope: &Envelope,
) -> Result<String, ProviderError> {
    let Some(current) = provider.get(object).await? else {
        // Gone rather than moved - the prune removed it between the two calls.
        // This device's copy is then the only one left.
        let bytes = seal_envelope(keys, envelope).map_err(ProviderError::Config)?;
        return provider.put(object, bytes, None).await;
    };
    let remote = open_envelope(keys, &current.bytes).map_err(ProviderError::Malformed)?;
    let winner = merge(envelope, &remote)
        .map_err(|e| ProviderError::Malformed(format!("sync: the two copies disagree ({e:?})")))?
        .envelope;
    // The other device already published what this merge resolves to. Writing
    // it again would only mint a fresh nonce for identical content.
    if !content_differs(&winner, &remote) {
        return Ok(current.etag);
    }
    let bytes = seal_envelope(keys, &winner).map_err(ProviderError::Config)?;
    provider.put(object, bytes, Some(&current.etag)).await
}

// ---------------------------------------------------------------------------
// The purge
// ---------------------------------------------------------------------------

/// Rewrite every remote object that carries a private key body so that it no
/// longer does, and answer with how many were rewritten.
///
/// What a user asking to stop carrying secrets actually means. Turning the
/// carry toggle off only stops this device publishing new bodies; every body
/// already on the remote stays there until something goes and removes it, and
/// the objects are opaque from outside so nothing else can tell which ones
/// those are.
///
/// REWRITTEN RATHER THAN DELETED. The object also holds the record, which every
/// other device still wants; deleting it would publish a disappearance that the
/// pull reads as `LocalOnly` on every other device and re-pushes straight back,
/// body and all.
///
/// A plain function beside [`pull`] and [`push`] rather than a command body,
/// for the reason those two are split the same way: the fake provider in this
/// file's tests can drive it, and a `tauri::State` cannot be built in a test.
pub async fn purge_secrets(
    provider: &dyn SyncProvider,
    keys: &SyncKeys,
    prefix: &str,
) -> Result<usize, ProviderError> {
    let cas = provider.capabilities().cas;
    let mut purged = 0;
    for entry in provider.list(&object_prefix(prefix)).await? {
        let Some(object) = provider.get(&entry.key).await? else {
            // Raced a delete by another device. Nothing left to strip.
            continue;
        };
        // SKIPPED, NOT FATAL - the disposition the pull already gives an object
        // it cannot read. One object written by a newer build, or one the
        // keyfile does not open, must not leave every body after it in the
        // listing on the remote.
        let Ok(mut envelope) = open_envelope(keys, &object.bytes) else {
            continue;
        };
        if envelope.secrets.is_none() {
            continue;
        }
        envelope.secrets = None;
        let bytes = seal_envelope(keys, &envelope).map_err(ProviderError::Config)?;
        // The etag of the copy that was READ, not the one the listing reported:
        // the condition has to name the bytes this rewrite was computed from,
        // and a write landing between the list and the get would make those two
        // different.
        let condition = if cas {
            Some(object.etag.as_str())
        } else {
            None
        };
        // A REFUSED WRITE ABORTS, which is the opposite of the pull's
        // disposition for a refused prune and is not an inconsistency. There the
        // residue is bytes nobody reads; here it is a private key body still
        // legible to whoever holds the storage, so answering with a count as
        // though the purge had run would be the failure itself. The caller sees
        // the error and can ask again.
        provider.put(&entry.key, bytes, condition).await?;
        purged += 1;
    }
    Ok(purged)
}

// ---------------------------------------------------------------------------
// State and commands
// ---------------------------------------------------------------------------

/// One opened configuration.
///
/// CLONED OUT OF THE LOCK before anything is awaited. A `std::sync::MutexGuard`
/// is not `Send`, so an async command holding one across an await does not
/// compile - and a lock held across a network round trip would serialize every
/// other caller behind the slowest request anyway. Every field here is either
/// an `Arc` or a short string, so the clone is cheap.
#[derive(Clone)]
pub struct SyncSession {
    pub keys: Arc<SyncKeys>,
    pub provider: Arc<dyn SyncProvider>,
    pub prefix: String,
    pub device: String,
}

/// The configuration the commands below run against, or none.
///
/// EMPTY ON EVERY LAUNCH, and nothing persists it. [`sync_configure`] fills it
/// and the process losing it is the whole of "sync is off" - there is no file
/// here holding a passphrase, and a stored configuration cannot open itself.
/// Until a caller configures, every other command answers [`NOT_CONFIGURED`].
#[derive(Default)]
pub struct SyncState {
    session: Mutex<Option<SyncSession>>,
}

impl SyncState {
    fn open(&self) -> Result<SyncSession, String> {
        self.session
            .lock()
            .map_err(|_| POISONED.to_string())?
            .clone()
            .ok_or_else(|| NOT_CONFIGURED.to_string())
    }

    /// ONE SPELLING OF THE WRITE for both the open and the close, so neither
    /// can grow its own lock handling.
    fn set(&self, session: Option<SyncSession>) -> Result<(), String> {
        *self.session.lock().map_err(|_| POISONED.to_string())? = session;
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What [`sync_configure`] takes.
///
/// MIRRORED BY `SyncConfigureArgs` in `src/modules/sync/types.ts`, kept in
/// lockstep by hand: `tsc` cannot see across the IPC boundary, so a field
/// renamed on one side arrives `undefined` on the other with no error anywhere.
/// `deny_unknown_fields` is what turns that into a loud refusal at the first
/// call instead of a silently defaulted field - the same reason each provider
/// config struct carries it.
///
/// THE SECRETS ARRIVE AS ARGUMENTS rather than being read from the keychain
/// here. The window that has them is the window that just took them from the
/// user, and reading them back would put a second copy of the passphrase on a
/// path that does not need one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncConfigureArgs {
    provider: String,
    prefix: String,
    passphrase: String,
    /// The PROVIDER's own shape, unread by anything between the caller and
    /// `build` in `src-tauri/src/modules/sync/provider.rs`. A typed field here
    /// would make a second backend a change to this struct rather than one file
    /// plus one line.
    config: Value,
}

/// Open a session: build the provider, unwrap the keyfile, and hold both.
///
/// REPLACES WHATEVER WAS THERE, but only once the new session is in hand. A
/// configure that fails - an endpoint that is down, a passphrase mistyped -
/// leaves the working session it could not replace, which is the recoverable
/// direction: the caller retries and nothing stopped syncing meanwhile. Clearing
/// first would turn one transient failure into sync being off until someone
/// noticed, and the caller that genuinely wants it off has [`sync_disable`].
#[tauri::command]
pub async fn sync_configure(
    state: tauri::State<'_, SyncState>,
    args: SyncConfigureArgs,
) -> Result<(), String> {
    let provider = build(&args.provider, args.config).map_err(|e| e.to_string())?;
    let key = keyfile_key(&args.prefix);

    let keys = match provider.get(&key).await.map_err(|e| e.to_string())? {
        Some(object) => {
            // TWO DIFFERENT SENTENCES, and the distinction is the whole point of
            // parsing separately from opening. `open_keyfile` answers a wrong
            // passphrase and a tampered keyfile with one opaque message, on
            // purpose - but bytes that are not a keyfile at all tell nobody
            // anything about the passphrase, and folding them into that message
            // would tell a user who simply mistyped that their remote is
            // corrupt.
            let keyfile: Keyfile = serde_json::from_slice(&object.bytes).map_err(|_| {
                "sync: the file at the root of this prefix is not a sync keyfile - check that the \
                 prefix names the right place"
                    .to_string()
            })?;
            open_keyfile(&keyfile, &args.passphrase)?
        }
        None => {
            let (keyfile, keys) = new_keyfile(&args.passphrase)?;
            let bytes = serde_json::to_vec(&keyfile)
                .map_err(|_| "sync: the keyfile could not be written".to_string())?;
            // THE RACE IS REAL AND UNMITIGATED HERE. Two devices configuring
            // against one fresh prefix both read no keyfile and both mint one;
            // the second write wins, and the first device is left holding a root
            // key that nothing on the remote was sealed under - every object it
            // published before its next configure becomes unreadable to
            // everyone, itself included.
            //
            // The mitigation is a create-if-absent condition, and `put` cannot
            // express one: `if_match` carries an etag, and `build_put` in
            // `src-tauri/src/modules/sync/providers/s3.rs` spends it on an
            // `if-match` header, which no absent object can satisfy. Inventing a
            // sentinel spelling for it would be a provider contract written from
            // the calling side, against a trait whose own doc says `if_match`
            // is an etag. So the write goes out unconditional and the residue
            // stands: two devices configured against one empty prefix in the
            // same moment need one of them redone.
            provider
                .put(&key, bytes, None)
                .await
                .map_err(|e| e.to_string())?;
            keys
        }
    };

    let device = super::device_id()?;
    state.set(Some(SyncSession {
        keys: Arc::new(keys),
        provider,
        prefix: args.prefix,
        device,
    }))
}

/// Close the session this process holds.
///
/// NO NETWORK AND NO KEYCHAIN WRITE, and that is the whole contract. The stored
/// configuration and the credentials under it are the caller's to remove - it is
/// the side that wrote them, and the objects on the remote are not this
/// command's business either, since another device is still syncing them. All
/// this does is make every other command here answer [`NOT_CONFIGURED`] again.
#[tauri::command]
pub async fn sync_disable(state: tauri::State<'_, SyncState>) -> Result<(), String> {
    state.set(None)
}

/// Strip every private key body the remote is still carrying.
#[tauri::command]
pub async fn sync_purge_secrets(state: tauri::State<'_, SyncState>) -> Result<usize, String> {
    let session = state.open()?;
    purge_secrets(session.provider.as_ref(), &session.keys, &session.prefix)
        .await
        .map_err(|e| e.to_string())
}

/// Reconcile, and answer with what the caller has to apply.
#[tauri::command]
pub async fn sync_pull(
    state: tauri::State<'_, SyncState>,
    envelopes: Vec<Envelope>,
    etags: BTreeMap<String, String>,
) -> Result<PullReport, String> {
    let session = state.open()?;
    pull(
        session.provider.as_ref(),
        &session.keys,
        &session.prefix,
        &session.device,
        envelopes,
        etags,
        now_ms(),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Publish what the caller says the remote is missing.
#[tauri::command]
pub async fn sync_push(
    state: tauri::State<'_, SyncState>,
    envelopes: Vec<Envelope>,
    etags: BTreeMap<String, String>,
) -> Result<PushReport, String> {
    let session = state.open()?;
    Ok(push(
        session.provider.as_ref(),
        &session.keys,
        &session.prefix,
        &session.device,
        envelopes,
        etags,
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::sync::crypto::new_keyfile;
    use crate::modules::sync::model::WIRE_VERSION;
    use crate::modules::sync::provider::{Caps, Entry, Object};
    use serde_json::{json, Value};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    const DAY: u64 = 24 * 60 * 60 * 1000;
    /// "Now" for every test here, far enough from the epoch that a stamp a
    /// hundred days before it is still positive.
    const NOW: u64 = 1_800_000_000_000;

    /// A provider that keeps its objects in memory and counts what it was
    /// asked to do.
    ///
    /// The counts are the point rather than a convenience: half the properties
    /// below are "this object was NOT fetched" and "no put was issued", and
    /// neither is visible from a return value.
    /// One stored object: its bytes, its etag, and the remote's own stamp.
    type Stored = (Vec<u8>, String, Option<u64>);

    #[derive(Default)]
    struct Fake {
        objects: Mutex<BTreeMap<String, Stored>>,
        gets: Mutex<Vec<String>>,
        puts: Mutex<Vec<String>>,
        deletes: Mutex<Vec<String>>,
        cas: bool,
        /// Keys whose next conditional put is rejected once, to reach the retry.
        reject_once: Mutex<BTreeSet<String>>,
        /// What a read-only bucket, an object lock or a lifecycle policy does
        /// to every delete this provider is asked for.
        refuse_deletes: AtomicBool,
    }

    impl Fake {
        fn cas(cas: bool) -> Self {
            Self {
                cas,
                ..Default::default()
            }
        }

        fn seed(&self, key: &str, bytes: Vec<u8>, etag: &str, modified_at: Option<u64>) {
            self.objects
                .lock()
                .unwrap()
                .insert(key.into(), (bytes, etag.into(), modified_at));
        }

        fn gets(&self) -> Vec<String> {
            self.gets.lock().unwrap().clone()
        }
        fn puts(&self) -> Vec<String> {
            self.puts.lock().unwrap().clone()
        }
        fn deletes(&self) -> Vec<String> {
            self.deletes.lock().unwrap().clone()
        }
    }

    impl SyncProvider for Fake {
        fn id(&self) -> &'static str {
            "fake"
        }

        fn capabilities(&self) -> Caps {
            Caps { cas: self.cas }
        }

        fn get<'a>(
            &'a self,
            key: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Object>, ProviderError>> + Send + 'a>>
        {
            Box::pin(async move {
                self.gets.lock().unwrap().push(key.to_string());
                Ok(self
                    .objects
                    .lock()
                    .unwrap()
                    .get(key)
                    .map(|(bytes, etag, _)| Object {
                        bytes: bytes.clone(),
                        etag: etag.clone(),
                    }))
            })
        }

        fn put<'a>(
            &'a self,
            key: &'a str,
            bytes: Vec<u8>,
            if_match: Option<&'a str>,
        ) -> Pin<Box<dyn Future<Output = Result<String, ProviderError>> + Send + 'a>> {
            Box::pin(async move {
                if self.cas && if_match.is_some() && self.reject_once.lock().unwrap().remove(key) {
                    return Err(ProviderError::PreconditionFailed);
                }
                self.puts.lock().unwrap().push(key.to_string());
                let etag = format!("etag-{}", self.puts.lock().unwrap().len());
                let modified = self
                    .objects
                    .lock()
                    .unwrap()
                    .get(key)
                    .and_then(|(_, _, m)| *m);
                self.objects
                    .lock()
                    .unwrap()
                    .insert(key.into(), (bytes, etag.clone(), modified));
                Ok(etag)
            })
        }

        fn list<'a>(
            &'a self,
            prefix: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Entry>, ProviderError>> + Send + 'a>> {
            Box::pin(async move {
                Ok(self
                    .objects
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(key, _)| key.starts_with(prefix))
                    .map(|(key, (_, etag, modified_at))| Entry {
                        key: key.clone(),
                        etag: etag.clone(),
                        modified_at: *modified_at,
                    })
                    .collect())
            })
        }

        fn delete<'a>(
            &'a self,
            key: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>> {
            Box::pin(async move {
                self.deletes.lock().unwrap().push(key.to_string());
                if self.refuse_deletes.load(Ordering::SeqCst) {
                    return Err(ProviderError::Remote {
                        status: 403,
                        code: Some("AccessDenied".into()),
                    });
                }
                self.objects.lock().unwrap().remove(key);
                Ok(())
            })
        }
    }

    const PREFIX: &str = "tervia";

    fn keys() -> SyncKeys {
        new_keyfile("correct horse").expect("new keyfile").1
    }

    fn env(kind: &str, id: &str, updated_at: u64, device: &str, record: Value) -> Envelope {
        Envelope {
            v: WIRE_VERSION,
            kind: kind.into(),
            id: id.into(),
            updated_at: Some(updated_at),
            device: device.into(),
            deleted: false,
            record,
            secrets: None,
        }
    }

    fn host(id: &str, updated_at: u64, device: &str, name: &str) -> Envelope {
        env(
            "host",
            id,
            updated_at,
            device,
            json!({"id": id, "name": name}),
        )
    }

    fn grave(kind: &str, id: &str, deleted_at: u64, device: &str) -> Envelope {
        Envelope {
            deleted: true,
            record: Value::Null,
            ..env(kind, id, deleted_at, device, Value::Null)
        }
    }

    /// Put one envelope on the fake as a real sealed object, at the key the
    /// engine will look for it under.
    fn publish(
        fake: &Fake,
        keys: &SyncKeys,
        envelope: &Envelope,
        etag: &str,
        modified: Option<u64>,
    ) {
        let key = object_key(PREFIX, &object_name(keys, &envelope.kind, &envelope.id));
        fake.seed(&key, seal_envelope(keys, envelope).unwrap(), etag, modified);
    }

    fn key_of(keys: &SyncKeys, envelope: &Envelope) -> String {
        object_key(PREFIX, &object_name(keys, &envelope.kind, &envelope.id))
    }

    fn outcome<'a>(report: &'a PullReport, id: &str) -> &'a Outcome {
        &report
            .records
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("no disposition for {id}"))
            .outcome
    }

    async fn pull_with(
        fake: &Fake,
        keys: &SyncKeys,
        locals: Vec<Envelope>,
        etags: BTreeMap<String, String>,
    ) -> PullReport {
        pull(fake, keys, PREFIX, "this-device", locals, etags, NOW)
            .await
            .expect("pull")
    }

    #[test]
    fn the_object_layout_is_versioned_and_the_prefix_is_normalized() {
        // Three spellings of one prefix have to name one place, or a user who
        // typed a trailing slash gets a second, empty inventory.
        for spelling in ["tervia", "/tervia", "tervia/", "/tervia/"] {
            assert_eq!(object_prefix(spelling), "tervia/v1/obj/");
            assert_eq!(object_key(spelling, "abcd"), "tervia/v1/obj/abcd");
        }
        assert_eq!(object_prefix(""), "v1/obj/");
        // The trailing slash on the LIST prefix, which is what keeps a sibling
        // prefix sharing these characters out of this inventory.
        assert!(object_prefix("tervia").ends_with('/'));
        assert_eq!(name_of("tervia/v1/obj/abcd"), "abcd");
    }

    #[tokio::test]
    async fn the_union_pairs_a_local_tombstone_with_its_remote_counterpart() {
        // R3. The clause that makes a delete survive a pull: with tombstones
        // outside the local set, a record deleted here reads as `RemoteOnly`
        // and lands again on the device that deleted it.
        let keys = keys();
        let fake = Fake::cas(true);
        let remote_live = host("h-1", NOW - 9000, "dev-b", "still here");
        let remote_new = host("h-2", NOW - 8000, "dev-b", "new over there");
        publish(&fake, &keys, &remote_live, "e1", Some(NOW - 9000));
        publish(&fake, &keys, &remote_new, "e2", Some(NOW - 8000));

        let locals = vec![
            grave("host", "h-1", NOW - 1000, "this-device"),
            host("h-3", NOW - 500, "this-device", "only here"),
        ];
        let report = pull_with(&fake, &keys, locals, BTreeMap::new()).await;

        // The local delete is newer, so the merge resolves to the tombstone -
        // and it is a `Merged`, not a `RemoteOnly`.
        match outcome(&report, "h-1") {
            Outcome::Merged {
                envelope,
                republish,
                ..
            } => {
                assert!(envelope.deleted, "the delete lost to the remote record");
                assert!(republish, "the remote still holds the deleted record");
            }
            other => panic!("h-1: {other:?}"),
        }
        assert!(matches!(
            outcome(&report, "h-2"),
            Outcome::RemoteOnly { .. }
        ));
        assert!(matches!(
            outcome(&report, "h-3"),
            Outcome::LocalOnly { stale: false }
        ));
        // Two records the remote is missing this device's copy of.
        assert_eq!(report.pending, 2);
    }

    #[tokio::test]
    async fn a_local_only_record_older_than_the_window_is_reported_and_not_deleted() {
        let keys = keys();
        let fake = Fake::cas(true);
        // THE REMOTE HOLDS SOMETHING, and that is load-bearing rather than
        // scenery: an empty listing lifts the stale rule outright, so a version
        // of this test with nothing published would pass for the wrong reason
        // and stop guarding the window at all. See
        // `an_empty_remote_is_never_stale_so_the_whole_inventory_publishes`.
        let theirs = host("h-9", NOW - 9000, "dev-b", "over there");
        publish(&fake, &keys, &theirs, "e1", Some(NOW - 9000));
        let locals = vec![
            host("h-1", NOW - 100 * DAY, "this-device", "long gone elsewhere"),
            host("h-2", NOW - 1000, "this-device", "recent"),
        ];
        let report = pull_with(&fake, &keys, locals, BTreeMap::new()).await;

        assert!(matches!(
            outcome(&report, "h-1"),
            Outcome::LocalOnly { stale: true }
        ));
        assert!(matches!(
            outcome(&report, "h-2"),
            Outcome::LocalOnly { stale: false }
        ));
        // A stale record is not pending either: reporting it is the whole
        // disposition, and counting it would keep a badge lit forever.
        assert_eq!(report.pending, 1);
        assert!(fake.deletes().is_empty(), "a listing gap deleted a record");
        assert!(fake.puts().is_empty(), "the pull wrote objects itself");
    }

    #[tokio::test]
    async fn an_empty_remote_is_never_stale_so_the_whole_inventory_publishes() {
        // D1, from the cross-device sync hand test: a device holding an inventory it had
        // already published to one remote was pointed at a fresh prefix, and
        // published only the records it had touched inside the tombstone
        // window - 16 of 65 - while reporting nothing pending and no error.
        // A prefix with no objects in it has never held any of these, so the
        // reading the stale rule makes is unavailable and every record is owed.
        let keys = keys();
        let fake = Fake::cas(true);
        let locals = vec![
            host(
                "h-1",
                NOW - 100 * DAY,
                "this-device",
                "older than the window",
            ),
            host("h-2", NOW - 1000, "this-device", "recent"),
        ];
        let report = pull_with(&fake, &keys, locals, BTreeMap::new()).await;

        assert!(
            matches!(outcome(&report, "h-1"), Outcome::LocalOnly { stale: false }),
            "an old record was withheld from a remote that holds nothing"
        );
        assert!(matches!(
            outcome(&report, "h-2"),
            Outcome::LocalOnly { stale: false }
        ));
        // Both are owed, so the settings surface says so rather than zero.
        assert_eq!(report.pending, 2);
        // The publishing is still the caller's, not the pull's.
        assert!(fake.puts().is_empty(), "the pull wrote objects itself");
        assert!(fake.deletes().is_empty());
    }

    #[tokio::test]
    async fn an_etag_that_matches_is_not_fetched_and_a_prune_candidate_still_is() {
        // R5. Both halves in one place, because the skip and the prune read the
        // same listing and only their ORDER keeps them from cancelling out.
        let keys = keys();
        let fake = Fake::cas(true);
        let unchanged = host("h-1", NOW - 9000, "dev-b", "unchanged");
        let moved = host("h-2", NOW - 8000, "dev-b", "moved");
        let old_grave = grave("host", "h-3", NOW - 100 * DAY, "this-device");
        publish(&fake, &keys, &unchanged, "same", Some(NOW - 9000));
        publish(&fake, &keys, &moved, "different", Some(NOW - 8000));
        publish(&fake, &keys, &old_grave, "ancient", Some(NOW - 100 * DAY));

        let etags = BTreeMap::from([
            ("host:h-1".to_string(), "same".to_string()),
            ("host:h-2".to_string(), "stale".to_string()),
            ("host:h-3".to_string(), "ancient".to_string()),
        ]);
        let locals = vec![host("h-1", NOW - 9000, "this-device", "unchanged")];
        let report = pull_with(&fake, &keys, locals, etags).await;

        let fetched = fake.gets();
        assert!(
            !fetched.contains(&key_of(&keys, &unchanged)),
            "an unchanged object was downloaded again"
        );
        assert!(fetched.contains(&key_of(&keys, &moved)));
        // The prune candidate's etag matched the map and it was fetched anyway.
        // This is the clause that makes the prune reachable at all: a tombstone
        // object never changes, so from the second pull on it is always a
        // skip candidate.
        assert!(
            fetched.contains(&key_of(&keys, &old_grave)),
            "the prune candidate was etag-skipped"
        );
        assert_eq!(report.pruned, 1);

        // The skipped object produces no disposition, and its local copy is not
        // reported as `LocalOnly`.
        assert!(
            !report.records.iter().any(|r| r.id == "h-1"),
            "a skipped object still produced a disposition"
        );
        // Its etag is carried forward, or the next pull would fetch it again.
        assert_eq!(report.etags.get("host:h-1"), Some(&"same".to_string()));
    }

    #[tokio::test]
    async fn the_prune_removes_only_this_devices_own_expired_tombstones() {
        // R4, run with a POPULATED etag map, so it certifies the prune the real
        // pipeline reaches rather than the one a first-ever pull reaches.
        let keys = keys();
        let fake = Fake::cas(true);
        let mine_old = grave("host", "h-1", NOW - 100 * DAY, "this-device");
        let mine_recent = grave("host", "h-2", NOW - DAY, "this-device");
        let theirs_old = grave("host", "h-3", NOW - 100 * DAY, "dev-b");
        publish(&fake, &keys, &mine_old, "a", Some(NOW - 100 * DAY));
        publish(&fake, &keys, &mine_recent, "b", Some(NOW - DAY));
        publish(&fake, &keys, &theirs_old, "c", Some(NOW - 100 * DAY));

        let etags = BTreeMap::from([
            ("host:h-1".to_string(), "a".to_string()),
            ("host:h-2".to_string(), "b".to_string()),
            ("host:h-3".to_string(), "c".to_string()),
        ]);
        let report = pull_with(&fake, &keys, Vec::new(), etags).await;

        assert_eq!(
            fake.deletes(),
            vec![key_of(&keys, &mine_old)],
            "the prune deleted the wrong set"
        );
        assert_eq!(report.pruned, 1);
        // A pruned object leaves the etag map with it.
        assert!(!report.etags.contains_key("host:h-1"));
        // The other device's expired tombstone survives on the remote - that is
        // the accepted residue - and is NOT landed here, which is a different
        // claim and the one that costs something: see
        // `another_devices_expired_tombstone_is_not_landed_either`.
        assert!(!report.records.iter().any(|r| r.id == "h-3"));
        // And the one INSIDE the window keeps its etag, so the skip above is
        // keyed on expiry rather than on being a tombstone at all - the
        // reconcile half of that claim is
        // `a_tombstone_inside_the_window_is_still_reconciled`, which runs with
        // no etag map so the object is actually read.
        assert_eq!(report.etags.get("host:h-2"), Some(&"b".to_string()));
    }

    #[tokio::test]
    async fn an_object_that_does_not_open_is_quarantined_and_leaves_the_map_alone() {
        let keys = keys();
        let fake = Fake::cas(true);
        let good = host("h-1", NOW - 1000, "dev-b", "fine");
        publish(&fake, &keys, &good, "e1", Some(NOW - 1000));
        fake.seed(
            &object_key(PREFIX, "deadbeef"),
            b"not a sealed record at all".to_vec(),
            "e2",
            Some(NOW - 1000),
        );

        let report = pull_with(&fake, &keys, Vec::new(), BTreeMap::new()).await;
        assert_eq!(report.quarantined.len(), 1);
        assert_eq!(report.quarantined[0].name, "deadbeef");
        // The good object in the same listing still landed - one bad object
        // must not cost an inventory.
        assert!(matches!(
            outcome(&report, "h-1"),
            Outcome::RemoteOnly { .. }
        ));
        assert_eq!(report.etags.len(), 1);
    }

    #[tokio::test]
    async fn an_object_from_a_newer_build_is_quarantined_rather_than_landed() {
        // The `RemoteOnly` arm never reaches `merge`, so `MergeError::Version`
        // cannot fire there - and that arm is precisely the one a brand new
        // record kind arrives through. Without the check here the first v2
        // object publishes its record shape straight into this device's store.
        let keys = keys();
        let fake = Fake::cas(true);
        let mut future = host("h-1", NOW - 1000, "dev-b", "from a newer build");
        future.v = WIRE_VERSION + 1;
        let good = host("h-2", NOW - 1000, "dev-b", "readable");
        publish(&fake, &keys, &future, "e1", Some(NOW - 1000));
        publish(&fake, &keys, &good, "e2", Some(NOW - 1000));

        let report = pull_with(&fake, &keys, Vec::new(), BTreeMap::new()).await;
        assert!(
            !report.records.iter().any(|r| r.id == "h-1"),
            "a newer-build object reached the apply path"
        );
        assert_eq!(report.quarantined.len(), 1);
        assert!(
            report.quarantined[0].reason.contains("newer build"),
            "unexpected: {}",
            report.quarantined[0].reason
        );
        // Out of the etag map too, or the next pull skips it and the
        // quarantine is reported exactly once, ever.
        assert!(!report.etags.contains_key("host:h-1"));
        // And the readable object in the same listing still landed.
        assert!(matches!(
            outcome(&report, "h-2"),
            Outcome::RemoteOnly { .. }
        ));
    }

    #[tokio::test]
    async fn a_refused_prune_delete_does_not_abort_the_pull() {
        // A bucket with read-only credentials, an object lock or a lifecycle
        // policy refuses every prune. Propagating that makes the FIRST expired
        // tombstone abort the whole reconcile - no landings, no pushes - over
        // an object whose only cost is the bytes it occupies.
        let keys = keys();
        let fake = Fake::cas(true);
        fake.refuse_deletes.store(true, Ordering::SeqCst);
        let mine_old = grave("host", "h-1", NOW - 100 * DAY, "this-device");
        let live = host("h-2", NOW - 1000, "dev-b", "still wanted");
        publish(&fake, &keys, &mine_old, "a", Some(NOW - 100 * DAY));
        publish(&fake, &keys, &live, "b", Some(NOW - 1000));

        let report = pull_with(&fake, &keys, Vec::new(), BTreeMap::new()).await;
        assert_eq!(report.pruned, 0, "a refused delete was counted as pruned");
        // The rest of the inventory reconciled anyway, which is the property.
        assert!(matches!(
            outcome(&report, "h-2"),
            Outcome::RemoteOnly { .. }
        ));
        // And the one it could not remove produces NO disposition. Landing an
        // expired tombstone writes a row every read then filters straight back
        // out, so a remote holding one this device cannot delete would
        // otherwise cost a store commit on every pull for the life of the
        // bucket.
        assert!(
            !report.records.iter().any(|r| r.id == "h-1"),
            "an expired tombstone was handed to the apply path"
        );
    }

    #[tokio::test]
    async fn another_devices_expired_tombstone_is_not_landed_either() {
        // The prune leaves it in place - that is the accepted residue - but
        // leaving it in place and LANDING it on every pull are different
        // things, and only the second costs a commit per pull forever.
        let keys = keys();
        let fake = Fake::cas(true);
        let theirs = grave("host", "h-3", NOW - 100 * DAY, "dev-b");
        publish(&fake, &keys, &theirs, "c", Some(NOW - 100 * DAY));

        let report = pull_with(&fake, &keys, Vec::new(), BTreeMap::new()).await;
        assert!(
            fake.deletes().is_empty(),
            "another device's object was pruned"
        );
        assert!(
            report.records.is_empty(),
            "an expired tombstone was handed to the apply path: {:?}",
            report.records
        );
    }

    #[tokio::test]
    async fn a_tombstone_inside_the_window_is_still_reconciled() {
        // The anti-vacuity pair for the two checks above: the skip is keyed on
        // EXPIRY, so a live delete still has to reach the apply path or every
        // delete stops propagating.
        let keys = keys();
        let fake = Fake::cas(true);
        let recent = grave("host", "h-4", NOW - DAY, "dev-b");
        publish(&fake, &keys, &recent, "d", Some(NOW - DAY));

        let report = pull_with(&fake, &keys, Vec::new(), BTreeMap::new()).await;
        assert!(matches!(
            outcome(&report, "h-4"),
            Outcome::RemoteOnly { .. }
        ));
    }

    #[tokio::test]
    async fn a_rejected_conditional_write_pulls_merges_and_retries_without_an_error() {
        // R2. The disposition `PreconditionFailed` exists for: the remote copy
        // moved after this device read its etag, so the winner of the two is
        // the only thing safe to write.
        let keys = keys();
        let fake = Fake::cas(true);
        let theirs = host("h-1", NOW - 1000, "dev-b", "theirs, newer");
        publish(&fake, &keys, &theirs, "current", Some(NOW - 1000));
        fake.reject_once
            .lock()
            .unwrap()
            .insert(key_of(&keys, &theirs));

        let mine = host("h-1", NOW - 5000, "this-device", "mine, older");
        let etags = BTreeMap::from([("host:h-1".to_string(), "stale".to_string())]);
        let report = push(&fake, &keys, PREFIX, "this-device", vec![mine], etags).await;

        assert!(report.failed.is_empty(), "unexpected: {:?}", report.failed);
        // The retry found the remote copy newer, so it wrote nothing at all and
        // reported the etag it already holds.
        assert!(
            fake.puts().is_empty(),
            "the retry overwrote a newer remote copy"
        );
        assert_eq!(report.etags.get("host:h-1"), Some(&"current".to_string()));
    }

    #[tokio::test]
    async fn a_retry_that_wins_the_merge_writes_the_winner_conditionally() {
        let keys = keys();
        let fake = Fake::cas(true);
        let theirs = host("h-1", NOW - 9000, "dev-b", "theirs, older");
        publish(&fake, &keys, &theirs, "current", Some(NOW - 9000));
        fake.reject_once
            .lock()
            .unwrap()
            .insert(key_of(&keys, &theirs));

        let mine = host("h-1", NOW - 1000, "this-device", "mine, newer");
        let etags = BTreeMap::from([("host:h-1".to_string(), "stale".to_string())]);
        let report = push(
            &fake,
            &keys,
            PREFIX,
            "this-device",
            vec![mine.clone()],
            etags,
        )
        .await;

        assert!(report.failed.is_empty(), "unexpected: {:?}", report.failed);
        assert_eq!(fake.puts(), vec![key_of(&keys, &theirs)]);
        // And what landed is this device's record, readable by the other side.
        let stored = fake.objects.lock().unwrap()[&key_of(&keys, &theirs)]
            .0
            .clone();
        assert_eq!(
            open_envelope(&keys, &stored).unwrap().record["name"],
            "mine, newer"
        );
    }

    #[tokio::test]
    async fn a_create_goes_out_unconditionally_and_a_non_cas_provider_never_conditions() {
        // Two ways to reach an unconditional put, and only one of them is a
        // capability: a record with no etag has no condition to send.
        for cas in [true, false] {
            let keys = keys();
            let fake = Fake::cas(cas);
            let mine = host("h-1", NOW - 1000, "this-device", "fresh");
            // Rejection is armed, and can only fire on a CONDITIONAL put.
            fake.reject_once
                .lock()
                .unwrap()
                .insert(key_of(&keys, &mine));
            let report = push(
                &fake,
                &keys,
                PREFIX,
                "this-device",
                vec![mine.clone()],
                BTreeMap::new(),
            )
            .await;
            assert!(report.failed.is_empty(), "cas={cas}: {:?}", report.failed);
            assert_eq!(fake.puts().len(), 1, "cas={cas}");
            assert!(report.etags.contains_key("host:h-1"), "cas={cas}");
        }
    }

    #[tokio::test]
    async fn the_push_stamps_this_device_over_whatever_it_was_handed() {
        // The prune deletes remote objects on the strength of this field, so a
        // frontend that could set it could make one device delete another's
        // tombstones. The stamp is what removes the question - and it also
        // removes the need for a command that tells the frontend this device's
        // id in the first place.
        let keys = keys();
        let fake = Fake::cas(false);
        let mut claimed = host("h-1", NOW - 1000, "somebody-elses-id", "fresh");
        claimed.device = "somebody-elses-id".into();
        push(
            &fake,
            &keys,
            PREFIX,
            "this-device",
            vec![claimed.clone()],
            BTreeMap::new(),
        )
        .await;

        let stored = fake.objects.lock().unwrap()[&key_of(&keys, &claimed)]
            .0
            .clone();
        assert_eq!(open_envelope(&keys, &stored).unwrap().device, "this-device");
    }

    #[tokio::test]
    async fn a_published_record_carries_no_device_local_field() {
        // The four fields that describe THIS machine. A wholesale write of a
        // pulled record deletes the receiving device's trust pins, so the
        // publishing side is where they have to stop.
        let keys = keys();
        let fake = Fake::cas(false);
        let mut mine = host("h-1", NOW - 1000, "this-device", "pinned");
        mine.record = json!({
            "id": "h-1",
            "name": "pinned",
            "pins": {"example.com": "SHA256:aaa"},
            "lastConnectedAt": 1700,
            "lastFingerprint": "SHA256:aaa",
            "certFingerprint": "SHA256:bbb",
        });
        push(
            &fake,
            &keys,
            PREFIX,
            "this-device",
            vec![mine],
            BTreeMap::new(),
        )
        .await;

        let stored = fake.objects.lock().unwrap()
            [&object_key(PREFIX, &object_name(&keys, "host", "h-1"))]
            .0
            .clone();
        let published = open_envelope(&keys, &stored).unwrap();
        for field in [
            "pins",
            "lastConnectedAt",
            "lastFingerprint",
            "certFingerprint",
        ] {
            assert!(
                published.record.get(field).is_none(),
                "{field} was published"
            );
        }
        assert_eq!(published.record["name"], "pinned");
    }

    #[tokio::test]
    async fn a_remote_win_that_needs_no_republish_is_not_counted_as_pending() {
        // The steady state of two devices that agree: the pull reads the
        // listing, finds nothing to do, and says so.
        let keys = keys();
        let fake = Fake::cas(true);
        let shared = host("h-1", NOW - 1000, "dev-b", "agreed");
        publish(&fake, &keys, &shared, "e1", Some(NOW - 1000));

        let mine = host("h-1", NOW - 1000, "this-device", "agreed");
        let report = pull_with(&fake, &keys, vec![mine], BTreeMap::new()).await;

        match outcome(&report, "h-1") {
            Outcome::Merged {
                changed,
                secrets_changed,
                republish,
                ..
            } => {
                assert!(!changed, "an agreed pair rewrote the store");
                assert!(!secrets_changed);
                assert!(!republish, "an agreed pair republished");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(report.pending, 0);
    }

    #[tokio::test]
    async fn the_purge_rewrites_the_objects_that_carried_a_body_and_touches_no_others() {
        // WHICH KEYS GOT A PUT is the entire content of this check. Byte
        // equality on the untouched objects would look like a stronger claim
        // and be a broken one: `seal_record` draws a fresh nonce, so a
        // re-sealed object is never byte-equal to itself and the assertion
        // would fail against a correct implementation.
        let keys = keys();
        let fake = Fake::cas(true);
        let carrying = |id: &str, updated_at: u64, body: &str| Envelope {
            secrets: Some(json!({ "privateKey": body })),
            ..env("key", id, updated_at, "dev-b", json!({"id": id}))
        };
        let one = carrying("k-1", NOW - 1000, "BODY ONE");
        let two = carrying("k-2", NOW - 2000, "BODY TWO");
        let bare = host("h-1", NOW - 3000, "dev-b", "never carried one");
        publish(&fake, &keys, &one, "e1", Some(NOW - 1000));
        publish(&fake, &keys, &two, "e2", Some(NOW - 2000));
        publish(&fake, &keys, &bare, "e3", Some(NOW - 3000));

        let purged = purge_secrets(&fake, &keys, PREFIX).await.expect("purge");

        assert_eq!(purged, 2);
        let mut written = fake.puts();
        written.sort();
        let mut expected = vec![key_of(&keys, &one), key_of(&keys, &two)];
        expected.sort();
        assert_eq!(
            written, expected,
            "the purge wrote the wrong set of objects"
        );
        // And what landed is the same record without the body, rather than a
        // record the other devices will read as a change.
        let stored = fake.objects.lock().unwrap()[&key_of(&keys, &one)].0.clone();
        let rewritten = open_envelope(&keys, &stored).unwrap();
        assert!(rewritten.secrets.is_none(), "the body survived the purge");
        assert_eq!(rewritten.record, one.record);
    }

    #[test]
    fn neither_command_runs_without_a_configuration() {
        // The state every launch starts in, asserted rather than assumed:
        // nothing persists a session, so a device whose user configured sync
        // last week still answers this way until a caller reopens it.
        let state = SyncState::default();
        // `.err()` rather than `.unwrap_err()`, which would need `SyncSession`
        // to be `Debug` - and a derived one prints the `SyncKeys` inside it,
        // which is exactly what `crypto.rs` declines a formatter for.
        let err = state.open().err().expect("an empty state must refuse");
        assert_eq!(err, NOT_CONFIGURED);
    }
}
