//! The wire format two devices agree on, and the merge that resolves one
//! record's two copies.
//!
//! PURE: no clock, no filesystem, no network, no randomness. Everything here
//! is a function of its arguments, which is what makes the merge testable at
//! all and what makes two devices running it on the same pair agree.
//!
//! THE RECORD BODY IS OPAQUE. [`Envelope::record`] is a `serde_json::Value`
//! and [`Envelope::kind`] is a `String`, rather than five Rust structs
//! mirroring the TypeScript records. A second schema would have to be
//! hand-maintained against the first, and a field added on one side and not
//! the other would be silently dropped on every round trip through here -
//! `src-tauri/src/modules/backup.rs` treats its payload as a `Value` for the
//! same reason. The cost is that the two vault exceptions in [`merge`] read
//! fields by name, so a rename in `src/modules/vault/types.ts` breaks them
//! silently; the tests below are the detector.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bumped when a change to this format stops an older build from reading it.
///
/// A VALUE CHECK, not a guess: [`merge`] refuses an envelope it does not
/// recognise rather than assuming the fields it knows mean what they used to,
/// the same way `SealedBlob.kdf` in `src-tauri/src/modules/backup.rs` is
/// checked rather than assumed.
pub const WIRE_VERSION: u32 = 1;

/// What a vault key is called in [`Envelope::kind`]. Mirrors
/// `KEY_TOMBSTONE_KIND` in `src/modules/vault/types.ts`.
///
/// The only record kind this module knows the NAME of, and it is named only to
/// gate the two vault exceptions. A future kind that grows its own `encrypted`
/// field does not inherit their meaning by accident.
const KEY_KIND: &str = "key";

/// Fields a record carries that describe THIS MACHINE rather than the record,
/// removed before a record is published.
///
/// Keyed on the field names alone rather than on `kind`, because every kind
/// that reuses one of these names means the same device-local thing by it, and
/// a host arrives as an `SshHost` or an `RdpHost` under the one `"host"` kind
/// either way. `pins` and `lastConnectedAt` come from `HostBase`,
/// `lastFingerprint` from `SshHost` and `certFingerprint` from `RdpHost`, all
/// in `src/modules/hosts/types.ts`.
///
/// `lastConnectedAt` is here deliberately: it does not travel, so its meaning
/// stays "last connected FROM THIS DEVICE". `VaultIdentity` and `VaultKey`
/// carry it too, with the same meaning, and are stripped by the same entry.
/// Letting it travel later is additive and not a format break.
///
/// `credentialStamp` needs no entry - it is a function, not a stored field.
const DEVICE_LOCAL_FIELDS: [&str; 4] = [
    "pins",
    "lastConnectedAt",
    "lastFingerprint",
    "certFingerprint",
];

/// One record, as it travels.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    /// [`WIRE_VERSION`] at the time this was written.
    pub v: u32,
    /// The tombstone `kind` the owning store already uses: `"host"`,
    /// `"group"`, `"identity"`, `"key"`, `"rule"`. See `src/lib/tombstones.ts`
    /// for why that field is a plain string there too.
    pub kind: String,
    pub id: String,
    /// Unix ms of the record's last content change, copied from the record's
    /// own `updatedAt`, or the tombstone's `deletedAt`.
    ///
    /// ABSENT IS NOT ZERO and is never backfilled - it orders BELOW any stamp,
    /// because absent means "written before the field existed" and must never
    /// outrank a real one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    /// Which device published this. PROVENANCE ONLY - the merge does not read
    /// it, and [`ordering_key`] says why not. The one reader is the prune, and
    /// there the question being asked IS provenance.
    ///
    /// `default` so a frontend that assembles an envelope may leave it out.
    /// That is not leniency: the push STAMPS this field over whatever arrived,
    /// because the prune deletes remote objects on the strength of it and a
    /// value a webview could choose is a value a webview could get wrong.
    #[serde(default)]
    pub device: String,
    /// A tombstone. `record` is `Null` and `updated_at` is the `deletedAt`.
    #[serde(default)]
    pub deleted: bool,
    /// The record with every device-local field already removed - see
    /// [`strip_device_local`]. `Null` when `deleted`.
    pub record: Value,
    /// Present only when the user opted into carrying secrets, which is off by
    /// default. A flat field-to-value map for this ONE record, e.g.
    /// `{"privateKey": "..."}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Value>,
}

/// Why an envelope pair could not be merged.
///
/// A typed error rather than a `String` because the caller has to tell three
/// dispositions apart: "the other device runs a newer build, skip this object
/// and say so", "this object is corrupt, quarantine it", and "this object was
/// overwritten by a different record". String-matching for that would be
/// decided once every call site was already written.
///
/// A refusal is PER OBJECT. One bad object must not block the rest of an
/// inventory, so the caller quarantines the object and carries on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// One side is not [`WIRE_VERSION`]. Unknown is not guessable, which is the
    /// entire reason [`Envelope::v`] exists.
    Version { found: u32, expected: u32 },
    /// The two sides disagree on `kind` or `id`. An object name is derived
    /// from both, so a decrypted envelope disagreeing with its sibling is the
    /// signal that an object was overwritten by a DIFFERENT record. Picking
    /// one of the two is corruption laundering.
    IdentityMismatch,
    /// `deleted` with no `updated_at`. `Tombstone.deletedAt` is a required
    /// number in `src/lib/tombstones.ts`, so this cannot be produced locally
    /// and can only arrive from a corrupt or hostile remote - where it would
    /// lose to every stamped record, which is a delete that quietly fails to
    /// propagate.
    UnstampedTombstone,
    /// Not `deleted`, yet `record` is `Null`. The mirror of the above and
    /// worse: it canonicalizes to the string `null`, so on a newer stamp it
    /// WINS, and the apply path then writes a null record over a live one.
    NullLiveRecord,
}

/// Which copy won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Local,
    Remote,
}

/// The resolved record, and which side it came from.
///
/// `winner` IS NOT A DIRTY FLAG, in either direction, and a caller that treats
/// it as one loses data:
///
/// - `Side::Local` does not mean the result equals `local`. The two vault
///   exceptions in [`merge`] run AFTER the side is decided and mutate the
///   winner, so a local win can still strip a `fingerprint` or gain an
///   `encrypted`. Skipping the local write on `Side::Local` silently drops
///   that.
/// - `Side::Remote` does not mean the result differs from `local` either. Once
///   an `encrypted` backfill has landed locally, the bare remote copy still
///   sorts above it - `canonical` puts `encrypted` before `hasPrivateKey` -
///   so it wins every subsequent pull and is re-backfilled to the same
///   content each time. The content is a fixed point; the side is not.
///
/// Compare the envelope with what is already stored. The side is provenance,
/// good for a log line or for deciding which way to push, and nothing more.
///
/// [`Merged::changed`] and [`Merged::secrets_changed`] are that comparison,
/// done here because this is the layer that still holds `local`.
#[derive(Debug, Clone, PartialEq)]
pub struct Merged {
    pub winner: Side,
    pub envelope: Envelope,
    /// Whether the winner differs from `local` in what the STORE holds.
    ///
    /// TWO FLAGS AND NOT ONE, because there are two destinations and each
    /// compares against exactly what it stores. A single flag over the whole
    /// envelope is wrong twice over:
    ///
    /// - whole-envelope equality reads `device`, the one field that always
    ///   differs between two devices, so it would be `true` on every remote
    ///   win and the store would be rewritten on every pull;
    /// - [`ordering_key`] reads `secrets`, and [`merge`]'s own doc calls the
    ///   configuration where two sides differ only in `secrets` the steady
    ///   state - so that would rewrite the store on every pull too, for a
    ///   difference that belongs to the keychain.
    ///
    /// Computed AFTER the two vault exceptions run, against the normalized
    /// local, so a stripped `fingerprint` or a backfilled `encrypted` is
    /// inside it.
    pub changed: bool,
    /// Whether the winner differs from `local` in what the KEYCHAIN holds.
    ///
    /// Drives the body write, which is the expensive one: on Linux and Windows
    /// a single keychain write is a read-modify-write of the whole secrets
    /// file, so a flag that fired on every pull would rewrite every stored
    /// secret every time the window regained focus.
    pub secrets_changed: bool,
}

/// The compact JSON for a value, which is what the ordering key compares.
///
/// `Value`'s `Display` is serde_json's own compact serializer, so this is
/// `serde_json::to_string` without the `Result` that cannot fire for a
/// `Value` that is already in hand.
///
/// STABILITY RESTS ON TWO SERDE_JSON DEFAULTS, and Cargo features are additive
/// across the whole dependency graph, so a crate elsewhere enabling either
/// would change this build silently:
///
/// - `preserve_order` swaps `Map`'s `BTreeMap` for an `IndexMap`, making key
///   order insertion-dependent, so two devices that built the same record by
///   different routes would compute different strings;
/// - `arbitrary_precision` turns `Number` into a text-preserving wrapper, so
///   `1` and `1.0` stop unifying. `HostGroup.order` in
///   `src/modules/hosts/types.ts` is a `number`, so a float does reach a
///   synced record.
///
/// Neither is enabled on this branch, and [`canonical_is_sorted_and_numeric`]
/// is what notices if that changes.
///
/// BENIGN RESIDUE, named so the next reader does not mistake it for a bug: a
/// field present as `null` and a field absent canonicalize differently, and a
/// `Value` parsed out of remote ciphertext took a different path than one
/// built from the local store file. Two devices can therefore see a "content
/// difference" that is serialization noise. It still converges - both sides
/// compute the SAME key from the same pair - so all it does is make the
/// tie-break jitter.
///
/// Non-finite floats need no guard: `Number::from_f64` rejects them and JSON
/// has no NaN literal, so no `Value` can hold one.
fn canonical(v: &Value) -> String {
    v.to_string()
}

/// A tombstone's `record` is `Null`, whatever arrived in it.
///
/// Run BEFORE the ordering key is computed, not after. A tombstone can arrive
/// carrying a junk record, and normalizing afterwards would let that junk into
/// the key - harmless today, since `deleted` is compared first, but it would
/// stop the key being a function of the envelope's MEANING.
fn normalize(e: &mut Envelope) {
    if e.deleted {
        e.record = Value::Null;
    }
}

/// What decides the winner, derived from CONTENT ALONE.
///
/// That is what makes the merge commutative by construction: two devices
/// running it locally on the same pair compare the same four values in the
/// same order and cannot disagree.
///
/// - `updated_at` first. `Option<u64>` already orders `None` below any `Some`,
///   which is exactly the wanted behaviour for an unstamped record.
/// - `deleted` breaks an exact timestamp tie in favour of the DELETE: a lost
///   delete re-spreads data the user removed, while a lost resurrection costs
///   one re-create.
/// - the canonical record breaks what is left of the tie.
/// - the canonical SECRETS breaks what is left after that, as an
///   `Option<String>` so `None < Some` gives present-beats-absent for free.
///
/// SECRETS HAS TO BE IN HERE, and presence alone is not enough. [`merge`]
/// reads the winner's `secrets`, so leaving it out would make `Equal`
/// reachable between two envelopes the merge treats DIFFERENTLY, and each
/// device would then keep its own copy permanently. The live case is the
/// steady state, not an exotic tie: carrying is a per-device opt-in, so a
/// device with it on pushes `{record: X, updatedAt: T, secrets: {..}}` while a
/// device that pulled X and never edited it pushes
/// `{record: X, updatedAt: T}`: same stamp, same `deleted`, byte-identical
/// record. Comparing presence alone leaves the identical hole one level down,
/// between two envelopes that both carry bodies that differ, which is why the
/// component is the canonical string rather than the flag.
///
/// With it in place, `Equal` means the two envelopes agree on every field the
/// merge reads. The one field outside this key is `device`, which nothing
/// reads.
///
/// DEVICE IS DELIBERATELY NOT IN HERE. No record carries a `device` field, so
/// the only place one can be stamped is when the envelope is built, at push
/// time. A record pulled from A and pushed back unedited by B would come back
/// stamped `device: "B"`, so the key would not be a function of the record and
/// the merge would not be idempotent under re-push: identical content,
/// different key. A lexicographic content tie-break is exactly as arbitrary as
/// a device-id one and has none of that.
fn ordering_key(e: &Envelope) -> (Option<u64>, bool, String, Option<String>) {
    (
        e.updated_at,
        e.deleted,
        canonical(&e.record),
        e.secrets.as_ref().map(canonical),
    )
}

/// The part of an envelope a STORE holds: the stamp, the delete, the record.
///
/// [`ordering_key`] minus `secrets`, which is the keychain's half and is
/// compared separately - see [`Merged::changed`] for why the two cannot be one
/// flag.
fn store_key(e: &Envelope) -> (Option<u64>, bool, String) {
    (e.updated_at, e.deleted, canonical(&e.record))
}

/// Whether two envelopes say anything different at all, `device` excluded.
///
/// The question a PUSH has to answer - "does the remote object already hold
/// this?" - and the reason it is not [`Merged::winner`]: a REMOTE win can still
/// differ from the remote copy, because the two vault exceptions in [`merge`]
/// mutate the winner after the side is decided. A caller reading the side
/// instead would leave an `encrypted` backfill on this device and never
/// publish it.
///
/// `device` is excluded for the reason it is outside [`ordering_key`]: it
/// always differs between two devices, so including it would make this `true`
/// for every pair and every pull would republish the whole inventory.
pub fn content_differs(a: &Envelope, b: &Envelope) -> bool {
    ordering_key(a) != ordering_key(b)
}

/// Is this record's own claim that it has a private key body?
fn claims_private_key(record: &Value) -> bool {
    record.get("hasPrivateKey") == Some(&Value::Bool(true))
}

/// Resolve one record's two copies.
///
/// Refuses before it compares anything - see [`MergeError`] for each refusal
/// and why it is one. After the identity check the two `kind`s are equal, so
/// the vault exceptions below have only one `kind` to read.
///
/// Then: normalize, compare [`ordering_key`], take the winner whole, and apply
/// the two vault exceptions. An `Equal` key resolves to LOCAL, which is
/// arbitrary only in the sense that the two envelopes are then identical on
/// everything read here.
///
/// SECRETS NEVER MERGES. The winner's is the result, absent included; the
/// loser's is discarded with the rest of the loser. The live case is lossy and
/// silent - the winner pushed with carrying off and has none, the loser
/// carries a `privateKey`, and that body is dropped - and that IS the correct
/// outcome, because a secret must not ride a record it did not come with. It
/// is written down because it has to be a rule with a test behind it rather
/// than a side effect of cloning the winner.
pub fn merge(local: &Envelope, remote: &Envelope) -> Result<Merged, MergeError> {
    for e in [local, remote] {
        if e.v != WIRE_VERSION {
            return Err(MergeError::Version {
                found: e.v,
                expected: WIRE_VERSION,
            });
        }
    }
    if local.kind != remote.kind || local.id != remote.id {
        return Err(MergeError::IdentityMismatch);
    }
    for e in [local, remote] {
        if e.deleted && e.updated_at.is_none() {
            return Err(MergeError::UnstampedTombstone);
        }
        if !e.deleted && e.record.is_null() {
            return Err(MergeError::NullLiveRecord);
        }
    }

    let mut l = local.clone();
    let mut r = remote.clone();
    normalize(&mut l);
    normalize(&mut r);

    // Taken BEFORE the winner is chosen, because `l` is moved into it on a
    // local win and the two flags below have to compare against the local copy
    // as it arrived, not against the copy the vault exceptions then mutated.
    let local_store = store_key(&l);
    let local_secrets = l.secrets.clone();

    let (winner_side, mut winner, loser) = if ordering_key(&r) > ordering_key(&l) {
        (Side::Remote, r, l)
    } else {
        (Side::Local, l, r)
    };

    if winner.kind == KEY_KIND && !winner.deleted {
        // ENCRYPTED: any inspected value beats absent, and two inspected
        // values go last-write-wins - which is what the comparison above
        // already did, so all that is left here is the backfill.
        //
        // `false` is a real inspection for the same reason `true` is: its doc
        // comment in `src/modules/vault/types.ts` calls it "the stronger claim
        // that something looked and the body is not encrypted". Strict
        // monotonicity was rejected because its failure mode is a one-way
        // door: a genuine true-to-false, where the user replaces an encrypted
        // body with a plaintext one, would never propagate, `keyNeedsPassphrase`
        // in `src/modules/vault/refs.ts` would answer yes forever, and the only
        // repair would be deleting and recreating the key. Last-write-wins
        // fails the other way and is recoverable: the next inspection on any
        // device writes a newer stamp and wins.
        //
        // RESIDUE, named and not solved: this copies a claim about the LOSER's
        // body onto the winner's record, and if the two describe different
        // bodies the claim is wrong. Strict monotonicity has the identical
        // hole. No rule available at this layer closes it, because the layer
        // cannot see either body.
        if claims_private_key(&winner.record) && winner.record.get("encrypted").is_none() {
            let from_loser = loser.record.get("encrypted").cloned();
            if let (Some(answer), Some(obj)) = (from_loser, winner.record.as_object_mut()) {
                obj.insert("encrypted".into(), answer);
            }
        }

        // FINGERPRINT: dropped when the winner's OWN record claims no body,
        // and never copied from the loser.
        //
        // Gated on `hasPrivateKey` rather than on the envelope's `secrets`,
        // and the difference is not academic: carrying secrets is off by
        // default, so a `secrets` gate would fire on every key merge on every
        // device, strip the field from records whose body sits in the local
        // keychain, and push that loss everywhere. The fingerprint is of the
        // PUBLIC half, which rides inside `record` on every envelope, so it
        // always describes something present.
        //
        // Re-deriving a fingerprint from a body the local keychain holds is
        // the apply path's job, not this one's - this layer has no keychain.
        //
        // EXCEPT `kind: "hardware"` (`VaultKeyKind` in
        // `src/modules/vault/types.ts`), which never claims a body at all -
        // `hasPrivateKey` is permanently `false` for it by design. There the
        // fingerprint names an ssh-agent IDENTITY, not a keychain body the
        // "could describe a body nobody holds" argument is about, and it is
        // the record's only identifying fact: strip it and nothing on any
        // device can put it back (`rederive` in `src/modules/sync/scheduler.ts`
        // restores a fingerprint from a keychain read, and a hardware key has
        // no keychain account to read).
        let hardware = winner.record.get("kind").and_then(Value::as_str) == Some("hardware");
        if !claims_private_key(&winner.record) && !hardware {
            if let Some(obj) = winner.record.as_object_mut() {
                obj.remove("fingerprint");
            }
        }
    }

    let changed = store_key(&winner) != local_store;
    let secrets_changed = winner.secrets != local_secrets;

    Ok(Merged {
        winner: winner_side,
        envelope: winner,
        changed,
        secrets_changed,
    })
}

/// Remove every field that describes this machine rather than the record.
///
/// Called on the record before it is put in an [`Envelope`], so what travels
/// is already stripped and no reader has to remember to do it.
pub fn strip_device_local(record: &mut Value) {
    let Some(obj) = record.as_object_mut() else {
        return;
    };
    for field in DEVICE_LOCAL_FIELDS {
        obj.remove(field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(kind: &str, id: &str, updated_at: Option<u64>, record: Value) -> Envelope {
        Envelope {
            v: WIRE_VERSION,
            kind: kind.into(),
            id: id.into(),
            updated_at,
            device: "dev-a".into(),
            deleted: false,
            record,
            secrets: None,
        }
    }

    fn host(updated_at: Option<u64>, name: &str) -> Envelope {
        env(
            "host",
            "h-1",
            updated_at,
            json!({"id": "h-1", "name": name}),
        )
    }

    fn tombstone(kind: &str, id: &str, deleted_at: u64) -> Envelope {
        Envelope {
            deleted: true,
            record: Value::Null,
            ..env(kind, id, Some(deleted_at), Value::Null)
        }
    }

    /// Both argument orders of one pair must resolve to the same record. This
    /// is the property that makes the merge safe to run independently on two
    /// devices, so nearly every ordering test below asserts it.
    ///
    /// THE TWO SIDES ARE STAMPED WITH DIFFERENT DEVICE IDS HERE, rather than
    /// taken as the fixtures left them. In production the one field that
    /// always differs between two copies of a record is `device`, and a helper
    /// that compared whole envelopes would pass only because every fixture in
    /// this file happened to share one id - which is the shape of an assertion
    /// that cannot fail.
    ///
    /// So `device` is excluded from the comparison, and that exclusion is the
    /// property rather than a weakening of it: `device` is deliberately
    /// outside the ordering key, so on a tie each side keeps its own and the
    /// two orders CANNOT agree on it. If `device` ever crept into the key,
    /// these differing ids would make the winner flip with the argument order
    /// and every caller below would fail on the fields that are compared.
    fn agrees_both_ways(a: &Envelope, b: &Envelope) -> Envelope {
        let a = Envelope {
            device: "dev-a".into(),
            ..a.clone()
        };
        let b = Envelope {
            device: "dev-b".into(),
            ..b.clone()
        };
        let one = merge(&a, &b).expect("merge a,b").envelope;
        let two = merge(&b, &a).expect("merge b,a").envelope;
        assert_eq!(
            Envelope {
                device: String::new(),
                ..one.clone()
            },
            Envelope {
                device: String::new(),
                ..two
            },
            "the two argument orders disagreed"
        );
        one
    }

    // --- refusals ---------------------------------------------------------

    #[test]
    fn an_unknown_wire_version_is_refused_on_either_side() {
        let good = host(Some(2), "a");
        let mut bad = host(Some(3), "b");
        bad.v = WIRE_VERSION + 1;
        let expected = MergeError::Version {
            found: WIRE_VERSION + 1,
            expected: WIRE_VERSION,
        };
        assert_eq!(merge(&bad, &good), Err(expected.clone()));
        assert_eq!(merge(&good, &bad), Err(expected));
    }

    #[test]
    fn two_sides_naming_different_records_are_refused() {
        // Both halves of the identity: an object name is derived from `kind`
        // AND `id`, so either one disagreeing means the object was overwritten
        // by a different record.
        let a = host(Some(1), "a");
        let mut other_kind = a.clone();
        other_kind.kind = "group".into();
        assert_eq!(merge(&a, &other_kind), Err(MergeError::IdentityMismatch));

        let mut other_id = a.clone();
        other_id.id = "h-2".into();
        assert_eq!(merge(&a, &other_id), Err(MergeError::IdentityMismatch));
    }

    #[test]
    fn a_tombstone_with_no_stamp_is_refused_in_either_position() {
        let live = host(Some(5), "a");
        let mut stampless = tombstone("host", "h-1", 1);
        stampless.updated_at = None;
        assert_eq!(
            merge(&stampless, &live),
            Err(MergeError::UnstampedTombstone)
        );
        assert_eq!(
            merge(&live, &stampless),
            Err(MergeError::UnstampedTombstone)
        );
    }

    #[test]
    fn a_live_envelope_with_a_null_record_is_refused_in_either_position() {
        let live = host(Some(5), "a");
        let null_live = env("host", "h-1", Some(9), Value::Null);
        assert_eq!(merge(&null_live, &live), Err(MergeError::NullLiveRecord));
        assert_eq!(merge(&live, &null_live), Err(MergeError::NullLiveRecord));
    }

    // --- ordering ---------------------------------------------------------

    #[test]
    fn the_newer_stamp_wins_from_either_side() {
        let older = host(Some(10), "older");
        let newer = host(Some(20), "newer");

        let local_newer = merge(&newer, &older).unwrap();
        assert_eq!(local_newer.winner, Side::Local);
        assert_eq!(local_newer.envelope.record["name"], "newer");

        let remote_newer = merge(&older, &newer).unwrap();
        assert_eq!(remote_newer.winner, Side::Remote);
        assert_eq!(remote_newer.envelope.record["name"], "newer");
    }

    #[test]
    fn an_unstamped_record_loses_to_any_stamp() {
        // Absent is not zero: a record written before the field existed must
        // never outrank a real stamp, in either argument position.
        let unstamped = host(None, "legacy");
        let stamped = host(Some(1), "stamped");
        assert_eq!(
            agrees_both_ways(&unstamped, &stamped).record["name"],
            "stamped"
        );

        // And two unstamped records still resolve identically both ways,
        // through `deleted` and the canonical strings - there is no stamp left
        // to break the tie with.
        agrees_both_ways(&unstamped, &host(None, "also-legacy"));
    }

    #[test]
    fn an_exact_tie_on_different_records_resolves_the_same_way_every_time() {
        let a = host(Some(7), "alpha");
        let b = host(Some(7), "beta");
        let first = agrees_both_ways(&a, &b);
        let again = agrees_both_ways(&a, &b);
        assert_eq!(
            first, again,
            "the same pair resolved differently on a rerun"
        );
    }

    #[test]
    fn an_exact_tie_between_a_delete_and_an_edit_goes_to_the_delete() {
        // The conservative side: a lost delete re-spreads data the user
        // removed, a lost resurrection costs one re-create.
        let live = host(Some(42), "still here");
        let gone = tombstone("host", "h-1", 42);
        assert!(agrees_both_ways(&live, &gone).deleted);
    }

    #[test]
    fn a_newer_tombstone_wins_and_carries_no_record() {
        // The inbound tombstone carries junk, which also proves the
        // normalization to Null happens BEFORE the ordering key is computed:
        // if it happened after, this junk would be in the key.
        let mut junk = tombstone("host", "h-1", 99);
        junk.record = json!({"id": "h-1", "name": "junk that should not travel"});
        let live = host(Some(1), "local");

        let merged = merge(&live, &junk).unwrap();
        assert_eq!(merged.winner, Side::Remote);
        assert!(merged.envelope.deleted);
        assert_eq!(merged.envelope.record, Value::Null);
    }

    #[test]
    fn an_older_tombstone_does_not_resurrect_itself_over_a_newer_edit() {
        let live = host(Some(100), "edited after the delete");
        let stale = tombstone("host", "h-1", 50);
        let merged = merge(&live, &stale).unwrap();
        assert_eq!(merged.winner, Side::Local);
        assert!(!merged.envelope.deleted);
        assert_eq!(merged.envelope.record["name"], "edited after the delete");
    }

    // --- the two vault exceptions -----------------------------------------

    fn key_env(updated_at: u64, record: Value) -> Envelope {
        env("key", "k-1", Some(updated_at), record)
    }

    #[test]
    fn an_inspected_encrypted_answer_survives_a_newer_envelope_that_has_none() {
        for answer in [json!(true), json!(false)] {
            let older = key_env(
                1,
                json!({"id": "k-1", "hasPrivateKey": true, "encrypted": answer}),
            );
            let newer = key_env(2, json!({"id": "k-1", "hasPrivateKey": true}));
            let merged = merge(&newer, &older).unwrap();
            assert_eq!(merged.envelope.record["encrypted"], answer);
        }
    }

    #[test]
    fn a_newer_false_beats_an_older_true() {
        // Last-write-wins between two present values, not monotonicity. The
        // rejected rule makes a genuine true-to-false unrepairable.
        let older = key_env(
            1,
            json!({"id": "k-1", "hasPrivateKey": true, "encrypted": true}),
        );
        let newer = key_env(
            2,
            json!({"id": "k-1", "hasPrivateKey": true, "encrypted": false}),
        );
        let merged = merge(&newer, &older).unwrap();
        assert_eq!(merged.envelope.record["encrypted"], json!(false));
    }

    #[test]
    fn encrypted_is_not_backfilled_onto_a_record_claiming_no_body() {
        // A claim about a body on a record that says it has none is the same
        // kind of lie the fingerprint rule below removes.
        let older = key_env(
            1,
            json!({"id": "k-1", "hasPrivateKey": true, "encrypted": true}),
        );
        let newer = key_env(2, json!({"id": "k-1", "hasPrivateKey": false}));
        let merged = merge(&newer, &older).unwrap();
        assert!(merged.envelope.record.get("encrypted").is_none());
    }

    #[test]
    fn a_fingerprint_is_dropped_when_the_winners_own_record_claims_no_body() {
        for claim in [json!({"hasPrivateKey": false}), json!({})] {
            let mut record = json!({"id": "k-1", "fingerprint": "SHA256:aaa"});
            let obj = record.as_object_mut().unwrap();
            for (k, v) in claim.as_object().unwrap() {
                obj.insert(k.clone(), v.clone());
            }
            let winner = key_env(2, record);
            let loser = key_env(1, json!({"id": "k-1", "hasPrivateKey": true}));
            let merged = merge(&winner, &loser).unwrap();
            assert!(
                merged.envelope.record.get("fingerprint").is_none(),
                "kept a fingerprint on a record claiming no body"
            );
        }
    }

    #[test]
    fn a_hardware_keys_fingerprint_survives_a_merge_even_though_it_claims_no_body() {
        // The one exception: `hasPrivateKey` is permanently `false` for a
        // `kind: "hardware"` key by design (`VaultKeyKind` in
        // `src/modules/vault/types.ts`), so the rule above would otherwise
        // strip its only identifying fact on the very first sync round trip,
        // with nothing anywhere able to put it back.
        let winner = key_env(
            2,
            json!({"id": "k-1", "kind": "hardware", "hasPrivateKey": false, "fingerprint": "SHA256:hw"}),
        );
        let loser = key_env(1, json!({"id": "k-1", "kind": "hardware", "hasPrivateKey": false}));
        let merged = merge(&winner, &loser).unwrap();
        assert_eq!(merged.envelope.record["fingerprint"], "SHA256:hw");
    }

    #[test]
    fn a_fingerprint_is_kept_when_the_record_claims_a_body() {
        // The failure this guards: gating on the envelope's `secrets` instead
        // would strip this on every device, since carrying secrets is off by
        // default.
        let winner = key_env(
            2,
            json!({"id": "k-1", "hasPrivateKey": true, "fingerprint": "SHA256:aaa"}),
        );
        let loser = key_env(1, json!({"id": "k-1", "hasPrivateKey": true}));
        let merged = merge(&winner, &loser).unwrap();
        assert_eq!(merged.envelope.record["fingerprint"], "SHA256:aaa");
    }

    #[test]
    fn a_fingerprint_is_never_copied_from_the_loser() {
        let winner = key_env(2, json!({"id": "k-1", "hasPrivateKey": true}));
        let loser = key_env(
            1,
            json!({"id": "k-1", "hasPrivateKey": true, "fingerprint": "SHA256:bbb"}),
        );
        let merged = merge(&winner, &loser).unwrap();
        assert!(merged.envelope.record.get("fingerprint").is_none());
    }

    // --- the two dirty flags ----------------------------------------------

    /// One pair, stamped with the two device ids production always differs on.
    ///
    /// EVERY case below goes through here rather than through the fixtures as
    /// they are written. `device` is the one field two copies of a record
    /// always disagree about, so a `changed` built on whole-envelope equality
    /// passes every test whose fixtures happen to share one id, and fails on
    /// the first real pull.
    fn two_devices(local: &Envelope, remote: &Envelope) -> Merged {
        let local = Envelope {
            device: "dev-a".into(),
            ..local.clone()
        };
        let remote = Envelope {
            device: "dev-b".into(),
            ..remote.clone()
        };
        merge(&local, &remote).expect("merge")
    }

    #[test]
    fn a_local_win_that_stripped_a_fingerprint_is_still_changed() {
        // The case `Merged`'s doc names first: the vault exceptions run AFTER
        // the side is decided, so a LOCAL win can still differ from what is
        // stored. A caller skipping the write on `Side::Local` drops this.
        let local = key_env(
            2,
            json!({"id": "k-1", "hasPrivateKey": false, "fingerprint": "SHA256:aaa"}),
        );
        let remote = key_env(1, json!({"id": "k-1", "hasPrivateKey": true}));
        let merged = two_devices(&local, &remote);
        assert_eq!(merged.winner, Side::Local);
        assert!(merged.envelope.record.get("fingerprint").is_none());
        assert!(merged.changed, "the stripped fingerprint was not noticed");
        assert!(!merged.secrets_changed);
    }

    #[test]
    fn a_remote_win_that_matches_after_the_backfill_is_not_changed() {
        // The fixed point the same doc names second: the bare remote copy sorts
        // above the backfilled local one on an exact stamp tie, wins every
        // pull, and is re-backfilled to the content already stored. The side is
        // `Remote` forever; the content never moves. A caller writing on
        // `Side::Remote` rewrites the vault file on every focus.
        let local = key_env(
            2,
            json!({"id": "k-1", "hasPrivateKey": true, "encrypted": true}),
        );
        let remote = key_env(2, json!({"id": "k-1", "hasPrivateKey": true}));
        let merged = two_devices(&local, &remote);
        assert_eq!(merged.winner, Side::Remote);
        assert_eq!(merged.envelope.record, local.record);
        assert!(!merged.changed, "a fixed point reported as a change");
    }

    #[test]
    fn two_sides_differing_only_in_secrets_change_the_keychain_and_not_the_store() {
        // The steady state of one device opting into carrying, and the
        // regression case for a `changed` built on `ordering_key`: that one
        // reads `secrets`, so this pair would rewrite the whole store on every
        // pull for a difference that belongs entirely to the keychain.
        let plain = json!({"id": "k-1", "hasPrivateKey": true});
        let local = key_env(2, plain.clone());
        let mut remote = key_env(2, plain);
        remote.secrets = Some(json!({"privateKey": "BODY"}));

        let merged = two_devices(&local, &remote);
        assert!(
            !merged.changed,
            "a secrets-only difference touched the store"
        );
        assert!(merged.secrets_changed, "the carried body was not noticed");
        assert_eq!(merged.envelope.secrets, remote.secrets);
    }

    #[test]
    fn content_differs_reads_everything_except_the_device() {
        // What a push asks before it re-uploads. The `device` clause is the
        // load-bearing one: without it every pair differs and every pull
        // republishes the whole inventory.
        let a = host(Some(5), "same");
        let b = Envelope {
            device: "dev-b".into(),
            ..a.clone()
        };
        assert!(!content_differs(&a, &b), "the device id was compared");
        assert!(content_differs(&a, &host(Some(6), "same")));
        assert!(content_differs(&a, &host(Some(5), "other")));

        // And `secrets` IS compared here, unlike in `changed`: the remote
        // object holds the body, so a winner that gained one has to be
        // re-uploaded.
        let mut carrying = a.clone();
        carrying.secrets = Some(json!({"privateKey": "BODY"}));
        assert!(content_differs(&a, &carrying));
    }

    // --- shape ------------------------------------------------------------

    #[test]
    fn canonical_is_sorted_and_numeric() {
        // One line covering all three hazards the ordering key depends on:
        // nested map ordering, top-level key ordering, and number
        // normalization - the last of which is what `arbitrary_precision`
        // would break, and the first two `preserve_order`.
        let v: Value = serde_json::from_str(r#"{"b":1.0,"a":{"d":1,"c":1e3}}"#).unwrap();
        assert_eq!(canonical(&v), r#"{"a":{"c":1000.0,"d":1},"b":1.0}"#);
    }

    #[test]
    fn an_envelope_round_trips_and_the_version_is_a_plain_number() {
        // Both `None` and `Some` for the two skipped fields, or
        // `skip_serializing_if` goes untested.
        let absent = env("group", "g-1", None, json!({"id": "g-1", "name": "prod"}));
        let json_text = serde_json::to_string(&absent).unwrap();
        assert!(json_text.contains(r#""v":1"#), "unexpected: {json_text}");
        assert!(!json_text.contains("updatedAt"), "unexpected: {json_text}");
        assert!(!json_text.contains("secrets"), "unexpected: {json_text}");
        assert_eq!(
            serde_json::from_str::<Envelope>(&json_text).unwrap(),
            absent
        );

        let present = Envelope {
            updated_at: Some(1),
            secrets: Some(json!({"privateKey": "BODY"})),
            ..absent
        };
        let json_text = serde_json::to_string(&present).unwrap();
        assert!(
            json_text.contains(r#""updatedAt":1"#),
            "unexpected: {json_text}"
        );
        assert_eq!(
            serde_json::from_str::<Envelope>(&json_text).unwrap(),
            present
        );
    }

    #[test]
    fn a_field_this_module_has_no_rules_for_survives_the_whole_trip() {
        // `groupId` is never named in this module outside this fixture, which
        // is what makes the record opaque by construction rather than by
        // discipline. The value is deliberately shaped like something a later
        // build might mean something by.
        let record = json!({"id": "h-1", "groupId": "g-1/g-2/g-3", "name": "n"});
        let sent = serde_json::to_string(&env("host", "h-1", Some(5), record.clone())).unwrap();
        let received: Envelope = serde_json::from_str(&sent).unwrap();
        let merged = merge(&received, &host(Some(1), "older")).unwrap();
        assert_eq!(merged.envelope.record["groupId"], "g-1/g-2/g-3");
        assert_eq!(serde_json::to_string(&merged.envelope).unwrap(), sent);
    }

    #[test]
    fn a_group_default_identity_field_survives_the_whole_trip() {
        // `defaultIdentityId` (a per-group default vault identity) is never
        // named in this module either, on the same "opaque by construction"
        // terms as `groupId` above - a
        // "group" kind record round-trips it unchanged, merges by the same
        // last-write-wins rule, and this module never validates that the id it
        // names still exists on either device.
        let record = json!({"id": "g-1", "name": "n", "defaultIdentityId": "i-1"});
        let sent = serde_json::to_string(&env("group", "g-1", Some(5), record.clone())).unwrap();
        let received: Envelope = serde_json::from_str(&sent).unwrap();
        let older = env(
            "group",
            "g-1",
            Some(1),
            json!({"id": "g-1", "name": "older"}),
        );
        let merged = merge(&received, &older).unwrap();
        assert_eq!(merged.envelope.record["defaultIdentityId"], "i-1");
        assert_eq!(serde_json::to_string(&merged.envelope).unwrap(), sent);
    }

    #[test]
    fn strip_removes_exactly_the_four_device_local_fields() {
        let mut record = json!({
            "id": "h-1",
            "name": "vps",
            "host": "example.com",
            "port": 22,
            "groupId": "g-1",
            "description": "notes",
            "updatedAt": 5,
            "protocol": "ssh",
            "credential": {"kind": "inline", "hostId": "h-1", "user": "root"},
            "proxyJumpId": "h-2",
            "desktopWidth": 1600,
            "desktopHeight": 900,
            "sizeMode": "preset",
            "tunnel": {"sshHostId": "h-3"},
            "pins": {"example.com": "SHA256:aaa"},
            "lastConnectedAt": 1700,
            "lastFingerprint": "SHA256:aaa",
            "certFingerprint": "SHA256:bbb"
        });
        // SPELLED OUT, not read back out of `DEVICE_LOCAL_FIELDS`. Iterating
        // the same constant the implementation iterates is an assertion that
        // cannot fail: a typo in the constant would remove nothing, the
        // mistyped name would drop out of the skip-list below, and the test
        // would confirm that the field it no longer strips is still present.
        // These four literals are what a rename in
        // `src/modules/hosts/types.ts` has to break.
        let expected_gone = [
            "pins",
            "lastConnectedAt",
            "lastFingerprint",
            "certFingerprint",
        ];
        assert_eq!(
            expected_gone.len(),
            DEVICE_LOCAL_FIELDS.len(),
            "the strip list grew or shrank without this test noticing"
        );

        let before = record.clone();
        strip_device_local(&mut record);

        for gone in expected_gone {
            assert!(
                before.get(gone).is_some(),
                "{gone} is missing from the fixture"
            );
            assert!(record.get(gone).is_none(), "{gone} survived the strip");
        }
        for (field, value) in before.as_object().unwrap() {
            if expected_gone.contains(&field.as_str()) {
                continue;
            }
            assert_eq!(record.get(field), Some(value), "{field} was disturbed");
        }
    }

    #[test]
    fn strip_leaves_a_non_object_record_alone() {
        let mut record = Value::Null;
        strip_device_local(&mut record);
        assert_eq!(record, Value::Null);
    }

    #[test]
    fn secrets_never_merge() {
        let body = json!({"privateKey": "BODY"});
        let plain = json!({"id": "k-1", "hasPrivateKey": true});

        // The lossy-but-correct case: the winner carried no body, so no body
        // travels, even though the loser had one.
        let winner = key_env(2, plain.clone());
        let mut loser = key_env(1, plain.clone());
        loser.secrets = Some(body.clone());
        assert!(merge(&winner, &loser).unwrap().envelope.secrets.is_none());

        // And the other direction: the winner's body rides along.
        let mut winner = key_env(2, plain.clone());
        winner.secrets = Some(body.clone());
        let loser = key_env(1, plain.clone());
        assert_eq!(
            merge(&winner, &loser).unwrap().envelope.secrets,
            Some(body.clone())
        );
    }

    #[test]
    fn two_envelopes_differing_only_in_secrets_still_agree_both_ways() {
        // Without `secrets` in the ordering key these compare Equal while the
        // merge treats them differently, so each device keeps its own copy
        // forever. This is the steady state of one device opting into
        // carrying, not an exotic tie.
        let plain = json!({"id": "k-1", "hasPrivateKey": true});
        let bare = key_env(2, plain.clone());
        let mut carrying = key_env(2, plain.clone());
        carrying.secrets = Some(json!({"privateKey": "BODY"}));
        assert_eq!(
            agrees_both_ways(&bare, &carrying).secrets,
            Some(json!({"privateKey": "BODY"})),
            "present must beat absent"
        );

        // One level down: two envelopes that BOTH carry, with different
        // bodies. Presence alone would leave this hole open.
        let mut other = key_env(2, plain);
        other.secrets = Some(json!({"privateKey": "OTHER"}));
        agrees_both_ways(&carrying, &other);
    }
}
