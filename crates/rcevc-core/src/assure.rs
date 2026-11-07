//! Boundary between immutable bytes and a checked action result.
//!
//! [`crate::repo::Repo::submit`] stays the admission transition. Its
//! [`crate::repo::Receipt`] and [`crate::repo::Refusal`] stay the log record.
//! This module does not define another receipt schema and it does not decide
//! admission. It answers a narrower question: may a caller treat some stored
//! bytes as the result of a particular action, on a particular head, under a
//! particular gate?
//!
//! # Threat model
//!
//! Trusted, inside this process only:
//! - the gate installed on a [`Repo`] (its [`crate::gate::Gate::digest`] is the checker
//!   identity; there is no signature and no remote authenticator);
//! - [`bind_repo_outcome`], which mints a [`CheckedAction`] only when that
//!   repository's log already contains the outcome;
//! - [`ActionCache::insert`] and [`ActionCache::insert_combined`], which
//!   accept only a [`CheckedAction`].
//!
//! Untrusted:
//! - the `writer` label on a [`Change`];
//! - any bytes put into a [`ContentStore`], including a correct blob;
//! - rows inserted by [`ActionCache::plant_untrusted`] or
//!   [`ActionCache::plant_combined_untrusted`];
//! - a claim that several individually checked changes compose, until
//!   [`ActionCache::insert_combined`] has seen that sequence in one log.
//!
//! A content digest proves that the bytes are the bytes. It does not prove
//! that an action produced them. A compare-and-swap ref update
//! ([`CasRef`]) proves that this op id moved the ref from an expected tip,
//! or that a retry of that same op id observed the tip it wrote. It does not
//! prove that the target digest is a gate-accepted state.
//!
//! # Not claimed
//!
//! No signatures, no SLSA level, no hardware isolation, no remote cache, and
//! no joule measurement. [`PhysicalEnergy::unknown`] is what this process can
//! say about electricity. [`PhysicalEnergy::not_from_semantic_fuel`] discards
//! a stated `est_uj` rather than converting it. Absence of a meter is not
//! zero.
//!
//! The in-repository conflict signature ([`crate::repo::conflict_signature`])
//! is unchanged. It is an index inside one repository, not this cache.

use std::collections::BTreeMap;

use crate::change::Change;
use crate::hash::{Digest, Enc, sha256};
use crate::repo::{Outcome, Repo};

/// Electricity, when this process has no meter.
///
/// The only constructor that this crate offers is the unknown reading.
/// A stated semantic cost is not a joule reading, and unknown is not zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhysicalEnergy {
    /// No meter sample was taken.
    Unknown {
        /// Why no number is available.
        reason: &'static str,
    },
}

impl PhysicalEnergy {
    /// No hardware energy meter is attached to this process.
    pub fn unknown() -> Self {
        PhysicalEnergy::Unknown {
            reason: "no hardware energy meter in this process",
        }
    }

    /// Discard a stated semantic cost. The result is [`PhysicalEnergy::unknown`],
    /// including when `est_uj` is zero.
    pub fn not_from_semantic_fuel(_est_uj: u64) -> Self {
        Self::unknown()
    }
}

/// Why an assurance check refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssureError {
    /// The outcome is not an entry in this repository's log.
    NotLogged,
    /// The claimed change, base, members, or output binding does not match
    /// the logged outcome.
    ForgedBinding,
    /// A row for this action already names a different output.
    ForgedMapping,
    /// The output digest is not in the content store.
    MissingOutput,
    /// The stored bytes do not hash to the claimed digest.
    CorruptOutput,
    /// The stored bytes are a proper prefix of the outcome image.
    TruncatedImage,
    /// The row was planted and was not minted by [`bind_repo_outcome`].
    UntrustedInsert,
    /// The dependency manifest does not declare a complete set.
    IncompleteDependencies,
    /// An accept was offered for a base this repository has not held.
    UnknownBase,
    /// The row was checked at `recorded`, and the caller asked about `current`.
    StaleHead {
        /// Head stored on the row.
        recorded: Digest,
        /// Head the caller asked to apply the row to.
        current: Digest,
    },
    /// The row was checked under `recorded`, and the caller asked under `current`.
    GateMismatch {
        /// Gate stored on the row.
        recorded: Digest,
        /// Gate the caller asked to apply the row under.
        current: Digest,
    },
    /// Individual rows do not discharge a combined sequence.
    UncheckedComposition,
    /// A combined sequence needs two or more changes.
    NotACombination,
    /// The row is a refusal, and the caller asked for an accept.
    NotAccept,
}

impl std::fmt::Display for AssureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AssureError {}

/// What a checked action decided. This is not a receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The logged outcome admitted `post`.
    Accept {
        /// Post-state root from the logged receipt.
        post: Digest,
    },
    /// The logged outcome refused.
    Refuse,
}

/// Declared dependency names. An incomplete manifest cannot mint a checked action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyManifest {
    digest: Digest,
    complete: bool,
}

impl DependencyManifest {
    /// Canonical digest of a complete name list. Order and duplicate names do
    /// not change the digest. This is a declaration by the checker, not a
    /// discovered toolchain closure.
    pub fn complete(entries: &[&str]) -> Self {
        let mut names: Vec<&str> = entries.to_vec();
        names.sort_unstable();
        names.dedup();
        let mut e = Enc::new("rcevc/deps/v1");
        e.u64(names.len() as u64);
        for n in names {
            e.str(n);
        }
        DependencyManifest {
            digest: e.finish(),
            complete: true,
        }
    }

    /// A manifest the checker knows is not a full closure.
    pub fn incomplete() -> Self {
        let e = Enc::new("rcevc/deps-incomplete/v1");
        DependencyManifest {
            digest: e.finish(),
            complete: false,
        }
    }

    /// Digest of the declaration.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Whether [`bind_repo_outcome`] may use this declaration.
    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Immutable bytes addressed by their SHA-256 digest.
///
/// Putting bytes here does not record an action. [`ContentStore::plant_unverified`]
/// is an adversary hook: it stores bytes under a digest the caller chooses.
#[derive(Clone, Debug, Default)]
pub struct ContentStore {
    blobs: BTreeMap<Digest, Vec<u8>>,
}

impl ContentStore {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            blobs: BTreeMap::new(),
        }
    }

    /// Store `bytes` under [`sha256`] of those bytes.
    pub fn put(&mut self, bytes: &[u8]) -> Digest {
        let digest = sha256(bytes);
        self.blobs.insert(digest, bytes.to_vec());
        digest
    }

    /// Return the bytes only when they hash to `digest`.
    pub fn get(&self, digest: &Digest) -> Result<&[u8], AssureError> {
        match self.blobs.get(digest) {
            None => Err(AssureError::MissingOutput),
            Some(bytes) if sha256(bytes) == *digest => Ok(bytes),
            Some(_) => Err(AssureError::CorruptOutput),
        }
    }

    /// Adversary hook. Not a trusted write. The next [`ContentStore::get`]
    /// of `claimed` fails closed unless `bytes` actually hash to it.
    pub fn plant_unverified(&mut self, claimed: Digest, bytes: Vec<u8>) {
        self.blobs.insert(claimed, bytes);
    }

    /// Number of stored keys, including planted ones.
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

/// Canonical bytes of an outcome's decision. Stated `est_uj` and the gear
/// path are not part of the image: a G0 retry names the same decision with a
/// different stated cost.
pub fn outcome_image(outcome: &Outcome) -> Vec<u8> {
    let mut e = Enc::new("rcevc/action-image/v1");
    match outcome {
        Outcome::Accepted(r) => {
            e.u8(1).digest(&r.change).digest(&r.pre).digest(&r.post);
            push_resolution(&mut e, &r.resolution);
        }
        Outcome::Refused(r) => {
            e.u8(0).digest(&r.change).digest(&r.pre);
            e.str(&format!("{:?}", r.reason));
            push_resolution(&mut e, &r.resolution);
        }
    }
    e.as_slice().to_vec()
}

fn push_resolution(e: &mut Enc, resolution: &crate::repo::Resolution) {
    e.u64(resolution.len() as u64);
    for (slot, unit) in resolution {
        e.str(slot);
        match unit {
            Some(unit) => {
                e.u8(1);
                unit.encode(e);
            }
            None => {
                e.u8(0);
            }
        }
    }
}

fn outcome_pre(outcome: &Outcome) -> Digest {
    match outcome {
        Outcome::Accepted(r) => r.pre,
        Outcome::Refused(r) => r.pre,
    }
}

fn outcome_change(outcome: &Outcome) -> Digest {
    match outcome {
        Outcome::Accepted(r) => r.change,
        Outcome::Refused(r) => r.change,
    }
}

fn head_after(outcome: &Outcome) -> Digest {
    match outcome {
        Outcome::Accepted(r) => r.post,
        Outcome::Refused(r) => r.pre,
    }
}

fn decision_of(outcome: &Outcome) -> Decision {
    match outcome {
        Outcome::Accepted(r) => Decision::Accept { post: r.post },
        Outcome::Refused(_) => Decision::Refuse,
    }
}

/// A checked binding. Only [`bind_repo_outcome`] constructs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedAction {
    gate: Digest,
    base: Digest,
    head: Digest,
    change: Digest,
    inputs: Vec<Digest>,
    dependencies: Digest,
    output: Digest,
    decision: Decision,
}

impl CheckedAction {
    /// Gate identity the binding was minted under.
    pub fn gate(&self) -> Digest {
        self.gate
    }
    /// Declared base of the change.
    pub fn base(&self) -> Digest {
        self.base
    }
    /// Head the decision was made against (the outcome's pre-state).
    pub fn head(&self) -> Digest {
        self.head
    }
    /// Change id.
    pub fn change_id(&self) -> Digest {
        self.change
    }
    /// Content digest of the outcome image.
    pub fn output(&self) -> Digest {
        self.output
    }
    /// Accept or refuse. A refuse is not an accept.
    pub fn decision(&self) -> &Decision {
        &self.decision
    }
}

/// Mint a checked action from an outcome this repository has logged.
///
/// `inputs` are extra blobs the checker declares (for example fixture
/// digests). An empty slice is an explicit empty declaration, not a
/// discovered closure. `dependencies` must be [`DependencyManifest::complete`].
///
/// `output` must be the digest of [`outcome_image`], and those bytes must
/// already be in `store`.
pub fn bind_repo_outcome(
    repo: &Repo,
    change: &Change,
    outcome: &Outcome,
    store: &ContentStore,
    output: Digest,
    inputs: &[Digest],
    dependencies: &DependencyManifest,
) -> Result<CheckedAction, AssureError> {
    if !dependencies.is_complete() {
        return Err(AssureError::IncompleteDependencies);
    }
    if outcome_change(outcome) != change.id() {
        return Err(AssureError::ForgedBinding);
    }
    let logged = repo
        .log()
        .iter()
        .any(|entry| entry.change.id() == change.id() && entry.outcome == *outcome);
    if !logged {
        return Err(AssureError::NotLogged);
    }
    if matches!(outcome, Outcome::Accepted(_)) && repo.snapshot(&change.base).is_none() {
        return Err(AssureError::UnknownBase);
    }
    let image = outcome_image(outcome);
    let image_digest = sha256(&image);
    if output != image_digest {
        if let Ok(bytes) = store.get(&output) {
            if image.starts_with(bytes) && bytes.len() < image.len() {
                return Err(AssureError::TruncatedImage);
            }
        }
        return Err(AssureError::ForgedMapping);
    }
    match store.get(&output) {
        Ok(bytes) if bytes == image.as_slice() => {}
        Ok(_) => return Err(AssureError::CorruptOutput),
        Err(AssureError::CorruptOutput) => return Err(AssureError::CorruptOutput),
        Err(_) => return Err(AssureError::MissingOutput),
    }
    let mut inputs = inputs.to_vec();
    inputs.sort();
    Ok(CheckedAction {
        gate: repo.gate().digest(),
        base: change.base,
        head: outcome_pre(outcome),
        change: change.id(),
        inputs,
        dependencies: dependencies.digest(),
        output,
        decision: decision_of(outcome),
    })
}

#[derive(Clone, Debug)]
struct Row {
    gate: Digest,
    base: Digest,
    head: Digest,
    change: Digest,
    output: Digest,
    decision: Decision,
    trusted: bool,
}

/// The action a caller wants to apply, or to plant.
///
/// `inputs` is not sorted by the caller. Lookup and plant sort a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionQuery<'a> {
    /// Gate the row was checked under, or the gate the caller wants.
    pub gate: Digest,
    /// Head the row was checked against, or the head the caller wants.
    pub head: Digest,
    /// Declared base of the change.
    pub base: Digest,
    /// Change id.
    pub change: Digest,
    /// Extra input digests declared by the checker.
    pub inputs: &'a [Digest],
    /// [`DependencyManifest::digest`].
    pub dependencies: Digest,
}

/// Cache of checked action results.
///
/// Keys are local to this value. Nothing here is a cross-machine
/// authentication scheme. Two caches do not share rows unless the caller
/// copies them through [`ActionCache::insert`].
#[derive(Clone, Debug, Default)]
pub struct ActionCache {
    rows: BTreeMap<Digest, Row>,
    by_loose: BTreeMap<Digest, Vec<Digest>>,
    combined: BTreeMap<Digest, Row>,
}

impl ActionCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a [`CheckedAction`]. The same row inserted again is a no-op.
    /// A second trusted output for the same key is [`AssureError::ForgedMapping`].
    /// A trusted row replaces an untrusted plant at the same key.
    pub fn insert(
        &mut self,
        checked: &CheckedAction,
        store: &ContentStore,
    ) -> Result<(), AssureError> {
        self.recheck_output(checked.output, store)?;
        let full = full_key(checked);
        let loose = loose_key(
            checked.base,
            checked.change,
            &checked.inputs,
            checked.dependencies,
        );
        if let Some(existing) = self.rows.get(&full) {
            if existing.trusted && existing.output != checked.output {
                return Err(AssureError::ForgedMapping);
            }
            if existing.trusted {
                return Ok(());
            }
        }
        self.rows.insert(full, row_from(checked));
        let bucket = self.by_loose.entry(loose).or_default();
        if !bucket.contains(&full) {
            bucket.push(full);
        }
        Ok(())
    }

    /// Adversary hook. Plants an action-to-output row with no checked action.
    /// Does not replace a trusted row. Returns whether the plant is now the
    /// stored row.
    pub fn plant_untrusted(&mut self, query: ActionQuery<'_>, output: Digest) -> bool {
        let mut inputs = query.inputs.to_vec();
        inputs.sort();
        let checked = CheckedAction {
            gate: query.gate,
            base: query.base,
            head: query.head,
            change: query.change,
            inputs,
            dependencies: query.dependencies,
            output,
            decision: Decision::Accept { post: output },
        };
        let full = full_key(&checked);
        if self.rows.get(&full).is_some_and(|row| row.trusted) {
            return false;
        }
        let loose = loose_key(
            query.base,
            query.change,
            &checked.inputs,
            query.dependencies,
        );
        let mut row = row_from(&checked);
        row.trusted = false;
        self.rows.insert(full, row);
        let bucket = self.by_loose.entry(loose).or_default();
        if !bucket.contains(&full) {
            bucket.push(full);
        }
        true
    }

    /// Look up the decision for `change` when the caller wants it to apply at
    /// `current_head` under `current_gate`.
    ///
    /// A hit requires a trusted row at that exact head and gate, with output
    /// bytes that still hash to the recorded digest. A row checked at another
    /// head is [`AssureError::StaleHead`]. A row checked under another gate at
    /// this head is [`AssureError::GateMismatch`]. Individual hits are not
    /// consulted as a substitute.
    pub fn lookup(&self, query: ActionQuery<'_>, store: &ContentStore) -> Lookup {
        let ActionQuery {
            gate: current_gate,
            head: current_head,
            base,
            change,
            inputs,
            dependencies,
        } = query;
        let mut inputs_sorted = inputs.to_vec();
        inputs_sorted.sort();
        let loose = loose_key(base, change, &inputs_sorted, dependencies);
        let Some(keys) = self.by_loose.get(&loose) else {
            return Lookup::Miss;
        };
        let rows: Vec<&Row> = keys.iter().filter_map(|key| self.rows.get(key)).collect();
        if rows.is_empty() {
            return Lookup::Miss;
        }
        if let Some(row) = rows
            .iter()
            .find(|row| row.gate == current_gate && row.head == current_head)
        {
            if row.base != base || row.change != change {
                return Lookup::Reject(AssureError::ForgedBinding);
            }
            return finish_row(row, store);
        }
        if let Some(row) = rows
            .iter()
            .find(|row| row.head == current_head && row.gate != current_gate)
        {
            return Lookup::Reject(AssureError::GateMismatch {
                recorded: row.gate,
                current: current_gate,
            });
        }
        if let Some(row) = rows
            .iter()
            .find(|row| row.gate == current_gate && row.head != current_head)
        {
            return Lookup::Reject(AssureError::StaleHead {
                recorded: row.head,
                current: current_head,
            });
        }
        match rows.first() {
            Some(row) => Lookup::Reject(AssureError::GateMismatch {
                recorded: row.gate,
                current: current_gate,
            }),
            None => Lookup::Miss,
        }
    }

    /// Record `checked` as the decision for `members` in log order.
    ///
    /// `members` must appear, in order, as a head-linked chain in `repo`'s
    /// log: each next entry's pre-state is the head after the previous matched
    /// entry. The last member's logged outcome must be `outcome`, and
    /// `checked` must be the binding of that outcome. Two accepts stored with
    /// [`ActionCache::insert`] do not create this row.
    pub fn insert_combined(
        &mut self,
        repo: &Repo,
        members: &[Change],
        outcome: &Outcome,
        checked: &CheckedAction,
        store: &ContentStore,
    ) -> Result<(), AssureError> {
        if members.len() < 2 {
            return Err(AssureError::NotACombination);
        }
        let last = members.last().expect("len checked");
        if checked.change_id() != last.id() || outcome_change(outcome) != last.id() {
            return Err(AssureError::ForgedBinding);
        }
        if checked.gate() != repo.gate().digest() || checked.head() != outcome_pre(outcome) {
            return Err(AssureError::ForgedBinding);
        }
        if checked.decision() != &decision_of(outcome)
            || checked.output() != sha256(&outcome_image(outcome))
        {
            return Err(AssureError::ForgedBinding);
        }
        if !chain_logged(repo, members, outcome) {
            return Err(AssureError::ForgedBinding);
        }
        self.recheck_output(checked.output(), store)?;
        let key = combined_key(members);
        if let Some(existing) = self.combined.get(&key) {
            if existing.trusted
                && (existing.output != checked.output() || existing.head != checked.head())
            {
                return Err(AssureError::ForgedMapping);
            }
            if existing.trusted && existing.gate != checked.gate() {
                return Err(AssureError::GateMismatch {
                    recorded: existing.gate,
                    current: checked.gate(),
                });
            }
            if existing.trusted {
                return Ok(());
            }
        }
        self.combined.insert(key, row_from(checked));
        Ok(())
    }

    /// Adversary hook for a combined row. Does not replace a trusted row.
    pub fn plant_combined_untrusted(&mut self, members: &[Digest], output: Digest) -> bool {
        if members.len() < 2 {
            return false;
        }
        let key = combined_key_ids(members);
        if self.combined.get(&key).is_some_and(|row| row.trusted) {
            return false;
        }
        self.combined.insert(
            key,
            Row {
                gate: Digest::default(),
                base: Digest::default(),
                head: Digest::default(),
                change: *members.last().expect("len checked"),
                output,
                decision: Decision::Accept { post: output },
                trusted: false,
            },
        );
        true
    }

    /// Whether `members` have a checked combined decision applicable at
    /// `current_head` under `current_gate`.
    ///
    /// Missing means [`AssureError::UncheckedComposition`], including when
    /// each member has its own trusted single-change row.
    pub fn lookup_combined(
        &self,
        current_gate: Digest,
        current_head: Digest,
        members: &[Digest],
        store: &ContentStore,
    ) -> Lookup {
        if members.len() < 2 {
            return Lookup::Reject(AssureError::NotACombination);
        }
        let Some(row) = self.combined.get(&combined_key_ids(members)) else {
            return Lookup::Reject(AssureError::UncheckedComposition);
        };
        if !row.trusted {
            return Lookup::Reject(AssureError::UntrustedInsert);
        }
        if row.gate != current_gate {
            return Lookup::Reject(AssureError::GateMismatch {
                recorded: row.gate,
                current: current_gate,
            });
        }
        if row.head != current_head {
            return Lookup::Reject(AssureError::StaleHead {
                recorded: row.head,
                current: current_head,
            });
        }
        finish_row(row, store)
    }

    fn recheck_output(&self, output: Digest, store: &ContentStore) -> Result<(), AssureError> {
        store.get(&output).map(|_| ())
    }
}

fn row_from(checked: &CheckedAction) -> Row {
    Row {
        gate: checked.gate,
        base: checked.base,
        head: checked.head,
        change: checked.change,
        output: checked.output,
        decision: checked.decision.clone(),
        trusted: true,
    }
}

fn finish_row(row: &Row, store: &ContentStore) -> Lookup {
    if !row.trusted {
        return Lookup::Reject(AssureError::UntrustedInsert);
    }
    match store.get(&row.output) {
        Ok(_) => Lookup::Hit(Hit {
            output: row.output,
            decision: row.decision.clone(),
            head: row.head,
            gate: row.gate,
        }),
        Err(error) => Lookup::Reject(error),
    }
}

fn inputs_digest(inputs: &[Digest]) -> Digest {
    let mut e = Enc::new("rcevc/action-inputs/v1");
    e.u64(inputs.len() as u64);
    for digest in inputs {
        e.digest(digest);
    }
    e.finish()
}

fn full_key(checked: &CheckedAction) -> Digest {
    let mut e = Enc::new("rcevc/action-key/v1");
    e.digest(&checked.gate)
        .digest(&checked.head)
        .digest(&checked.base)
        .digest(&checked.change)
        .digest(&inputs_digest(&checked.inputs))
        .digest(&checked.dependencies);
    e.finish()
}

fn loose_key(base: Digest, change: Digest, inputs: &[Digest], dependencies: Digest) -> Digest {
    let mut e = Enc::new("rcevc/action-loose/v1");
    e.digest(&base)
        .digest(&change)
        .digest(&inputs_digest(inputs))
        .digest(&dependencies);
    e.finish()
}

fn combined_key(members: &[Change]) -> Digest {
    let ids: Vec<Digest> = members.iter().map(Change::id).collect();
    combined_key_ids(&ids)
}

fn combined_key_ids(members: &[Digest]) -> Digest {
    let mut e = Enc::new("rcevc/combined-action/v1");
    e.u64(members.len() as u64);
    for id in members {
        e.digest(id);
    }
    e.finish()
}

fn chain_logged(repo: &Repo, members: &[Change], outcome: &Outcome) -> bool {
    let mut matched = 0;
    let mut expect_pre: Option<Digest> = None;
    for entry in repo.log() {
        if matched == members.len() {
            break;
        }
        if entry.change.id() != members[matched].id() {
            continue;
        }
        if let Some(pre) = expect_pre {
            if outcome_pre(&entry.outcome) != pre {
                // An earlier submission of this change. Keep scanning.
                continue;
            }
        }
        let last = matched + 1 == members.len();
        if last && entry.outcome != *outcome {
            continue;
        }
        expect_pre = Some(head_after(if last { outcome } else { &entry.outcome }));
        matched += 1;
    }
    matched == members.len()
}

/// Result of a cache lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A trusted row applies at the requested head and gate.
    Hit(Hit),
    /// No row for this action.
    Miss,
    /// A row exists, or a combination was asked for, and it does not apply.
    Reject(AssureError),
}

/// A trusted cache hit. Call [`Hit::require_accept`] before treating it as
/// an admitted post-state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// Content digest of the outcome image.
    pub output: Digest,
    /// Accept or refuse.
    pub decision: Decision,
    /// Head the decision was made against.
    pub head: Digest,
    /// Gate the decision was made under.
    pub gate: Digest,
}

impl Hit {
    /// The admitted post-state, or [`AssureError::NotAccept`] for a refusal.
    pub fn require_accept(&self) -> Result<Digest, AssureError> {
        match self.decision {
            Decision::Accept { post } => Ok(post),
            Decision::Refuse => Err(AssureError::NotAccept),
        }
    }
}

/// Tip of a mutable ref. `epoch` counts successful new op ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefTip {
    /// Current target.
    pub target: Digest,
    /// Successful op count.
    pub epoch: u64,
}

/// Compare-and-swap on one ref, with per-op retry.
///
/// This is not a Git ref and it does not admit a state. Identical target
/// bytes written by a different op id are [`CasFail::UnrelatedWriter`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasRef {
    tip: RefTip,
    applied: BTreeMap<Digest, RefTip>,
}

impl CasRef {
    /// A ref at `target`, epoch 0, with no applied ops.
    pub fn new(target: Digest) -> Self {
        CasRef {
            tip: RefTip { target, epoch: 0 },
            applied: BTreeMap::new(),
        }
    }

    /// Current tip.
    pub fn tip(&self) -> RefTip {
        self.tip
    }

    /// Move the ref from `expected` at `expected_epoch` to `new_target`.
    ///
    /// A repeated `op_id` does not move the ref again. [`CasOk::Replay`]
    /// reports whether the tip is still the value that op wrote.
    /// `still_tip == false` is not authority to treat `wrote` as current.
    /// The same `op_id` with a different `new_target` is
    /// [`CasFail::OpRetarget`] and leaves the ref where it is.
    ///
    /// This value is not `Sync`. Callers serialize `&mut self`. It is not a
    /// cross-process lock.
    pub fn compare_and_swap(
        &mut self,
        op_id: Digest,
        expected_epoch: u64,
        expected: Digest,
        new_target: Digest,
    ) -> Result<CasOk, CasFail> {
        if let Some(wrote) = self.applied.get(&op_id).copied() {
            if wrote.target != new_target {
                return Err(CasFail::OpRetarget {
                    wrote,
                    requested: new_target,
                });
            }
            return Ok(CasOk::Replay {
                wrote,
                still_tip: self.tip == wrote,
            });
        }
        if self.tip.epoch != expected_epoch || self.tip.target != expected {
            if self.tip.target == new_target {
                return Err(CasFail::UnrelatedWriter { current: self.tip });
            }
            return Err(CasFail::Stale {
                expected_epoch,
                expected,
                current: self.tip,
            });
        }
        self.tip.epoch += 1;
        self.tip.target = new_target;
        self.applied.insert(op_id, self.tip);
        Ok(CasOk::Applied(self.tip))
    }
}

/// A successful compare-and-swap or a retry of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasOk {
    /// `op_id` moved the ref to this tip.
    Applied(RefTip),
    /// `op_id` had already been applied. The ref was not moved again.
    Replay {
        /// Tip that op wrote.
        wrote: RefTip,
        /// Whether the ref is still at `wrote`.
        still_tip: bool,
    },
}

/// Why a compare-and-swap did not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasFail {
    /// The tip is no longer the expected value.
    Stale {
        /// Epoch the caller expected.
        expected_epoch: u64,
        /// Target the caller expected.
        expected: Digest,
        /// Tip actually present.
        current: RefTip,
    },
    /// The tip already holds `new_target`, but this op id did not write it.
    UnrelatedWriter {
        /// Tip actually present.
        current: RefTip,
    },
    /// This op id already wrote a different target. The ref was not moved.
    OpRetarget {
        /// Tip that op wrote.
        wrote: RefTip,
        /// Target the retry asked for.
        requested: Digest,
    },
}

impl std::fmt::Display for CasFail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CasFail {}
