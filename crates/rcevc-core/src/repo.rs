//! The transition δ, the integration ladder, receipts and the log (part D).
//!
//! `Repo::submit` is total: every change is either accepted with a receipt
//! or refused with a recorded reason, and either way one entry is appended
//! to a hash-chained log (VC1, no limbo). Only states that are well formed
//! and pass the gate become head (VC2, green by induction). Head is the fold
//! of the log: [`Repo::replay`] rebuilds it from genesis without calling any
//! proposer, because every resolution a proposer supplied is recorded in its
//! receipt (the model is out of the loop on replay).
//!
//! The ladder, cheapest rung first:
//! - **G0 lookup**: an identical change against an identical head returns
//!   its memoized refusal; a conflict whose name-free signature was resolved
//!   before reuses that resolution (VC5, compounding).
//! - **G1 commutation**: if the change's closure misses every slot that
//!   moved since its base, apply it to head directly (VC3).
//! - **G2 structural merge**: per-slot three-way merge of base, head and
//!   the change's own result.
//! - **G3 re-validation**: closures met, so the merged state is re-checked
//!   as a whole; this is where semantic conflicts are caught.
//! - **G4 proposer**: only for slots both sides changed differently and no
//!   reuse exists. Its output is a candidate, admitted only if the gate
//!   accepts it, and promoted for reuse only then.

use std::collections::{BTreeMap, BTreeSet};

use crate::change::{apply, Change, Level};
use crate::gate::{Evidence, Gate};
use crate::hash::{Digest, Enc};
use crate::model::{diff, ApplyError, Draft, Slot, State, Unit, WfError};

/// A rung of the integration ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Gear {
    /// Memoized outcome or reused resolution.
    G0Lookup,
    /// Commutation: closures disjoint from what moved.
    G1Commute,
    /// Per-slot three-way structural merge.
    G2Structural,
    /// Whole-state re-validation after closures met.
    G3Revalidate,
    /// Proposer (for example a model) for true conflicts.
    G4Proposer,
}

impl Gear {
    fn code(self) -> u8 {
        self as u8
    }
}

/// Estimated cost per rung, in microjoules. These are `est_j`-class
/// figures (stated, not measured); `rcevc-meter` replaces them with
/// `measured_j` where hardware counters exist.
#[derive(Clone, Debug)]
pub struct CostTable {
    /// G0 lookup.
    pub g0: u64,
    /// G1 commutation test.
    pub g1: u64,
    /// G2 three-way merge.
    pub g2: u64,
    /// One checker run.
    pub per_check: u64,
    /// One proposer call.
    pub g4: u64,
}

impl Default for CostTable {
    fn default() -> Self {
        CostTable { g0: 1, g1: 10, g2: 100, per_check: 1_000, g4: 5_000_000 }
    }
}

/// Resolutions of conflicted slots (`None` resolves to deletion).
pub type Resolution = Vec<(Slot, Option<Unit>)>;

/// Proof of admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Change id.
    pub change: Digest,
    /// Head root before.
    pub pre: Digest,
    /// Head root after.
    pub post: Digest,
    /// Rungs used.
    pub path: Vec<Gear>,
    /// Gate evidence for the post-state.
    pub evidence: Vec<Evidence>,
    /// Conflict resolutions used (recorded so replay needs no proposer).
    pub resolution: Resolution,
    /// Estimated cost, microjoules.
    pub est_uj: u64,
}

/// Why a change was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The declared base is not a state this repository has held.
    UnknownBase(Digest),
    /// The operations do not apply to the base.
    Apply(ApplyError),
    /// The result is not well formed.
    IllFormed(WfError),
    /// Declared `NameOnly` but content changed.
    LevelMismatch,
    /// Slots both sides changed differently, unresolved.
    Conflict(Vec<Slot>),
    /// A checker refused the post-state.
    Gate {
        /// Checker name.
        checker: String,
        /// Its message.
        message: String,
    },
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Reason {}

/// Proof of refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// Change id.
    pub change: Digest,
    /// Head root at the time.
    pub pre: Digest,
    /// Rungs tried.
    pub path: Vec<Gear>,
    /// The reason.
    pub reason: Reason,
    /// Any resolution that was attempted (recorded for replay).
    pub resolution: Resolution,
    /// Estimated cost, microjoules.
    pub est_uj: u64,
}

/// The result of δ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Admitted.
    Accepted(Receipt),
    /// Refused.
    Refused(Refusal),
}

impl Outcome {
    /// Whether admitted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Outcome::Accepted(_))
    }
    /// Rungs used.
    pub fn path(&self) -> &[Gear] {
        match self {
            Outcome::Accepted(r) => &r.path,
            Outcome::Refused(r) => &r.path,
        }
    }
    /// Estimated cost.
    pub fn est_uj(&self) -> u64 {
        match self {
            Outcome::Accepted(r) => r.est_uj,
            Outcome::Refused(r) => r.est_uj,
        }
    }
    /// The refusal reason, if refused.
    pub fn reason(&self) -> Option<&Reason> {
        match self {
            Outcome::Refused(r) => Some(&r.reason),
            Outcome::Accepted(_) => None,
        }
    }
    fn resolution(&self) -> &Resolution {
        match self {
            Outcome::Accepted(r) => &r.resolution,
            Outcome::Refused(r) => &r.resolution,
        }
    }
    fn encode(&self, e: &mut Enc) {
        fn res(e: &mut Enc, r: &Resolution) {
            e.u64(r.len() as u64);
            for (s, u) in r {
                e.str(s);
                match u {
                    Some(u) => {
                        e.u8(1);
                        u.encode(e);
                    }
                    None => {
                        e.u8(0);
                    }
                }
            }
        }
        match self {
            Outcome::Accepted(r) => {
                e.u8(1).digest(&r.pre).digest(&r.post);
                e.u64(r.path.len() as u64);
                for g in &r.path {
                    e.u8(g.code());
                }
                e.u64(r.evidence.len() as u64);
                for ev in &r.evidence {
                    e.digest(&ev.digest);
                }
                res(e, &r.resolution);
                e.u64(r.est_uj);
            }
            Outcome::Refused(r) => {
                e.u8(0).digest(&r.pre);
                e.u64(r.path.len() as u64);
                for g in &r.path {
                    e.u8(g.code());
                }
                e.str(&format!("{:?}", r.reason));
                res(e, &r.resolution);
                e.u64(r.est_uj);
            }
        }
    }
}

/// One log entry. `hash` chains to `prev`.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Position.
    pub index: u64,
    /// Hash of the previous entry (or genesis).
    pub prev: Digest,
    /// The submitted change.
    pub change: Change,
    /// Its outcome.
    pub outcome: Outcome,
    /// This entry's hash.
    pub hash: Digest,
}

fn entry_hash(index: u64, prev: &Digest, change: &Change, outcome: &Outcome) -> Digest {
    let mut e = Enc::new("rcevc/entry/v1");
    e.u64(index).digest(prev).digest(&change.id());
    outcome.encode(&mut e);
    e.finish()
}

/// Verify the hash chain. Returns the index of the first bad entry.
pub fn verify_chain(genesis: &Digest, entries: &[Entry]) -> Result<(), usize> {
    let mut prev = *genesis;
    for (i, en) in entries.iter().enumerate() {
        if en.index != i as u64 || en.prev != prev || entry_hash(en.index, &en.prev, &en.change, &en.outcome) != en.hash
        {
            return Err(i);
        }
        prev = en.hash;
    }
    Ok(())
}

/// Something that proposes a resolution for one conflicted slot.
/// Returns `None` for no proposal, `Some(None)` to resolve by deletion.
pub trait Proposer {
    /// Propose for `slot` given the base, head ("ours") and change ("theirs").
    fn propose(
        &self,
        slot: &str,
        base: Option<&Unit>,
        ours: Option<&Unit>,
        theirs: Option<&Unit>,
    ) -> Option<Option<Unit>>;
}

/// Why replay failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// Genesis is not admissible under the gate.
    Genesis(Reason),
    /// Hash chain broken at this index.
    BrokenChain(usize),
    /// Replayed outcome differs from the record at this index.
    Diverged(usize),
}

enum Mode<'a> {
    Live,
    Replay(&'a Resolution),
}

/// A repository: the Form's state, gate, log and reuse store.
pub struct Repo {
    gate: Gate,
    proposer: Option<Box<dyn Proposer>>,
    costs: CostTable,
    genesis: Digest,
    head: State,
    head_root: Digest,
    snapshots: BTreeMap<Digest, State>,
    log: Vec<Entry>,
    memo: BTreeMap<(Digest, Digest), Outcome>,
    reuse: BTreeMap<Digest, Option<Unit>>,
    proposer_calls: u64,
}

impl Repo {
    /// Open a repository on `genesis`, which must be well formed and pass the gate.
    pub fn new(gate: Gate, genesis: Draft) -> Result<Self, Reason> {
        let genesis = genesis.seal().map_err(Reason::IllFormed)?;
        let root = genesis.root();
        gate.run(&genesis).map_err(|(checker, message)| Reason::Gate { checker, message })?;
        let mut e = Enc::new("rcevc/genesis/v1");
        e.digest(&root).digest(&gate.digest());
        let mut snapshots = BTreeMap::new();
        snapshots.insert(root, genesis.clone());
        Ok(Repo {
            gate,
            proposer: None,
            costs: CostTable::default(),
            genesis: e.finish(),
            head: genesis,
            head_root: root,
            snapshots,
            log: Vec::new(),
            memo: BTreeMap::new(),
            reuse: BTreeMap::new(),
            proposer_calls: 0,
        })
    }

    /// Attach a proposer (G4).
    pub fn with_proposer(mut self, p: impl Proposer + 'static) -> Self {
        self.proposer = Some(Box::new(p));
        self
    }
    /// Replace the cost table.
    pub fn with_costs(mut self, c: CostTable) -> Self {
        self.costs = c;
        self
    }

    /// Current head.
    pub fn head(&self) -> &State {
        &self.head
    }
    /// Current head root.
    pub fn head_root(&self) -> Digest {
        self.head_root
    }
    /// Genesis hash (first `prev` of the chain).
    pub fn genesis(&self) -> Digest {
        self.genesis
    }
    /// The log.
    pub fn log(&self) -> &[Entry] {
        &self.log
    }
    /// A state this repository has held, by root.
    pub fn snapshot(&self, root: &Digest) -> Option<&State> {
        self.snapshots.get(root)
    }
    /// Number of promoted resolutions.
    pub fn reuse_len(&self) -> usize {
        self.reuse.len()
    }
    /// Number of proposer calls made.
    pub fn proposer_calls(&self) -> u64 {
        self.proposer_calls
    }
    /// The gate.
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// δ: integrate one change. Total; always appends exactly one log entry.
    pub fn submit(&mut self, change: Change) -> Outcome {
        let outcome = self.integrate(&change, Mode::Live);
        self.append(change, outcome.clone());
        outcome
    }

    fn append(&mut self, change: Change, outcome: Outcome) {
        let index = self.log.len() as u64;
        let prev = self.log.last().map(|e| e.hash).unwrap_or(self.genesis);
        let hash = entry_hash(index, &prev, &change, &outcome);
        self.log.push(Entry { index, prev, change, outcome, hash });
    }

    /// Rebuild a repository from genesis and a log, with no proposer.
    /// Succeeds only if every outcome and every post-root reproduces.
    pub fn replay(gate: Gate, genesis: Draft, entries: &[Entry]) -> Result<Repo, ReplayError> {
        let mut r = Repo::new(gate, genesis).map_err(ReplayError::Genesis)?;
        verify_chain(&r.genesis, entries).map_err(ReplayError::BrokenChain)?;
        for (i, en) in entries.iter().enumerate() {
            let got = r.integrate(&en.change, Mode::Replay(en.outcome.resolution()));
            let same = match (&got, &en.outcome) {
                (Outcome::Accepted(a), Outcome::Accepted(b)) => a.pre == b.pre && a.post == b.post,
                (Outcome::Refused(a), Outcome::Refused(b)) => a.pre == b.pre && a.reason == b.reason,
                _ => false,
            };
            if !same {
                return Err(ReplayError::Diverged(i));
            }
            // Keep the recorded entry so the replayed chain is byte-identical.
            r.log.push(en.clone());
        }
        Ok(r)
    }

    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &mut self,
        mode: &Mode<'_>,
        id: Digest,
        pre: Digest,
        path: Vec<Gear>,
        reason: Reason,
        resolution: Resolution,
        est_uj: u64,
    ) -> Outcome {
        let o = Outcome::Refused(Refusal { change: id, pre, path, reason, resolution, est_uj });
        if let Mode::Live = mode {
            self.memo.insert((pre, id), o.clone());
        }
        o
    }

    fn integrate(&mut self, c: &Change, mode: Mode<'_>) -> Outcome {
        let id = c.id();
        let pre = self.head_root;
        let mut cost = self.costs.g0;

        // G0: identical change against identical head.
        if let Mode::Live = mode {
            if let Some(Outcome::Refused(prev)) = self.memo.get(&(pre, id)) {
                let mut r = prev.clone();
                r.path = vec![Gear::G0Lookup];
                r.est_uj = cost;
                return Outcome::Refused(r);
            }
        }

        let mut path = Vec::new();
        let Some(base) = self.snapshots.get(&c.base).cloned() else {
            return self.refuse(&mode, id, pre, path, Reason::UnknownBase(c.base), vec![], cost);
        };
        // The change against its own base must make sense on its own.
        let theirs = match apply(&base, &c.ops) {
            Ok(t) => t,
            Err(ApplyError::Wf(e)) => return self.refuse(&mode, id, pre, path, Reason::IllFormed(e), vec![], cost),
            Err(e) => return self.refuse(&mode, id, pre, path, Reason::Apply(e), vec![], cost),
        };
        let theirs_moved = diff(&base, &theirs);
        if c.level == Level::NameOnly && !same_content(&base, &theirs, &theirs_moved) {
            return self.refuse(&mode, id, pre, path, Reason::LevelMismatch, vec![], cost);
        }

        // G1: commutation against everything that moved since base.
        cost += self.costs.g1;
        let head = self.head.clone();
        let moved = diff(&base, &head);
        let mut candidate = None;
        if moved.is_empty() {
            candidate = Some(theirs.clone());
        } else if c.closure_in(&base, &theirs).is_disjoint(&moved) {
            if let Ok(h2) = apply(&head, &c.ops) {
                if c.closure_in(&head, &h2).is_disjoint(&moved) {
                    candidate = Some(h2);
                }
            }
        }

        let mut resolution: Resolution = Vec::new();
        let mut promote: Vec<(Digest, Option<Unit>)> = Vec::new();
        let candidate = match candidate {
            Some(s) => {
                path.push(Gear::G1Commute);
                s
            }
            None => {
                // G2: structural three-way merge, over the moved slots only.
                path.push(Gear::G2Structural);
                cost += self.costs.g2;
                let mut assign: Vec<(Slot, Option<Unit>)> = Vec::new();
                let mut conflicts = Vec::new();
                for s in moved.union(&theirs_moved) {
                    let (b, h, t) = (base.get(s), head.get(s), theirs.get(s));
                    if h == t || t == b {
                        continue;
                    }
                    if h == b {
                        assign.push((s.clone(), t.cloned()));
                        continue;
                    }
                    conflicts.push(s.clone());
                }
                if !conflicts.is_empty() {
                    let mut unresolved = Vec::new();
                    let (mut used_g0, mut used_g4) = (false, false);
                    for s in &conflicts {
                        let sig = conflict_signature(base.key(s).as_ref(), head.key(s).as_ref(), theirs.key(s).as_ref());
                        let value = match &mode {
                            Mode::Replay(rec) => rec.iter().find(|(rs, _)| rs == s).map(|(_, u)| u.clone()),
                            Mode::Live => {
                                if let Some(v) = self.reuse.get(&sig) {
                                    used_g0 = true;
                                    cost += self.costs.g0;
                                    Some(v.clone())
                                } else if let Some(p) = &self.proposer {
                                    used_g4 = true;
                                    cost += self.costs.g4;
                                    self.proposer_calls += 1;
                                    let v = p.propose(s, base.get(s), head.get(s), theirs.get(s));
                                    if let Some(v) = &v {
                                        promote.push((sig, v.clone()));
                                    }
                                    v
                                } else {
                                    None
                                }
                            }
                        };
                        match value {
                            Some(v) => {
                                assign.push((s.clone(), v.clone()));
                                resolution.push((s.clone(), v));
                            }
                            None => unresolved.push(s.clone()),
                        }
                    }
                    if used_g0 {
                        path.push(Gear::G0Lookup);
                    }
                    if used_g4 {
                        path.push(Gear::G4Proposer);
                    }
                    if !unresolved.is_empty() {
                        return self.refuse(&mode, id, pre, path, Reason::Conflict(unresolved), resolution, cost);
                    }
                }
                // G3: closures met, so the merged state is re-validated.
                path.push(Gear::G3Revalidate);
                match head.with(assign) {
                    Ok(m) => m,
                    Err(e) => return self.refuse(&mode, id, pre, path, Reason::IllFormed(e), resolution, cost),
                }
            }
        };

        // Gate, on every path (VC2), over what changed relative to head.
        let post = candidate.root();
        let delta = diff(&head, &candidate);
        cost += self.costs.per_check * self.gate.len() as u64;
        let evidence = match self.gate.run_delta(&candidate, &delta) {
            Ok(ev) => ev,
            Err((checker, message)) => {
                return self.refuse(&mode, id, pre, path, Reason::Gate { checker, message }, resolution, cost);
            }
        };

        // Admit. Proposer output is promoted only now, after the gate accepted it.
        for (sig, v) in promote {
            self.reuse.insert(sig, v);
        }
        if let Mode::Replay(_) = mode {
            // Rebuild the reuse store from the record so later live use matches.
            for (s, v) in &resolution {
                let sig = conflict_signature(base.key(s).as_ref(), head.key(s).as_ref(), theirs.key(s).as_ref());
                self.reuse.insert(sig, v.clone());
            }
        }
        self.snapshots.entry(post).or_insert_with(|| candidate.clone());
        self.head = candidate;
        self.head_root = post;
        Outcome::Accepted(Receipt { change: id, pre, post, path, evidence, resolution, est_uj: cost })
    }
}

/// Whether two states differing at `moved` hold the same multiset of keys
/// (only names moved). O(moved and their dependents).
fn same_content(a: &State, b: &State, moved: &BTreeSet<Slot>) -> bool {
    let mut zone = a.rdep_closure(moved);
    zone.extend(b.rdep_closure(moved));
    let mut ka: Vec<Digest> = zone.iter().filter_map(|s| a.key(s)).collect();
    let mut kb: Vec<Digest> = zone.iter().filter_map(|s| b.key(s)).collect();
    ka.sort();
    kb.sort();
    ka == kb
}

/// Name-free signature of a conflict: the keys on each side, not the slot.
pub fn conflict_signature(b: Option<&Digest>, h: Option<&Digest>, t: Option<&Digest>) -> Digest {
    let mut e = Enc::new("rcevc/conflict/v1");
    e.opt_digest(b).opt_digest(h).opt_digest(t);
    e.finish()
}
