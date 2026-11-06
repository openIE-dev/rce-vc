//! Repository state `S` and name-free keys (part R of the repository Form).
//!
//! A [`Unit`] is the smallest addressable piece of meaning (a function, a
//! type, a file). A unit with dependencies refers to them only by position,
//! `$0`, `$1`, … bound by `deps`; a unit without dependencies (a *leaf*) is
//! literal text, so any file is a leaf. A unit's key is the hash of its body
//! and the *keys* of its dependencies, so a rename moves a binding and
//! changes no key (Definition 4, after RCE T7 and Unison).
//!
//! Two types separate building from holding:
//! - [`Draft`]: an unvalidated map, for genesis and for ingesting trees.
//! - [`State`]: always well formed. Persistent (structural sharing through a
//!   Merkle HAMT), so cloning is O(1), [`State::root`] is O(1), and
//!   [`diff`] costs O(difference). Keys and the reverse-dependency index are
//!   maintained incrementally: an edit recomputes keys only for the edited
//!   units and their dependents.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use crate::hamt::{HValue, Hamt};
use crate::hash::{Digest, Enc};

/// A name in the projection. Names are bindings, not identity.
pub type Slot = String;

/// A unit of meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    /// Body. If `deps` is non-empty, `$i` refers to `deps[i]` and `$$` is a
    /// literal `$`. If `deps` is empty, the body is literal text.
    pub body: String,
    /// Binding of `$i` to the slot at index `i`.
    pub deps: Vec<Slot>,
}

impl Unit {
    /// Build a unit.
    pub fn new(body: impl Into<String>, deps: &[&str]) -> Self {
        Unit { body: body.into(), deps: deps.iter().map(|d| d.to_string()).collect() }
    }

    /// Whether this is a leaf (no dependencies; literal body).
    pub fn is_leaf(&self) -> bool {
        self.deps.is_empty()
    }

    /// Positional references used in the body. Leaves have none.
    pub fn refs(&self) -> Vec<usize> {
        if self.is_leaf() {
            return Vec::new();
        }
        let b = self.body.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'$' && b.get(i + 1) == Some(&b'$') {
                i += 2;
            } else if b[i] == b'$' {
                let mut j = i + 1;
                let mut n: usize = 0;
                let mut any = false;
                while j < b.len() && b[j].is_ascii_digit() {
                    n = n.saturating_mul(10).saturating_add((b[j] - b'0') as usize);
                    any = true;
                    j += 1;
                }
                if any {
                    out.push(n);
                }
                i = j;
            } else {
                i += 1;
            }
        }
        out
    }

    pub(crate) fn encode(&self, e: &mut Enc) {
        e.str(&self.body).u64(self.deps.len() as u64);
        for d in &self.deps {
            e.str(d);
        }
    }

    /// Digest of the unit as written (body and named bindings).
    pub fn content(&self) -> Digest {
        let mut e = Enc::new("rcevc/unit-content/v1");
        self.encode(&mut e);
        e.finish()
    }
}

/// Why a state is not well formed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfError {
    /// `slot` binds a dependency that does not exist.
    MissingDep {
        /// The unit with the dangling binding.
        slot: Slot,
        /// The missing slot.
        dep: Slot,
    },
    /// The dependency graph has a cycle through `slot`.
    Cycle {
        /// A slot on the cycle.
        slot: Slot,
    },
    /// The body uses `$index` but `deps` has no such entry.
    BadRef {
        /// The unit.
        slot: Slot,
        /// The unbound index.
        index: usize,
    },
}

/// Why operations could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// Delete or rename of a slot that does not exist.
    NoSuchSlot(Slot),
    /// Rename onto a slot that is taken.
    SlotTaken(Slot),
    /// The result is not well formed.
    Wf(WfError),
}

/// An unvalidated set of units.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Draft {
    units: BTreeMap<Slot, Unit>,
}

impl Draft {
    /// Empty draft.
    pub fn new() -> Self {
        Self::default()
    }
    /// Insert or replace.
    pub fn put(&mut self, slot: impl Into<Slot>, unit: Unit) -> &mut Self {
        self.units.insert(slot.into(), unit);
        self
    }
    /// Look up.
    pub fn get(&self, slot: &str) -> Option<&Unit> {
        self.units.get(slot)
    }
    /// Entries by name.
    pub fn iter(&self) -> impl Iterator<Item = (&Slot, &Unit)> {
        self.units.iter()
    }
    /// Number of units.
    pub fn len(&self) -> usize {
        self.units.len()
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
    /// Validate into a [`State`].
    pub fn seal(&self) -> Result<State, WfError> {
        let mut e = State::default().edit();
        for (s, u) in &self.units {
            e.set(s.clone(), Some(u.clone()));
        }
        e.finish()
    }
    /// Assignments that turn `base` into this draft.
    pub fn changes_from(&self, base: &State) -> Vec<(Slot, Option<Unit>)> {
        let mut out = Vec::new();
        for (s, u) in &self.units {
            if base.get(s) != Some(u) {
                out.push((s.clone(), Some(u.clone())));
            }
        }
        for s in base.slots() {
            if !self.units.contains_key(s) {
                out.push((s.clone(), None));
            }
        }
        out
    }
}

#[derive(Clone)]
struct UEntry {
    unit: Arc<Unit>,
    content: Digest,
}
impl HValue for UEntry {
    const MERKLE: bool = true;
    fn digest(&self) -> Digest {
        self.content
    }
}

#[derive(Clone)]
struct KEntry(Digest);
impl HValue for KEntry {
    const MERKLE: bool = false;
    fn digest(&self) -> Digest {
        self.0
    }
}

#[derive(Clone)]
struct Users(Arc<BTreeSet<Slot>>);
impl HValue for Users {
    const MERKLE: bool = false;
    fn digest(&self) -> Digest {
        Digest::default()
    }
}

/// A well-formed repository state. Cheap to clone; equality is root equality.
#[derive(Clone, Default)]
pub struct State {
    units: Hamt<UEntry>,
    keys: Hamt<KEntry>,
    users: Hamt<Users>,
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.root() == other.root()
    }
}
impl Eq for State {}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "State({} units, root {:?})", self.len(), self.root())
    }
}

impl State {
    /// The empty state.
    pub fn empty() -> Self {
        Self::default()
    }
    /// The unit at `slot`.
    pub fn get(&self, slot: &str) -> Option<&Unit> {
        self.units.get(slot).map(|e| &*e.unit)
    }
    /// Name-free key of the unit at `slot`.
    pub fn key(&self, slot: &str) -> Option<Digest> {
        self.keys.get(slot).map(|k| k.0)
    }
    /// Whether `slot` is bound.
    pub fn contains(&self, slot: &str) -> bool {
        self.units.get(slot).is_some()
    }
    /// Number of units.
    pub fn len(&self) -> usize {
        self.units.len()
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
    /// Slots, sorted by name. O(n).
    pub fn slots(&self) -> Vec<&Slot> {
        let mut v = Vec::with_capacity(self.len());
        self.units.for_each(|k, _| v.push(k));
        v.sort();
        v
    }
    /// Units, sorted by name. O(n log n).
    pub fn iter(&self) -> Vec<(&Slot, &Unit)> {
        let mut v = Vec::with_capacity(self.len());
        self.units.for_each(|k, e| v.push((k, &*e.unit)));
        v.sort_by(|a, b| a.0.cmp(b.0));
        v
    }
    /// Root over the projection: names, units and bindings. O(1).
    pub fn root(&self) -> Digest {
        let mut e = Enc::new("rcevc/state/v2");
        e.opt_digest(self.units.root_hash().as_ref());
        e.finish()
    }
    /// Root over content only: the multiset of keys. Unchanged by renames. O(n).
    pub fn content_root(&self) -> Digest {
        let mut ks = Vec::with_capacity(self.len());
        self.keys.for_each(|_, k| ks.push(k.0));
        ks.sort();
        let mut e = Enc::new("rcevc/content/v1");
        e.u64(ks.len() as u64);
        for k in &ks {
            e.digest(k);
        }
        e.finish()
    }
    /// Every name-free key. O(n).
    pub fn keys(&self) -> BTreeMap<Slot, Digest> {
        let mut m = BTreeMap::new();
        self.keys.for_each(|s, k| {
            m.insert(s.clone(), k.0);
        });
        m
    }
    /// Units that bind `slot`.
    pub fn users(&self, slot: &str) -> BTreeSet<Slot> {
        self.users.get(slot).map(|u| (*u.0).clone()).unwrap_or_default()
    }
    /// `seeds` plus every unit that transitively depends on one of them.
    pub fn rdep_closure(&self, seeds: &BTreeSet<Slot>) -> BTreeSet<Slot> {
        let mut out = seeds.clone();
        let mut stack: Vec<Slot> = seeds.iter().cloned().collect();
        while let Some(s) = stack.pop() {
            if let Some(us) = self.users.get(&s) {
                for u in us.0.iter() {
                    if out.insert(u.clone()) {
                        stack.push(u.clone());
                    }
                }
            }
        }
        out
    }
    /// Start an edit. Validation happens once, in [`Edit::finish`].
    pub fn edit(&self) -> Edit {
        Edit { next: self.clone(), touched: BTreeSet::new() }
    }
    /// Apply assignments (`None` deletes) and validate.
    pub fn with(&self, assignments: impl IntoIterator<Item = (Slot, Option<Unit>)>) -> Result<State, WfError> {
        let mut e = self.edit();
        for (s, u) in assignments {
            e.set(s, u);
        }
        e.finish()
    }

    fn link(&mut self, dep: &str, user: &str) {
        let mut set = self.users.get(dep).map(|u| (*u.0).clone()).unwrap_or_default();
        if set.insert(user.to_string()) {
            self.users.insert(dep.to_string(), Users(Arc::new(set)));
        }
    }
    fn unlink(&mut self, dep: &str, user: &str) {
        let Some(cur) = self.users.get(dep) else { return };
        if !cur.0.contains(user) {
            return;
        }
        let mut set = (*cur.0).clone();
        set.remove(user);
        if set.is_empty() {
            self.users.remove(dep);
        } else {
            self.users.insert(dep.to_string(), Users(Arc::new(set)));
        }
    }
}

/// An in-progress edit of a state.
pub struct Edit {
    next: State,
    touched: BTreeSet<Slot>,
}

impl Edit {
    /// The unit currently at `slot` in the edit.
    pub fn get(&self, slot: &str) -> Option<&Unit> {
        self.next.get(slot)
    }
    /// Whether `slot` is bound in the edit.
    pub fn contains(&self, slot: &str) -> bool {
        self.next.contains(slot)
    }
    /// Units binding `slot` in the edit.
    pub fn users(&self, slot: &str) -> BTreeSet<Slot> {
        self.next.users(slot)
    }
    /// Set or delete one slot.
    pub fn set(&mut self, slot: Slot, unit: Option<Unit>) {
        if let Some(old) = self.next.units.get(&slot).map(|e| e.unit.clone()) {
            for d in &old.deps {
                self.next.unlink(d, &slot);
            }
        }
        match unit {
            Some(u) => {
                for d in &u.deps {
                    self.next.link(d, &slot);
                }
                let content = u.content();
                self.next.units.insert(slot.clone(), UEntry { unit: Arc::new(u), content });
            }
            None => {
                self.next.units.remove(&slot);
                self.next.keys.remove(&slot);
            }
        }
        self.touched.insert(slot);
    }
    /// Validate and re-key only what the edit could affect.
    pub fn finish(self) -> Result<State, WfError> {
        let Edit { mut next, touched } = self;
        let affected = next.rdep_closure(&touched);
        let mut memo = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        for s in &affected {
            if next.contains(s) {
                key_rec(&next, s, &affected, &mut memo, &mut visiting)?;
            }
        }
        for (s, k) in memo {
            next.keys.insert(s, KEntry(k));
        }
        Ok(next)
    }
}

fn key_rec(
    st: &State,
    slot: &Slot,
    affected: &BTreeSet<Slot>,
    memo: &mut BTreeMap<Slot, Digest>,
    visiting: &mut BTreeSet<Slot>,
) -> Result<Digest, WfError> {
    if let Some(k) = memo.get(slot) {
        return Ok(*k);
    }
    if !affected.contains(slot) {
        if let Some(k) = st.key(slot) {
            return Ok(k);
        }
    }
    let Some(unit) = st.get(slot) else {
        return Err(WfError::MissingDep { slot: slot.clone(), dep: slot.clone() });
    };
    for r in unit.refs() {
        if r >= unit.deps.len() {
            return Err(WfError::BadRef { slot: slot.clone(), index: r });
        }
    }
    if !visiting.insert(slot.clone()) {
        return Err(WfError::Cycle { slot: slot.clone() });
    }
    let mut e = Enc::new("rcevc/unit/v1");
    e.str(&unit.body).u64(unit.deps.len() as u64);
    for d in &unit.deps {
        if !st.contains(d) {
            return Err(WfError::MissingDep { slot: slot.clone(), dep: d.clone() });
        }
        let k = key_rec(st, d, affected, memo, visiting)?;
        e.digest(&k);
    }
    visiting.remove(slot);
    let k = e.finish();
    memo.insert(slot.clone(), k);
    Ok(k)
}

/// Slots whose unit (body or bindings) differs between `a` and `b`.
/// Cost follows the size of the difference, not the size of the states.
pub fn diff(a: &State, b: &State) -> BTreeSet<Slot> {
    a.units.diff(&b.units)
}
