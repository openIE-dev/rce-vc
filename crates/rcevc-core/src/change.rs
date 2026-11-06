//! Typed changes (part Δ) and commutation from dependency closures (part X).
//!
//! A change is a list of operations against a declared base, with a declared
//! equivalence level. Its *writes* are the slots it actually alters; its
//! *closure* adds every unit whose meaning can depend on those writes and
//! every slot it reads. Two changes whose writes miss each other's closures
//! commute (Proposition VC3): applying them in either order gives the same
//! state, so they can be admitted without coordination.

use std::collections::BTreeSet;

use crate::hash::{Digest, Enc};
use crate::model::{diff, ApplyError, Slot, State, Unit};

/// One operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Bind `slot` to `unit` (insert or replace).
    Put {
        /// Target slot.
        slot: Slot,
        /// New unit.
        unit: Unit,
    },
    /// Remove `slot`.
    Del {
        /// Target slot.
        slot: Slot,
    },
    /// Move a binding; every dependent is rebound. No key changes.
    Rename {
        /// Old name.
        from: Slot,
        /// New name.
        to: Slot,
    },
}

/// Declared equivalence level (RCE `rce change`, plus a name-only level).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Only names move; content root must be unchanged (kernel-verified).
    NameOnly,
    /// Behaviour-preserving fix.
    Erratum,
    /// Behaviour changes, interface does not.
    MeaningChange,
    /// Interface changes.
    InterfaceChange,
}

impl Level {
    fn code(self) -> u8 {
        match self {
            Level::NameOnly => 0,
            Level::Erratum => 1,
            Level::MeaningChange => 2,
            Level::InterfaceChange => 3,
        }
    }
}

/// A change submitted by any writer, human or agent. The writer field is an
/// opaque label: nothing in admission depends on who wrote the change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// Opaque writer label.
    pub writer: String,
    /// Root of the state the change was written against.
    pub base: Digest,
    /// Declared level.
    pub level: Level,
    /// Operations, applied in order.
    pub ops: Vec<Op>,
    /// Stated intent (free text, for example a commit message). Covered by
    /// the id; never consulted by admission.
    pub message: String,
}

impl Change {
    /// A change with no operations yet.
    pub fn new(writer: impl Into<String>, base: Digest, level: Level) -> Self {
        Change { writer: writer.into(), base, level, ops: Vec::new(), message: String::new() }
    }
    /// Set the stated intent.
    pub fn message(mut self, m: impl Into<String>) -> Self {
        self.message = m.into();
        self
    }
    /// Add a put.
    pub fn put(mut self, slot: impl Into<Slot>, unit: Unit) -> Self {
        self.ops.push(Op::Put { slot: slot.into(), unit });
        self
    }
    /// Add a delete.
    pub fn del(mut self, slot: impl Into<Slot>) -> Self {
        self.ops.push(Op::Del { slot: slot.into() });
        self
    }
    /// Add a rename.
    pub fn rename(mut self, from: impl Into<Slot>, to: impl Into<Slot>) -> Self {
        self.ops.push(Op::Rename { from: from.into(), to: to.into() });
        self
    }

    /// Content address of the change.
    pub fn id(&self) -> Digest {
        let mut e = Enc::new("rcevc/change/v1");
        e.str(&self.writer).str(&self.message).digest(&self.base).u8(self.level.code());
        e.u64(self.ops.len() as u64);
        for op in &self.ops {
            match op {
                Op::Put { slot, unit } => {
                    e.u8(0).str(slot);
                    unit.encode(&mut e);
                }
                Op::Del { slot } => {
                    e.u8(1).str(slot);
                }
                Op::Rename { from, to } => {
                    e.u8(2).str(from).str(to);
                }
            }
        }
        e.finish()
    }

    /// Whether the change only adds fresh slots in `s` (CALM-monotone).
    pub fn is_monotone(&self, s: &State) -> bool {
        self.ops.iter().all(|op| matches!(op, Op::Put { slot, .. } if !s.contains(slot)))
    }

    /// Slots read: everything a put binds as a dependency, and rename sources.
    pub fn reads(&self) -> BTreeSet<Slot> {
        let mut r = BTreeSet::new();
        for op in &self.ops {
            match op {
                Op::Put { unit, .. } => r.extend(unit.deps.iter().cloned()),
                Op::Rename { from, .. } => {
                    r.insert(from.clone());
                }
                Op::Del { .. } => {}
            }
        }
        r
    }

    fn op_slots(&self) -> BTreeSet<Slot> {
        let mut w = BTreeSet::new();
        for op in &self.ops {
            match op {
                Op::Put { slot, .. } | Op::Del { slot } => {
                    w.insert(slot.clone());
                }
                Op::Rename { from, to } => {
                    w.insert(from.clone());
                    w.insert(to.clone());
                }
            }
        }
        w
    }

    /// Slots this change actually alters when applied to `s`.
    pub fn writes(&self, s: &State) -> BTreeSet<Slot> {
        match apply(s, &self.ops) {
            Ok(t) => diff(s, &t),
            Err(_) => self.op_slots(),
        }
    }

    /// Dependency closure in `s`: writes, their dependents before and after,
    /// and reads.
    pub fn closure(&self, s: &State) -> BTreeSet<Slot> {
        match apply(s, &self.ops) {
            Ok(t) => self.closure_in(s, &t),
            Err(_) => {
                let w = self.op_slots();
                let mut c = s.rdep_closure(&w);
                c.extend(self.reads());
                c
            }
        }
    }

    /// Closure given the already-computed post-state `post = apply(s)`.
    pub fn closure_in(&self, s: &State, post: &State) -> BTreeSet<Slot> {
        let w = diff(s, post);
        let mut c = s.rdep_closure(&w);
        c.extend(post.rdep_closure(&w));
        c.extend(self.reads());
        c
    }
}

/// Apply operations in order and validate once at the end. Total: returns
/// the new state or the reason. Cost follows the edited units and their
/// dependents, not the size of the state.
pub fn apply(s: &State, ops: &[Op]) -> Result<State, ApplyError> {
    let mut e = s.edit();
    for op in ops {
        match op {
            Op::Put { slot, unit } => e.set(slot.clone(), Some(unit.clone())),
            Op::Del { slot } => {
                if !e.contains(slot) {
                    return Err(ApplyError::NoSuchSlot(slot.clone()));
                }
                e.set(slot.clone(), None);
            }
            Op::Rename { from, to } => {
                if from == to {
                    continue;
                }
                let Some(u) = e.get(from).cloned() else {
                    return Err(ApplyError::NoSuchSlot(from.clone()));
                };
                if e.contains(to) {
                    return Err(ApplyError::SlotTaken(to.clone()));
                }
                let users = e.users(from);
                e.set(from.clone(), None);
                e.set(to.clone(), Some(u));
                for w in users {
                    if let Some(mut wu) = e.get(&w).cloned() {
                        for d in wu.deps.iter_mut() {
                            if d == from {
                                *d = to.clone();
                            }
                        }
                        e.set(w, Some(wu));
                    }
                }
            }
        }
    }
    e.finish().map_err(ApplyError::Wf)
}

/// Commutation test (Definition 6): neither change writes into the other's
/// closure in `s`.
pub fn commutes(a: &Change, b: &Change, s: &State) -> bool {
    let (wa, wb) = (a.writes(s), b.writes(s));
    let (ca, cb) = (a.closure(s), b.closure(s));
    wa.is_disjoint(&cb) && wb.is_disjoint(&ca)
}
