//! The gate (part G) and its checkers (part K).
//!
//! Every checker makes its statements, after RCE Compile: the property class
//! it decides, the linking assumption, its trusted base, its evidence
//! authority, its **scope**, and a digest over all of it. A checker must be
//! deterministic: same state in, same verdict out.
//!
//! Scope is what lets the gate stay O(change) without weakening VC2:
//! - [`Scope::Unit`]: the verdict on a unit depends only on that unit. After
//!   an edit, only edited units are re-checked.
//! - [`Scope::Closure`]: the verdict on a unit depends on the unit and its
//!   transitive dependencies. Edited units *and their dependents* are
//!   re-checked.
//! - [`Scope::Global`]: anything else; the whole state is checked.
//!
//! Since the previous head passed (induction hypothesis), re-checking the
//! declared scope of the delta is equivalent to checking everything,
//! provided the checker's declared scope is true. That proviso is part of
//! its linking assumption and is digest-covered. The planned `rcevc-gate`
//! crate runs checkers under Wasmtime with fuel limits and can enforce
//! scope by only exposing the declared slice of the state.

use std::collections::BTreeSet;

use crate::hash::{Digest, Enc};
use crate::model::{Slot, State, Unit};

/// Where a checker's evidence comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Authority {
    /// A pinned external tool at a recorded version.
    Pinned,
    /// Re-execution of recorded inputs.
    Replay,
    /// Decided exactly by construction or proof.
    Proved,
    /// Derived from other evidence by a stated rule.
    Derived,
    /// Inferred by a statistical component (a model). Never sufficient alone.
    Inferred,
}

impl Authority {
    fn code(self) -> u8 {
        self as u8
    }
}

/// What a verdict depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// The unit alone.
    Unit,
    /// The unit and its transitive dependencies.
    Closure,
    /// The whole state.
    Global,
}

/// What a checker must state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Checker name.
    pub name: String,
    /// What property class it decides.
    pub property_class: String,
    /// What must hold for its verdict to carry over to the running system.
    pub linking_assumption: String,
    /// What is trusted.
    pub trusted_base: String,
    /// Evidence authority.
    pub authority: Authority,
    /// What a verdict depends on.
    pub scope: Scope,
    /// Version string, covered by the digest.
    pub version: String,
}

impl Statement {
    /// Digest of every statement.
    pub fn digest(&self) -> Digest {
        let mut e = Enc::new("rcevc/checker/v2");
        e.str(&self.name)
            .str(&self.property_class)
            .str(&self.linking_assumption)
            .str(&self.trusted_base)
            .u8(self.authority.code())
            .u8(self.scope as u8)
            .str(&self.version);
        e.finish()
    }
}

/// A deterministic checker.
pub trait Checker {
    /// Its statements.
    fn statement(&self) -> Statement;
    /// Verdict on one unit in its state (`Unit` and `Closure` scope).
    fn check_unit(&self, _state: &State, _slot: &str, _unit: &Unit) -> Result<(), String> {
        Ok(())
    }
    /// Verdict on the whole state (`Global` scope).
    fn check_global(&self, _state: &State) -> Result<(), String> {
        Ok(())
    }
}

/// Evidence that one checker accepted a state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Checker name.
    pub checker: String,
    /// Statement digest.
    pub digest: Digest,
    /// Authority of the evidence.
    pub authority: Authority,
    /// Units examined (`None`: whole state).
    pub examined: Option<usize>,
}

/// An ordered set of checkers. All must accept.
#[derive(Default)]
pub struct Gate {
    checkers: Vec<Box<dyn Checker>>,
}

impl Gate {
    /// The empty gate (accepts every well-formed state).
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a checker.
    pub fn with(mut self, c: impl Checker + 'static) -> Self {
        self.checkers.push(Box::new(c));
        self
    }
    /// Number of checkers.
    pub fn len(&self) -> usize {
        self.checkers.len()
    }
    /// Whether the gate has no checkers.
    pub fn is_empty(&self) -> bool {
        self.checkers.is_empty()
    }
    /// Digest of the gate: the ordered checker digests.
    pub fn digest(&self) -> Digest {
        let mut e = Enc::new("rcevc/gate/v2");
        e.u64(self.checkers.len() as u64);
        for c in &self.checkers {
            e.digest(&c.statement().digest());
        }
        e.finish()
    }
    /// Check everything.
    pub fn run(&self, s: &State) -> Result<Vec<Evidence>, (String, String)> {
        self.run_scoped(s, None)
    }
    /// Check what `delta` (the units changed since an accepted state) can affect.
    pub fn run_delta(&self, s: &State, delta: &BTreeSet<Slot>) -> Result<Vec<Evidence>, (String, String)> {
        self.run_scoped(s, Some(delta))
    }

    fn run_scoped(&self, s: &State, delta: Option<&BTreeSet<Slot>>) -> Result<Vec<Evidence>, (String, String)> {
        let all: Option<BTreeSet<Slot>> = delta.is_none().then(|| s.slots().into_iter().cloned().collect());
        let mut closure: Option<BTreeSet<Slot>> = None;
        let mut ev = Vec::with_capacity(self.checkers.len());
        for c in &self.checkers {
            let st = c.statement();
            let examined = match (st.scope, delta) {
                (Scope::Global, _) => {
                    c.check_global(s).map_err(|m| (st.name.clone(), m))?;
                    None
                }
                (scope, _) => {
                    let set: &BTreeSet<Slot> = match (scope, delta) {
                        (_, None) => all.as_ref().expect("full run"),
                        (Scope::Unit, Some(d)) => d,
                        (_, Some(d)) => closure.get_or_insert_with(|| s.rdep_closure(d)),
                    };
                    let mut n = 0;
                    for slot in set {
                        if let Some(u) = s.get(slot) {
                            c.check_unit(s, slot, u).map_err(|m| (st.name.clone(), m))?;
                            n += 1;
                        }
                    }
                    Some(n)
                }
            };
            ev.push(Evidence { checker: st.name.clone(), digest: st.digest(), authority: st.authority, examined });
        }
        Ok(ev)
    }
}

/// Refuses any unit whose body contains `token`.
pub struct Forbid {
    /// The forbidden substring.
    pub token: String,
}

impl Checker for Forbid {
    fn statement(&self) -> Statement {
        Statement {
            name: format!("forbid:{}", self.token),
            property_class: "syntactic: no unit body contains the token".into(),
            linking_assumption: "checked on the exact post-state that is admitted".into(),
            trusted_base: "rcevc-core substring search".into(),
            authority: Authority::Proved,
            scope: Scope::Unit,
            version: "1".into(),
        }
    }
    fn check_unit(&self, _: &State, slot: &str, u: &Unit) -> Result<(), String> {
        if u.body.contains(&self.token) { Err(format!("{slot} contains {:?}", self.token)) } else { Ok(()) }
    }
}

/// A per-unit checker from a plain function and its statement
/// (`Unit` or `Closure` scope).
pub struct FnChecker {
    /// The statements.
    pub statement: Statement,
    /// The decision procedure for one unit.
    pub f: fn(&State, &str, &Unit) -> Result<(), String>,
}

impl Checker for FnChecker {
    fn statement(&self) -> Statement {
        self.statement.clone()
    }
    fn check_unit(&self, s: &State, slot: &str, u: &Unit) -> Result<(), String> {
        (self.f)(s, slot, u)
    }
}
