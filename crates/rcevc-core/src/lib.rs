//! # rcevc-core
//!
//! The dependency-free core of RCE-VC, the Law of Version Control:
//!
//! > Version control is the admission of changes to a canonical, name-free
//! > repository state. Each change is admitted only when a named checker
//! > accepts the post-state under a declared contract, or is refused with a
//! > recorded reason; changes whose dependency closures do not meet are
//! > admitted without coordination; among admissible integrations, a stated
//! > cost ranks the candidates; and every accepted result, including every
//! > resolved conflict, is reused.
//!
//! Parts of the repository Form implemented here: R (name-free keys,
//! [`model`]), Δ (typed changes, [`change`]), D (hash-chained log, [`repo`]),
//! K and G (checkers and gate, [`gate`]), X (commutation, [`change::commutes`]),
//! U (reuse and promotion, inside [`repo::Repo`]) and C (stated cost,
//! [`repo::CostTable`]). Projections (Π) and storage live in other crates.
//!
//! State is a persistent Merkle HAMT ([`hamt`]): snapshots share structure,
//! roots are O(1), diffs cost O(difference), and every step of the ladder
//! works on diffs, so integration cost follows the change, not the repository.
//!
//! No clock, no randomness, no I/O, no `unsafe`, no dependencies.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod change;
pub mod gate;
pub mod hamt;
pub mod hash;
pub mod model;
pub mod repo;

pub use change::{apply, commutes, Change, Level, Op};
pub use gate::{Authority, Checker, Evidence, FnChecker, Forbid, Gate, Scope, Statement};
pub use hash::{sha256, Digest};
pub use model::{diff, ApplyError, Draft, Edit, Slot, State, Unit, WfError};
pub use repo::{verify_chain, CostTable, Entry, Gear, Outcome, Proposer, Reason, Receipt, Refusal, Repo, ReplayError};
