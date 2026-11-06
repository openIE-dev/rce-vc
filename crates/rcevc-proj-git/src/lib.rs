//! # rcevc-proj-git
//!
//! Π_git, the Git projection of RCE-VC (milestone M2). Admitted states are
//! ordinary Git commits; plain Git commits are ingested as changes. This is
//! the interface-compatibility layer: nobody has to stop using Git for RCE-VC
//! to sit underneath.
//!
//! Std-only: SHA-1, zlib inflate and loose-object I/O are implemented here.
//! In a networked build these are delegated to `gix`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod project;
pub mod store;

pub use project::{
    export, ingest, parse_unit, read_commit, read_tree, render_unit, trailer, write_commit, write_tree, Commit,
    Exported, HEADER,
};
pub use store::{GitDir, Oid, ProjError};
