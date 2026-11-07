//! Measurements from one isolated workspace.
//!
//! [`measure_isolated`] times a fixed local workload and runs cache and ref
//! adversaries in the same call. The wall times are samples from that call.
//! They are not a rate, a speed-up, or a result for any other machine.
//! [`rcevc_core::assure::PhysicalEnergy`] stays unknown: this process has no
//! electricity meter, and a receipt's stated `est_uj` is not converted.

use std::fs;
use std::io;
use std::path::Path;
use std::time::Instant;

use rcevc_core::assure::{
    ActionCache, ActionQuery, AssureError, ContentStore, DependencyManifest, Lookup, PhysicalEnergy,
};
use rcevc_core::{Change, Draft, Gate, Level, Repo, Unit, sha256};

use crate::store::{GitDir, Oid, RefCas};

/// What one call of [`measure_isolated`] observed.
///
/// `cold_wall_ns` and `warm_wall_ns` are the only timings, and only for the
/// workload named in [`IsolateReport::workload`]. There is no joule field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsolateReport {
    /// `std::env::consts::ARCH` of this process.
    pub arch: &'static str,
    /// `std::env::consts::OS` of this process.
    pub os: &'static str,
    /// `cfg!(debug_assertions)` of this build.
    pub debug_assertions: bool,
    /// The timed work, and nothing else.
    pub workload: &'static str,
    /// Which caches the timed work and the adversaries were allowed to see.
    pub cache_boundary: &'static str,
    /// Crates and network used by this process.
    pub dependency_boundary: &'static str,
    /// Where the files were written.
    pub target_boundary: &'static str,
    /// Electricity. Unknown in this crate, including when `est_uj` is zero.
    pub physical_energy: PhysicalEnergy,
    /// Wall time of the cold pass, in nanoseconds, from `Instant`.
    pub cold_wall_ns: u128,
    /// Wall time of the warm pass, in nanoseconds, from `Instant`.
    pub warm_wall_ns: u128,
    /// Blobs written on the cold pass.
    pub blob_count: usize,
    /// An untrusted action row was not a hit, while the blob still read back.
    pub poison_rejected: bool,
    /// Bytes planted under the wrong digest did not read back as that digest.
    pub corrupt_blob_rejected: bool,
    /// A second workspace with a copied blob did not see the first action cache.
    pub isolation_held: bool,
    /// A second writer advanced the ref; the first op's retry was not still at the tip.
    pub stale_cas_rejected: bool,
    /// Before that advance, a retry of the successful op was still at the tip.
    pub replay_still_tip: bool,
}

const BLOB_COUNT: usize = 32;

/// Delete and recreate `root`, then measure and run the adversaries.
///
/// `root` is a scratch directory. The function removes it first.
pub fn measure_isolated(root: &Path) -> io::Result<IsolateReport> {
    if root.exists() {
        fs::remove_dir_all(root)?;
    }
    fs::create_dir_all(root)?;
    let cold_dir = root.join("cold");
    let warm_note = root.join("warm-marker");
    fs::write(
        &warm_note,
        b"warm pass reuses the cold git dir and content store\n",
    )?;

    let mut store = ContentStore::new();
    let git = GitDir::init(&cold_dir)?;
    let op_cold = sha256(b"rcevc-isolate-op-cold");

    let cold_start = Instant::now();
    let oid = write_blobs(&git, &mut store, BLOB_COUNT)?;
    git.compare_and_swap_ref("refs/heads/main", op_cold, None, oid)
        .map_err(io_ref)?;
    let cold_wall_ns = cold_start.elapsed().as_nanos();

    let warm_start = Instant::now();
    let oid_again = write_blobs(&git, &mut store, BLOB_COUNT)?;
    let replay = git
        .compare_and_swap_ref("refs/heads/main", op_cold, None, oid_again)
        .map_err(io_ref)?;
    let warm_wall_ns = warm_start.elapsed().as_nanos();
    let replay_still_tip =
        matches!(replay, RefCas::Replay { wrote, still_tip: true } if wrote == oid);

    let stated = stated_est_uj()?;
    let (poison_rejected, corrupt_blob_rejected) = poison_and_corrupt(&mut store);
    let isolation_held = isolation(&git, &oid, root)?;
    let stale_cas_rejected = stale_ref(&git, oid)?;

    Ok(IsolateReport {
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        debug_assertions: cfg!(debug_assertions),
        workload: "32 loose git blobs (56 bytes each) and one ref compare-and-swap, then the same writes and the same op id",
        cache_boundary: "in-process ContentStore and ActionCache; loose git objects in this scratch directory; no remote cache",
        dependency_boundary: "std only; no crates.io dependency; no network",
        target_boundary: "the scratch directory passed to measure_isolated; this process only",
        physical_energy: PhysicalEnergy::not_from_semantic_fuel(stated),
        cold_wall_ns,
        warm_wall_ns,
        blob_count: BLOB_COUNT,
        poison_rejected,
        corrupt_blob_rejected,
        isolation_held,
        stale_cas_rejected,
        replay_still_tip,
    })
}

fn blob_bytes(i: usize) -> Vec<u8> {
    format!("blob-{i:02}-{}", "x".repeat(48)).into_bytes()
}

fn write_blobs(git: &GitDir, store: &mut ContentStore, n: usize) -> io::Result<Oid> {
    let mut last = None;
    for i in 0..n {
        let bytes = blob_bytes(i);
        store.put(&bytes);
        last = Some(git.write("blob", &bytes)?);
    }
    last.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no blobs"))
}

fn stated_est_uj() -> io::Result<u64> {
    let mut draft = Draft::new();
    draft.put("a", Unit::new("a", &[]));
    let mut repo = Repo::new(Gate::new(), draft)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let base = repo.head_root();
    let outcome = repo.submit(
        Change::new("meter-absent", base, Level::MeaningChange).put("b", Unit::new("b", &[])),
    );
    Ok(outcome.est_uj())
}

fn poison_and_corrupt(store: &mut ContentStore) -> (bool, bool) {
    let bytes = b"checked-looking-bytes";
    let digest = store.put(bytes);
    let mut cache = ActionCache::new();
    let deps = DependencyManifest::complete(&["std"]).digest();
    let query = ActionQuery {
        gate: sha256(b"gate"),
        head: sha256(b"head"),
        base: sha256(b"base"),
        change: sha256(b"change"),
        inputs: &[],
        dependencies: deps,
    };
    let planted = cache.plant_untrusted(query, digest);
    let lookup_rejects = matches!(
        cache.lookup(query, store),
        Lookup::Reject(AssureError::UntrustedInsert)
    );
    let blob_ok = store.get(&digest).ok() == Some(bytes.as_slice());
    store.plant_unverified(digest, b"truncated".to_vec());
    let corrupt = matches!(store.get(&digest), Err(AssureError::CorruptOutput));
    (planted && lookup_rejects && blob_ok, corrupt)
}

fn isolation(git: &GitDir, oid: &Oid, root: &Path) -> io::Result<bool> {
    let other_dir = root.join("other");
    let other = GitDir::init(&other_dir)?;
    let hex = oid.hex();
    let src = git.path().join("objects").join(&hex[..2]).join(&hex[2..]);
    let dst_dir = other.path().join("objects").join(&hex[..2]);
    fs::create_dir_all(&dst_dir)?;
    fs::copy(&src, dst_dir.join(&hex[2..]))?;
    let copied = other.read(oid).is_ok();
    let foreign = ActionCache::new();
    let deps = DependencyManifest::complete(&[]).digest();
    let missed = matches!(
        foreign.lookup(
            ActionQuery {
                gate: sha256(b"gate"),
                head: sha256(b"head"),
                base: sha256(b"base"),
                change: sha256(b"change"),
                inputs: &[],
                dependencies: deps,
            },
            &ContentStore::new()
        ),
        Lookup::Miss
    );
    let ref_stayed = other.read_ref("refs/heads/main").is_none();
    let op_log_stayed = !other.path().join("rcevc-cas").exists();
    Ok(copied && missed && ref_stayed && op_log_stayed)
}

fn stale_ref(git: &GitDir, current: Oid) -> io::Result<bool> {
    let next = git.write("blob", b"second-writer")?;
    let op_next = sha256(b"rcevc-isolate-op-next");
    let op_cold = sha256(b"rcevc-isolate-op-cold");
    git.compare_and_swap_ref("refs/heads/main", op_next, Some(current), next)
        .map_err(io_ref)?;
    let replay = git
        .compare_and_swap_ref("refs/heads/main", op_cold, None, current)
        .map_err(io_ref)?;
    Ok(matches!(
        replay,
        RefCas::Replay {
            still_tip: false,
            ..
        }
    ) && git.read_ref("refs/heads/main") == Some(next))
}

fn io_ref(err: crate::store::RefUpdateError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}
