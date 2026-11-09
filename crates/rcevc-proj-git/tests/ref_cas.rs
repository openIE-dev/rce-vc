//! Loose-ref compare-and-swap, distinct from blob integrity.

use std::fs;

use rcevc_core::sha256;
use rcevc_proj_git::{GitDir, Oid, RefCas, RefUpdateError};

fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("rcevc-cas-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn ref_cas_is_idempotent_and_a_blob_copy_is_not_a_ref_update() {
    let dir = scratch("cas");
    let git = GitDir::init(&dir).unwrap();
    let first = git.write("blob", b"first").unwrap();
    let second = git.write("blob", b"second").unwrap();
    let op = sha256(b"op-first");
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", op, None, first).unwrap(),
        RefCas::Applied { oid } if oid == first
    ));
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", op, None, first).unwrap(),
        RefCas::Replay { wrote, still_tip: true } if wrote == first
    ));
    let other = sha256(b"op-second");
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", other, None, second),
        Err(RefUpdateError::Stale { .. })
    ));
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", other, Some(first), second).unwrap(),
        RefCas::Applied { oid } if oid == second
    ));
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", op, None, first)
            .unwrap(),
        RefCas::Replay {
            still_tip: false,
            ..
        }
    ));
    assert_eq!(git.read_ref("refs/heads/main"), Some(second));

    let forged = sha256(b"op-forged");
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", forged, Some(first), second),
        Err(RefUpdateError::Unrelated { .. })
    ));

    let lock = git.path().join("refs/heads/main.lock");
    fs::write(&lock, b"held").unwrap();
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", sha256(b"op-busy"), Some(second), first),
        Err(RefUpdateError::Busy)
    ));
    fs::remove_file(&lock).unwrap();
    assert!(matches!(
        git.compare_and_swap_ref("heads/main", op, None, first),
        Err(RefUpdateError::RefusedName)
    ));

    let raw = fs::read(
        git.path()
            .join("objects")
            .join(&first.hex()[..2])
            .join(&first.hex()[2..]),
    )
    .unwrap();
    let mut broken = raw.clone();
    broken[0] ^= 0xff;
    fs::write(
        git.path()
            .join("objects")
            .join(&first.hex()[..2])
            .join(&first.hex()[2..]),
        &broken,
    )
    .unwrap();
    assert!(git.read(&first).is_err());
    let _ = dir;
}

#[test]
fn copied_loose_object_does_not_copy_the_ref_or_the_op_log() {
    let dir = scratch("copy");
    let source = GitDir::init(&dir.join("source")).unwrap();
    let dest = GitDir::init(&dir.join("dest")).unwrap();
    let oid = source.write("blob", b"same-bytes").unwrap();
    let op = sha256(b"op-copy");
    source
        .compare_and_swap_ref("refs/heads/main", op, None, oid)
        .unwrap();
    let hex = oid.hex();
    let from = source
        .path()
        .join("objects")
        .join(&hex[..2])
        .join(&hex[2..]);
    let to_dir = dest.path().join("objects").join(&hex[..2]);
    fs::create_dir_all(&to_dir).unwrap();
    fs::copy(from, to_dir.join(&hex[2..])).unwrap();
    assert!(dest.read(&oid).is_ok());
    assert_eq!(dest.read_ref("refs/heads/main"), None);
    assert!(!dest.path().join("rcevc-cas").exists());
}

#[test]
fn a_dotted_ref_name_is_the_file_that_moves() {
    let dir = scratch("dotted");
    let git = GitDir::init(&dir).unwrap();
    let oid = git.write("blob", b"tagged").unwrap();
    let op = sha256(b"dot-op");
    let name = "refs/tags/v1.2.3";
    git.compare_and_swap_ref(name, op, None, oid).unwrap();
    assert_eq!(git.read_ref(name), Some(oid));
    assert!(git.path().join("refs/tags/v1.2.3").is_file());
    assert!(!git.path().join("refs/tags/v1.2.tmp").exists());
    assert!(!git.path().join("refs/tags/v1.tmp").exists());
    let other = git.write("blob", b"other-tag").unwrap();
    assert!(matches!(
        git.compare_and_swap_ref(name, op, None, other),
        Err(RefUpdateError::OpRetarget { wrote, requested }) if wrote == oid && requested == other
    ));
    assert_eq!(git.read_ref(name), Some(oid));
}

#[test]
fn set_ref_does_not_write_through_a_held_lock() {
    let dir = scratch("set-lock");
    let git = GitDir::init(&dir).unwrap();
    let oid = git.write("blob", b"locked").unwrap();
    let lock = git.path().join("refs/heads/main.lock");
    fs::create_dir_all(lock.parent().unwrap()).unwrap();
    fs::write(&lock, b"held").unwrap();
    assert!(git.set_ref("refs/heads/main", &oid).is_err());
    assert_eq!(git.read_ref("refs/heads/main"), None);
    fs::remove_file(&lock).unwrap();
    git.set_ref("refs/heads/main", &oid).unwrap();
    assert_eq!(git.read_ref("refs/heads/main"), Some(oid));
}

#[test]
fn two_writers_cannot_both_apply_from_the_same_tip() {
    use std::sync::Arc;
    use std::thread;

    let dir = scratch("race");
    let git = GitDir::init(&dir).unwrap();
    let left = git.write("blob", b"left").unwrap();
    let right = git.write("blob", b"right").unwrap();
    let git = Arc::new(git);
    let one = Arc::clone(&git);
    let two = Arc::clone(&git);
    let op_left = sha256(b"race-left");
    let op_right = sha256(b"race-right");
    let h1 = thread::spawn(move || race_once(one, op_left, left));
    let h2 = thread::spawn(move || race_once(two, op_right, right));
    let a = h1.join().unwrap();
    let b = h2.join().unwrap();
    let applied = [&a, &b].into_iter().filter(|r| matches!(r, Ok(RefCas::Applied { .. }))).count();
    assert_eq!(applied, 1, "a={a:?} b={b:?}");
    let tip = git.read_ref("refs/heads/main");
    assert!(tip == Some(left) || tip == Some(right), "tip {tip:?}");
    let winner = if tip == Some(left) { op_left } else { op_right };
    let loser = if tip == Some(left) { op_right } else { op_left };
    let again = git
        .compare_and_swap_ref("refs/heads/main", winner, None, tip.unwrap())
        .unwrap();
    assert!(matches!(again, RefCas::Replay { still_tip: true, .. }));
    let loser_oid = if tip == Some(left) { right } else { left };
    assert!(matches!(
        git.compare_and_swap_ref("refs/heads/main", loser, None, loser_oid),
        Err(RefUpdateError::Stale { .. })
    ));
}

fn race_once(git: std::sync::Arc<GitDir>, op: rcevc_core::Digest, oid: Oid) -> Result<RefCas, RefUpdateError> {
    for _ in 0..64 {
        match git.compare_and_swap_ref("refs/heads/main", op, None, oid) {
            Err(RefUpdateError::Busy) => std::thread::yield_now(),
            other => return other,
        }
    }
    Err(RefUpdateError::Busy)
}
