//! Loose-ref compare-and-swap, distinct from blob integrity.

use std::fs;

use rcevc_core::sha256;
use rcevc_proj_git::{GitDir, RefCas, RefUpdateError};

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
