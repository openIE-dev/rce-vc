//! Interop against the real `git` binary. Skips (with a message) if git is
//! not installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rcevc_core::*;
use rcevc_proj_git::*;

const T0: i64 = 1_798_761_600; // 2027-01-01T00:00:00Z, a fixed time base

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=alice", "-c", "user.email=alice@example.com", "-c", "init.defaultBranch=main"])
        .args(args)
        .output()
        .expect("run git");
    assert!(o.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rcevc-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

struct Join;
impl Proposer for Join {
    fn propose(&self, _: &str, _: Option<&Unit>, o: Option<&Unit>, t: Option<&Unit>) -> Option<Option<Unit>> {
        let (o, t) = (o?, t?);
        Some(Some(Unit { body: format!("{}{}", o.body, t.body), deps: o.deps.clone() }))
    }
}

fn gate() -> Gate {
    Gate::new().with(Forbid { token: "BAD".into() })
}

fn genesis() -> Draft {
    let mut g = Draft::new();
    g.put("README.md", Unit::new("# Demo\n\nShell users: echo $1 and $HOME stay literal.\n", &[]))
        .put("src/parse.rs", Unit::new("pub fn parse(s: &str) -> u32 { s.len() as u32 }\n", &[]))
        .put("src/main.rs", Unit::new("fn main() { println!(\"{}\", $0(\"hi\")); }\n", &["src/parse.rs"]))
        .put("docs/notes.txt", Unit::new("notes\n", &[]));
    g
}

fn build_repo() -> Repo {
    let mut r = Repo::new(gate(), genesis()).unwrap().with_proposer(Join);
    let r0 = r.head_root();
    r.submit(Change::new("agent-7", r0, Level::MeaningChange).put("src/util.rs", Unit::new("pub fn id() {}\n", &[])));
    r.submit(Change::new("agent-9", r0, Level::MeaningChange).put("docs/notes.txt", Unit::new("notes\nagent-9\n", &[])));
    r.submit(Change::new("bob", r0, Level::MeaningChange).put("docs/notes.txt", Unit::new("notes\nbob\n", &[])));
    r.submit(Change::new("agent-3", r0, Level::MeaningChange).put("src/bad.rs", Unit::new("BAD\n", &[])));
    r
}

#[test]
fn units_round_trip_through_files() {
    let cases = [
        Unit::new("plain text", &[]),
        Unit::new("literal $1 and $$", &[]),
        Unit::new(format!("{HEADER}looks like a header"), &[]),
        Unit::new("uses $0 and $1, and $$5 literally", &["a/b", "c"]),
        Unit::new("", &[]),
    ];
    for u in cases {
        assert_eq!(parse_unit("x", &render_unit(&u)).unwrap(), u);
    }
}

#[test]
fn export_is_valid_git_round_trips_and_is_reproducible() {
    if !git_available() {
        eprintln!("git not installed; skipping");
        return;
    }
    let repo = build_repo();
    let dir = tmp("export");
    let g = GitDir::init(&dir).unwrap();
    let ex = export(&g, &repo, &genesis(), "main", T0).unwrap();

    // Git accepts every object under its strictest check.
    let fsck = Command::new("git").arg("-C").arg(&dir).args(["fsck", "--full", "--strict"]).output().unwrap();
    assert!(fsck.status.success(), "fsck: {}", String::from_utf8_lossy(&fsck.stderr));

    // main holds only admitted states; refs/rcevc/log holds every entry.
    let accepted = repo.log().iter().filter(|e| e.outcome.is_accepted()).count();
    assert_eq!(git(&dir, &["rev-list", "--count", "main"]).trim(), (accepted + 1).to_string());
    assert_eq!(git(&dir, &["rev-list", "--count", "refs/rcevc/log"]).trim(), (repo.log().len() + 1).to_string());
    assert_eq!(ex.admitted, accepted + 1);

    // Git sees the files as written, and its trailer parser reads receipts.
    assert_eq!(git(&dir, &["show", "main:docs/notes.txt"]), "notes\nagent-9\nnotes\nbob\n");
    let main_rs = git(&dir, &["show", "main:src/main.rs"]);
    assert!(main_rs.starts_with(HEADER) && main_rs.contains("#dep src/parse.rs"));
    let path = git(&dir, &["log", "-1", "--format=%(trailers:key=RCE-VC-Path,valueonly)", "main"]);
    assert!(path.contains("G4Proposer"), "{path}");
    let reasons = git(&dir, &["log", "--format=%(trailers:key=RCE-VC-Reason,valueonly)", "refs/rcevc/log"]);
    assert!(reasons.contains("Gate"), "{reasons}");

    // Every commit on main re-imports to exactly the root its receipt names.
    let mut cur = Some(ex.main);
    let mut seen = 0;
    while let Some(o) = cur {
        let c = read_commit(&g, &o).unwrap();
        let want = Digest::from_hex(trailer(&c.message, "RCE-VC-Post").unwrap()).unwrap();
        assert_eq!(read_tree(&g, &c.tree).unwrap().seal().unwrap().root(), want);
        seen += 1;
        cur = c.parents.first().copied();
    }
    assert_eq!(seen, accepted + 1);

    // Same log, same time base: byte-identical history elsewhere.
    let dir2 = tmp("export2");
    let ex2 = export(&GitDir::init(&dir2).unwrap(), &repo, &genesis(), "main", T0).unwrap();
    assert_eq!(ex.main, ex2.main);
    assert_eq!(ex.log, ex2.log);
    let _ = fs::remove_dir_all(dir2);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_plain_git_commit_is_ingested_and_admitted_through_the_ladder() {
    if !git_available() {
        eprintln!("git not installed; skipping");
        return;
    }
    let mut repo = build_repo();
    let dir = tmp("ingest");
    let g = GitDir::init(&dir).unwrap();
    let first = export(&g, &repo, &genesis(), "main", T0).unwrap();

    // A person works with ordinary git on a branch.
    git(&dir, &["reset", "-q", "--hard", "main"]);
    git(&dir, &["checkout", "-q", "-b", "alice/readme"]);
    let mut long = String::from("# Demo\n\n");
    for i in 0..400 {
        long.push_str(&format!("Line {i}: the quick brown fox {} jumps over {} lazy dogs.\n", i * 7 % 13, i % 5));
    }
    fs::write(dir.join("README.md"), &long).unwrap();
    fs::write(dir.join("docs/alice.txt"), "alice was here\n").unwrap();
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "readme: expand"]);
    fs::remove_file(dir.join("docs/alice.txt")).unwrap();
    fs::write(dir.join("docs/alice.md"), "alice was here\n").unwrap();
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "docs: rename"]);
    let tip = g.read_ref("refs/heads/alice/readme").unwrap();

    // Meanwhile an agent's change is admitted, so alice's base is now stale.
    let head = repo.head_root();
    assert!(repo.submit(Change::new("agent-1", head, Level::MeaningChange).put("src/util.rs", Unit::new("pub fn id() -> u8 { 0 }\n", &[]))).is_accepted());

    // Ingest reads git's own zlib-compressed objects (dynamic Huffman for the
    // long README) and folds both commits into one change.
    let change = ingest(&g, &tip, &repo).unwrap();
    assert_eq!(change.writer, "alice");
    assert_eq!(change.message, "readme: expand\n\ndocs: rename");
    assert_eq!(change.ops.len(), 2, "README.md and docs/alice.md; alice.txt never reached main");
    let o = repo.submit(change);
    assert!(o.is_accepted(), "{o:?}");
    assert_eq!(o.path(), &[Gear::G1Commute], "disjoint from the agent's change");
    assert_eq!(repo.head().get("README.md").unwrap().body, long);

    // Re-export fast-forwards main; history stays valid.
    let second = export(&g, &repo, &genesis(), "main", T0).unwrap();
    git(&dir, &["merge-base", "--is-ancestor", &first.main.hex(), &second.main.hex()]);
    let fsck = Command::new("git").arg("-C").arg(&dir).args(["fsck", "--full", "--strict"]).output().unwrap();
    assert!(fsck.status.success(), "fsck: {}", String::from_utf8_lossy(&fsck.stderr));
    assert_eq!(git(&dir, &["log", "-1", "--format=%an|%s", "main"]).trim(), "alice|readme: expand");

    // A commit with a forbidden token is refused, recorded on the log ref, and main does not move.
    git(&dir, &["checkout", "-q", "-b", "mallory/x", "main"]);
    fs::write(dir.join("src/evil.rs"), "BAD\n").unwrap();
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "-m", "x"]);
    let tip = g.read_ref("refs/heads/mallory/x").unwrap();
    let o = repo.submit(ingest(&g, &tip, &repo).unwrap());
    assert!(matches!(o.reason(), Some(Reason::Gate { .. })));
    let third = export(&g, &repo, &genesis(), "main", T0).unwrap();
    assert_eq!(third.main, second.main);
    assert_ne!(third.log, second.log);
    let _ = fs::remove_dir_all(dir);
}
