//! Agents submit to RCE-VC; a person uses plain git; both meet on `main`.
//!
//! Run: `cargo run -p rcevc-proj-git --example git_roundtrip -- [dir]`
//! Then inspect with ordinary tools: `git -C <dir> log --stat main`,
//! `git -C <dir> log refs/rcevc/log`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use rcevc_core::*;
use rcevc_proj_git::*;

struct Join;
impl Proposer for Join {
    fn propose(&self, _: &str, _: Option<&Unit>, o: Option<&Unit>, t: Option<&Unit>) -> Option<Option<Unit>> {
        let (o, t) = (o?, t?);
        Some(Some(Unit { body: format!("{}{}", o.body, t.body), deps: o.deps.clone() }))
    }
}

fn git(dir: &PathBuf, args: &[&str]) -> String {
    let o = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=alice", "-c", "user.email=alice@example.com"])
        .args(args)
        .output()
        .expect("git must be installed for this example");
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir: PathBuf = std::env::args().nth(1).map(PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join("rcevc-demo"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;

    let mut genesis = Draft::new();
    genesis
        .put("README.md", Unit::new("# Demo\n", &[]))
        .put("src/parse.rs", Unit::new("pub fn parse(s: &str) -> u32 { s.len() as u32 }\n", &[]))
        .put("src/main.rs", Unit::new("fn main() { println!(\"{}\", $0(\"hi\")); }\n", &["src/parse.rs"]))
        .put("docs/notes.txt", Unit::new("notes\n", &[]));
    let gate = || Gate::new().with(Forbid { token: "BAD".into() });
    let mut repo = Repo::new(gate(), genesis.clone())?.with_proposer(Join);
    let g = GitDir::init(&dir)?;
    let t0 = 1_798_761_600;

    println!("1. Three agents and one person submit from the same base.");
    let r0 = repo.head_root();
    for (w, slot, body) in [
        ("agent-7", "src/util.rs", "pub fn id() {}\n"),
        ("agent-9", "docs/notes.txt", "notes\nagent-9\n"),
        ("bob", "docs/notes.txt", "notes\nbob\n"),
        ("agent-3", "src/bad.rs", "BAD\n"),
    ] {
        let o = repo.submit(Change::new(w, r0, Level::MeaningChange).message(format!("{slot}: update")).put(slot, Unit::new(body, &[])));
        println!("   {w:<8} {slot:<15} -> {} {:?}", if o.is_accepted() { "admit " } else { "refuse" }, o.path());
    }
    export(&g, &repo, &genesis, "main", t0)?;

    println!("\n2. Alice uses plain git on a branch.");
    git(&dir, &["reset", "-q", "--hard", "main"]);
    git(&dir, &["checkout", "-q", "-b", "alice/readme"]);
    fs::write(dir.join("README.md"), "# Demo\n\nNow with a real introduction.\n")?;
    git(&dir, &["commit", "-qam", "readme: intro"]);

    println!("3. Meanwhile an agent's change lands, so her base is stale.");
    let h = repo.head_root();
    repo.submit(Change::new("agent-1", h, Level::MeaningChange).message("util: return a value").put("src/util.rs", Unit::new("pub fn id() -> u8 { 0 }\n", &[])));

    let tip = g.read_ref("refs/heads/alice/readme").ok_or("no branch")?;
    let change = ingest(&g, &tip, &repo)?;
    let o = repo.submit(change);
    println!("   alice    README.md       -> {} {:?} (no rebase asked of her)", if o.is_accepted() { "admit " } else { "refuse" }, o.path());
    export(&g, &repo, &genesis, "main", t0)?;

    println!("\n4. What any Git tool now sees on main:\n");
    print!("{}", git(&dir, &["log", "--format=   %h %<(8)%an %s", "main"]));
    println!("\n   Receipt on the merge-resolved commit (git's own trailer parser):\n");
    let c = git(&dir, &["log", "-1", "--grep=G4Proposer", "--format=%(trailers)", "main"]);
    for l in c.lines().filter(|l| !l.is_empty()) {
        println!("   {l}");
    }
    println!("\n5. refs/rcevc/log keeps every entry, refusals included:\n");
    print!("{}", git(&dir, &["log", "--format=   %h %<(8)%an %s", "refs/rcevc/log"]).replace("log: ", ""));
    let fsck = Command::new("git").arg("-C").arg(&dir).args(["fsck", "--full", "--strict"]).output()?;
    println!("\n6. git fsck --full --strict: {}", if fsck.status.success() { "clean" } else { "FAILED" });
    println!("   repository: {}", dir.display());
    Ok(())
}
