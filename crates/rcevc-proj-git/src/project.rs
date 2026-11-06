//! Π_git: the projection between RCE-VC and Git.
//!
//! **Out** (`export`): every admitted state becomes a commit on a branch,
//! so `main` is ordinary Git history that any tool can clone, diff, blame
//! or build. Each commit carries its receipt as Git trailers. A second
//! chain, `refs/rcevc/log`, has one commit per log entry, refusals
//! included, so nothing is in limbo even when seen only through Git.
//! Export is a pure function of the log and a time base: the same log
//! always yields the same commit ids (reproducible history).
//!
//! **In** (`ingest`): any commit whose first-parent ancestry reaches an
//! admitted commit becomes one `Change` against that admitted state. A
//! person or an agent can keep using plain `git commit` on a branch; the
//! branch is the proposal, and the ladder decides.
//!
//! Files map to units: a file is a leaf unit (literal text). A unit with
//! dependencies is written as a small header (`#rcevc-unit v1`, `#dep`
//! lines, `#body`) followed by its body. The mapping is a bijection on
//! UTF-8 files, so every tree round-trips to the same state root.

use std::collections::BTreeMap;

use rcevc_core::{Change, Digest, Draft, Entry, Gear, Level, Op, Outcome, Receipt, Refusal, Repo, State, Unit};

use crate::store::{GitDir, Oid, ProjError};

/// First line of a unit file that has dependencies.
pub const HEADER: &str = "#rcevc-unit v1\n";

/// Bytes of the file for a unit.
pub fn render_unit(u: &Unit) -> Vec<u8> {
    if u.is_leaf() && !u.body.starts_with(HEADER) {
        return u.body.as_bytes().to_vec();
    }
    let mut s = String::from(HEADER);
    for d in &u.deps {
        s.push_str("#dep ");
        s.push_str(d);
        s.push('\n');
    }
    s.push_str("#body\n");
    s.push_str(&u.body);
    s.into_bytes()
}

/// Unit for the bytes of a file.
pub fn parse_unit(path: &str, bytes: &[u8]) -> Result<Unit, ProjError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ProjError::NonUtf8(path.to_string()))?;
    let Some(mut rest) = text.strip_prefix(HEADER) else {
        return Ok(Unit { body: text.to_string(), deps: Vec::new() });
    };
    let mut deps = Vec::new();
    loop {
        if let Some(body) = rest.strip_prefix("#body\n") {
            return Ok(Unit { body: body.to_string(), deps });
        }
        let bad = || ProjError::Corrupt(format!("{path}: bad unit header"));
        let (line, r) = rest.split_once('\n').ok_or_else(bad)?;
        deps.push(line.strip_prefix("#dep ").ok_or_else(bad)?.to_string());
        rest = r;
    }
}

enum Node {
    File(Vec<u8>),
    Dir(BTreeMap<String, Node>),
}

fn check_segment(path: &str, seg: &str) -> Result<(), ProjError> {
    if seg.is_empty() || seg == "." || seg == ".." || seg.eq_ignore_ascii_case(".git") || seg.contains(['\0', '\n']) {
        return Err(ProjError::Path(format!("slot {path:?} is not a valid path")));
    }
    Ok(())
}

fn insert(root: &mut BTreeMap<String, Node>, path: &str, bytes: Vec<u8>) -> Result<(), ProjError> {
    let segs: Vec<&str> = path.split('/').collect();
    for s in &segs {
        check_segment(path, s)?;
    }
    let (last, dirs) = segs.split_last().expect("split yields at least one segment");
    let mut cur = root;
    for seg in dirs {
        let n = cur.entry(seg.to_string()).or_insert_with(|| Node::Dir(BTreeMap::new()));
        cur = match n {
            Node::Dir(m) => m,
            Node::File(_) => return Err(ProjError::Path(format!("{path}: {seg} is a file"))),
        };
    }
    if cur.contains_key(*last) {
        return Err(ProjError::Path(format!("{path}: file/directory clash")));
    }
    cur.insert(last.to_string(), Node::File(bytes));
    Ok(())
}

fn write_node(g: &GitDir, map: &BTreeMap<String, Node>) -> Result<Oid, ProjError> {
    let mut entries: Vec<(Vec<u8>, &str, &str, Oid)> = Vec::new();
    for (name, node) in map {
        let (mode, oid, key) = match node {
            Node::File(b) => ("100644", g.write("blob", b)?, name.as_bytes().to_vec()),
            Node::Dir(m) => ("40000", write_node(g, m)?, [name.as_bytes(), b"/"].concat()),
        };
        entries.push((key, mode, name, oid));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut data = Vec::new();
    for (_, mode, name, oid) in entries {
        data.extend_from_slice(format!("{mode} {name}\0").as_bytes());
        data.extend_from_slice(&oid.0);
    }
    Ok(g.write("tree", &data)?)
}

/// Write a state as a Git tree.
pub fn write_tree(g: &GitDir, s: &State) -> Result<Oid, ProjError> {
    let mut root = BTreeMap::new();
    for (slot, unit) in s.iter() {
        insert(&mut root, slot, render_unit(unit))?;
    }
    write_node(g, &root)
}

/// Read a Git tree as a draft (validate with [`Draft::seal`]).
pub fn read_tree(g: &GitDir, tree: &Oid) -> Result<Draft, ProjError> {
    let mut s = Draft::new();
    read_into(g, tree, "", &mut s)?;
    Ok(s)
}

fn read_into(g: &GitDir, tree: &Oid, prefix: &str, s: &mut Draft) -> Result<(), ProjError> {
    let (kind, data) = g.read(tree)?;
    if kind != "tree" {
        return Err(ProjError::Corrupt(format!("{tree:?} is a {kind}, not a tree")));
    }
    let bad = || ProjError::Corrupt(format!("tree {tree:?}"));
    let mut i = 0;
    while i < data.len() {
        let sp = i + data[i..].iter().position(|&b| b == b' ').ok_or_else(bad)?;
        let nul = sp + data[sp..].iter().position(|&b| b == 0).ok_or_else(bad)?;
        let oid_bytes: [u8; 20] = data.get(nul + 1..nul + 21).ok_or_else(bad)?.try_into().map_err(|_| bad())?;
        let (mode, name) = (&data[i..sp], std::str::from_utf8(&data[sp + 1..nul]).map_err(|_| bad())?);
        let oid = Oid(oid_bytes);
        let path = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        match mode {
            b"40000" => read_into(g, &oid, &path, s)?,
            b"100644" | b"100755" => {
                let (k, bytes) = g.read(&oid)?;
                if k != "blob" {
                    return Err(bad());
                }
                s.put(path.clone(), parse_unit(&path, &bytes)?);
            }
            b"120000" => return Err(ProjError::Unsupported(format!("{path}: symlink"))),
            b"160000" => return Err(ProjError::Unsupported(format!("{path}: submodule"))),
            _ => return Err(bad()),
        }
        i = nul + 21;
    }
    Ok(())
}

/// A parsed commit.
#[derive(Debug, Clone)]
pub struct Commit {
    /// Root tree.
    pub tree: Oid,
    /// Parents in order.
    pub parents: Vec<Oid>,
    /// Author name.
    pub author: String,
    /// Full message.
    pub message: String,
}

fn ident(s: &str) -> String {
    let t: String = s.chars().map(|c| if matches!(c, '<' | '>' | '\n' | '\r') { '_' } else { c }).collect();
    let t = t.trim().to_string();
    if t.is_empty() { "unknown".into() } else { t }
}

fn email_local(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '-' }).collect()
}

/// Write a commit. Deterministic in all arguments.
pub fn write_commit(g: &GitDir, tree: Oid, parents: &[Oid], author: &str, time: i64, message: &str) -> Result<Oid, ProjError> {
    let name = ident(author);
    let mut t = format!("tree {tree}\n");
    for p in parents {
        t.push_str(&format!("parent {p}\n"));
    }
    t.push_str(&format!("author {name} <{}@rcevc.invalid> {time} +0000\n", email_local(&name)));
    t.push_str(&format!("committer rcevc <rcevc@rcevc.invalid> {time} +0000\n\n"));
    t.push_str(message);
    if !message.ends_with('\n') {
        t.push('\n');
    }
    Ok(g.write("commit", t.as_bytes())?)
}

/// Read a commit.
pub fn read_commit(g: &GitDir, oid: &Oid) -> Result<Commit, ProjError> {
    let (kind, data) = g.read(oid)?;
    if kind != "commit" {
        return Err(ProjError::Corrupt(format!("{oid:?} is a {kind}, not a commit")));
    }
    let text = String::from_utf8(data).map_err(|_| ProjError::NonUtf8(format!("commit {oid:?}")))?;
    let (head, message) = text.split_once("\n\n").unwrap_or((&text, ""));
    let (mut tree, mut parents, mut author) = (None, Vec::new(), String::new());
    for line in head.lines() {
        if let Some(h) = line.strip_prefix("tree ") {
            tree = Oid::from_hex(h);
        } else if let Some(h) = line.strip_prefix("parent ") {
            parents.push(Oid::from_hex(h).ok_or_else(|| ProjError::Corrupt("parent".into()))?);
        } else if let Some(a) = line.strip_prefix("author ") {
            author = a.split(" <").next().unwrap_or("").to_string();
        }
    }
    let tree = tree.ok_or_else(|| ProjError::Corrupt(format!("commit {oid:?} has no tree")))?;
    Ok(Commit { tree, parents, author, message: message.to_string() })
}

/// Value of the last trailer `key` in a message.
pub fn trailer<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    message.lines().rev().find_map(|l| l.strip_prefix(key)?.strip_prefix(": "))
}

fn gears(path: &[Gear]) -> String {
    if path.is_empty() {
        return "-".into();
    }
    path.iter().map(|g| format!("{g:?}")).collect::<Vec<_>>().join(">")
}

fn intent(e: &Entry, fallback: String) -> String {
    let m = e.change.message.trim();
    if m.is_empty() { format!("{fallback}\n\n") } else { format!("{m}\n\n") }
}

fn accept_message(e: &Entry, r: &Receipt) -> String {
    let p = gears(&r.path);
    let mut m = intent(e, format!("admit {} via {p}", r.change.short()));
    m += &format!("RCE-VC-Change: {}\nRCE-VC-Pre: {}\nRCE-VC-Post: {}\nRCE-VC-Path: {p}\n", r.change, r.pre, r.post);
    for ev in &r.evidence {
        m += &format!("RCE-VC-Evidence: {} {:?} {}\n", ev.checker, ev.authority, ev.digest.short());
    }
    for (s, _) in &r.resolution {
        m += &format!("RCE-VC-Resolved: {s}\n");
    }
    m += &format!("RCE-VC-Est-uJ: {}\nRCE-VC-Entry: {} {}\n", r.est_uj, e.index, e.hash);
    m
}

fn refuse_message(e: &Entry, r: &Refusal, post: &Digest) -> String {
    let p = gears(&r.path);
    let mut m = format!("refuse {}: {}\n\n", r.change.short(), intent(e, String::new()).trim());
    m += &format!("RCE-VC-Change: {}\nRCE-VC-Pre: {}\nRCE-VC-Post: {post}\nRCE-VC-Path: {p}\n", r.change, r.pre);
    m += &format!("RCE-VC-Reason: {}\n", format!("{:?}", r.reason).replace('\n', " "));
    m += &format!("RCE-VC-Est-uJ: {}\nRCE-VC-Entry: {} {}\n", r.est_uj, e.index, e.hash);
    m
}

/// Result of an export.
#[derive(Debug, Clone, Copy)]
pub struct Exported {
    /// Tip of the admitted-states branch.
    pub main: Oid,
    /// Tip of `refs/rcevc/log`.
    pub log: Oid,
    /// Commits on the branch, genesis included.
    pub admitted: usize,
}

/// Project the whole log into Git. Idempotent and append-only: exporting a
/// longer log fast-forwards both refs.
pub fn export(g: &GitDir, repo: &Repo, genesis: &Draft, branch: &str, time_base: i64) -> Result<Exported, ProjError> {
    let genesis = genesis.seal().map_err(ProjError::Wf)?;
    let groot = genesis.root();
    let mut tree = write_tree(g, &genesis)?;
    let msg = format!("rcevc: genesis\n\nRCE-VC-Post: {groot}\nRCE-VC-Genesis: {}\n", repo.genesis());
    let root = write_commit(g, tree, &[], "genesis", time_base, &msg)?;
    let (mut main, mut log, mut admitted, mut post) = (root, root, 1, groot);
    for e in repo.log() {
        let t = time_base + e.index as i64 + 1;
        match &e.outcome {
            Outcome::Accepted(r) => {
                let s = repo.snapshot(&r.post).ok_or_else(|| ProjError::Corrupt("missing snapshot".into()))?;
                tree = write_tree(g, s)?;
                post = r.post;
                let msg = accept_message(e, r);
                main = write_commit(g, tree, &[main], &e.change.writer, t, &msg)?;
                log = write_commit(g, tree, &[log], &e.change.writer, t, &format!("log: {msg}"))?;
                admitted += 1;
            }
            Outcome::Refused(r) => {
                let msg = refuse_message(e, r, &post);
                log = write_commit(g, tree, &[log], &e.change.writer, t, &format!("log: {msg}"))?;
            }
        }
    }
    g.set_ref(&format!("refs/heads/{branch}"), &main)?;
    g.set_ref("refs/rcevc/log", &log)?;
    Ok(Exported { main, log, admitted })
}

/// Turn a plain Git commit into a change. Walks first parents to the
/// nearest admitted commit; that state is the base. Any number of
/// intermediate commits fold into one change.
pub fn ingest(g: &GitDir, tip: &Oid, repo: &Repo) -> Result<Change, ProjError> {
    let c = read_commit(g, tip)?;
    let mut cur = Some(*tip);
    let mut messages = Vec::new();
    let base = loop {
        let Some(o) = cur else {
            return Err(ProjError::NoBase(format!("{tip:?} does not descend from an admitted commit")));
        };
        let pc = read_commit(g, &o)?;
        if let Some(d) = trailer(&pc.message, "RCE-VC-Post").and_then(Digest::from_hex) {
            if !pc.message.starts_with("log: ") && repo.snapshot(&d).is_some() {
                break d;
            }
        }
        messages.push(pc.message.trim().to_string());
        cur = pc.parents.first().copied();
    };
    let base_state = repo.snapshot(&base).expect("checked above");
    let new = read_tree(g, &c.tree)?;
    let name_only = matches!(new.seal(), Ok(t) if t.content_root() == base_state.content_root());
    let level = if name_only { Level::NameOnly } else { Level::MeaningChange };
    messages.reverse();
    let mut ch = Change::new(c.author, base, level).message(messages.join("\n\n"));
    for (slot, u) in new.changes_from(base_state) {
        ch.ops.push(match u {
            Some(unit) => Op::Put { slot, unit },
            None => Op::Del { slot },
        });
    }
    Ok(ch)
}
