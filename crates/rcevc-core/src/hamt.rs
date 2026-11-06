//! Persistent Merkle hash-array-mapped trie.
//!
//! A 16-way trie over SHA-256(name). Properties the repository relies on:
//!
//! - **Persistent.** Updates copy only the root-to-leaf path; every other
//!   node is shared, so a snapshot of every admitted state costs
//!   O(changes × depth), not O(state).
//! - **Canonical.** The shape is a function of the key set alone: a prefix
//!   holds nothing, a single leaf, or a branch over two or more keys. Insert
//!   order and history never show in the root hash.
//! - **Merkle.** For maps whose values opt in (`HValue::MERKLE`), every node
//!   carries a hash, so equal subtrees are recognised in O(1) and a diff
//!   visits only the paths that differ.
//!
//! Non-Merkle maps (indexes) skip hashing entirely and are plain persistent
//! maps.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::hash::{Digest, Enc};

/// A value stored in a [`Hamt`].
pub trait HValue: Clone {
    /// Whether nodes carry hashes.
    const MERKLE: bool;
    /// Digest of the value (ignored when not Merkle).
    fn digest(&self) -> Digest;
}

enum Node<V> {
    Leaf { path: Digest, key: String, value: V, hash: Digest },
    Branch { children: [Option<Arc<Node<V>>>; 16], len: usize, hash: Digest },
}

impl<V> Node<V> {
    fn hash(&self) -> Digest {
        match self {
            Node::Leaf { hash, .. } | Node::Branch { hash, .. } => *hash,
        }
    }
    fn len(&self) -> usize {
        match self {
            Node::Leaf { .. } => 1,
            Node::Branch { len, .. } => *len,
        }
    }
}

/// The persistent map.
pub struct Hamt<V> {
    root: Option<Arc<Node<V>>>,
}

impl<V> Clone for Hamt<V> {
    fn clone(&self) -> Self {
        Hamt { root: self.root.clone() }
    }
}

impl<V> Default for Hamt<V> {
    fn default() -> Self {
        Hamt { root: None }
    }
}

fn path_of(key: &str) -> Digest {
    let mut e = Enc::new("rcevc/path/v1");
    e.str(key);
    e.finish()
}

fn nibble(path: &Digest, depth: usize) -> usize {
    let b = path.0[depth / 2];
    if depth % 2 == 0 { (b >> 4) as usize } else { (b & 0x0f) as usize }
}

fn empty<V>() -> [Option<Arc<Node<V>>>; 16] {
    std::array::from_fn(|_| None)
}

fn mk_leaf<V: HValue>(path: Digest, key: String, value: V) -> Arc<Node<V>> {
    let hash = if V::MERKLE {
        let mut e = Enc::new("rcevc/hamt-leaf/v1");
        e.str(&key).digest(&value.digest());
        e.finish()
    } else {
        Digest::default()
    };
    Arc::new(Node::Leaf { path, key, value, hash })
}

fn mk_branch<V: HValue>(children: [Option<Arc<Node<V>>>; 16]) -> Option<Arc<Node<V>>> {
    let len: usize = children.iter().flatten().map(|c| c.len()).sum();
    match len {
        0 => None,
        // Canonical form: a lone key is a leaf, never a branch.
        1 => children.into_iter().flatten().next(),
        _ => {
            let hash = if V::MERKLE {
                let mut e = Enc::new("rcevc/hamt-branch/v1");
                for c in &children {
                    e.opt_digest(c.as_ref().map(|c| c.hash()).as_ref());
                }
                e.finish()
            } else {
                Digest::default()
            };
            Some(Arc::new(Node::Branch { children, len, hash }))
        }
    }
}

fn insert<V: HValue>(node: Option<&Arc<Node<V>>>, depth: usize, path: Digest, key: String, value: V) -> Arc<Node<V>> {
    let Some(n) = node else { return mk_leaf(path, key, value) };
    match &**n {
        Node::Leaf { key: k, path: p, .. } => {
            if *k == key {
                return mk_leaf(path, key, value);
            }
            assert!(depth < 64, "SHA-256 path collision between distinct names");
            let mut c = empty();
            c[nibble(p, depth)] = Some(n.clone());
            let j = nibble(&path, depth);
            c[j] = Some(insert(c[j].as_ref(), depth + 1, path, key, value));
            mk_branch(c).expect("two keys")
        }
        Node::Branch { children, .. } => {
            let mut c = children.clone();
            let j = nibble(&path, depth);
            c[j] = Some(insert(c[j].as_ref(), depth + 1, path, key, value));
            mk_branch(c).expect("non-empty")
        }
    }
}

/// `None`: key absent. `Some(new)`: the node after removal.
fn remove<V: HValue>(n: &Arc<Node<V>>, depth: usize, path: &Digest, key: &str) -> Option<Option<Arc<Node<V>>>> {
    match &**n {
        Node::Leaf { key: k, .. } => (k == key).then_some(None),
        Node::Branch { children, .. } => {
            let j = nibble(path, depth);
            let r = remove(children[j].as_ref()?, depth + 1, path, key)?;
            let mut c = children.clone();
            c[j] = r;
            Some(mk_branch(c))
        }
    }
}

fn walk<'a, V>(n: &'a Arc<Node<V>>, f: &mut impl FnMut(&'a String, &'a V)) {
    match &**n {
        Node::Leaf { key, value, .. } => f(key, value),
        Node::Branch { children, .. } => {
            for c in children.iter().flatten() {
                walk(c, f);
            }
        }
    }
}

impl<V: HValue> Hamt<V> {
    /// Number of entries.
    pub fn len(&self) -> usize {
        self.root.as_ref().map_or(0, |r| r.len())
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }
    /// Root hash (`None` when empty). Meaningful for Merkle maps.
    pub fn root_hash(&self) -> Option<Digest> {
        self.root.as_ref().map(|r| r.hash())
    }

    /// Look up a key.
    pub fn get(&self, key: &str) -> Option<&V> {
        let path = path_of(key);
        let mut n = self.root.as_ref()?;
        let mut d = 0;
        loop {
            match &**n {
                Node::Leaf { key: k, value, .. } => return (k == key).then_some(value),
                Node::Branch { children, .. } => {
                    n = children[nibble(&path, d)].as_ref()?;
                    d += 1;
                }
            }
        }
    }

    /// Insert or replace.
    pub fn insert(&mut self, key: String, value: V) {
        let path = path_of(&key);
        self.root = Some(insert(self.root.as_ref(), 0, path, key, value));
    }

    /// Remove; returns whether the key was present.
    pub fn remove(&mut self, key: &str) -> bool {
        let Some(r) = &self.root else { return false };
        match remove(r, 0, &path_of(key), key) {
            Some(new) => {
                self.root = new;
                true
            }
            None => false,
        }
    }

    /// Visit every entry, in trie order (deterministic).
    pub fn for_each<'a>(&'a self, mut f: impl FnMut(&'a String, &'a V)) {
        if let Some(r) = &self.root {
            walk(r, &mut f);
        }
    }

    /// Keys whose presence or value digest differs. Skips shared and
    /// equal-hash subtrees, so the cost follows the size of the difference.
    pub fn diff(&self, other: &Hamt<V>) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        diff_nodes(self.root.as_ref(), other.root.as_ref(), &mut out);
        out
    }
}

fn collect<V: HValue>(n: Option<&Arc<Node<V>>>, out: &mut BTreeMap<String, Digest>) {
    if let Some(n) = n {
        walk(n, &mut |k, v: &V| {
            out.insert(k.clone(), v.digest());
        });
    }
}

fn diff_nodes<V: HValue>(x: Option<&Arc<Node<V>>>, y: Option<&Arc<Node<V>>>, out: &mut BTreeSet<String>) {
    match (x, y) {
        (None, None) => {}
        (Some(a), Some(b)) if Arc::ptr_eq(a, b) || (V::MERKLE && a.hash() == b.hash()) => {}
        (Some(a), Some(b)) if matches!((&**a, &**b), (Node::Branch { .. }, Node::Branch { .. })) => {
            if let (Node::Branch { children: ca, .. }, Node::Branch { children: cb, .. }) = (&**a, &**b) {
                for i in 0..16 {
                    diff_nodes(ca[i].as_ref(), cb[i].as_ref(), out);
                }
            }
        }
        _ => {
            let (mut la, mut lb) = (BTreeMap::new(), BTreeMap::new());
            collect(x, &mut la);
            collect(y, &mut lb);
            for k in la.keys().chain(lb.keys()) {
                if la.get(k) != lb.get(k) {
                    out.insert(k.clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    #[derive(Clone, Debug, PartialEq)]
    struct V(u64);
    impl HValue for V {
        const MERKLE: bool = true;
        fn digest(&self) -> Digest {
            sha256(&self.0.to_le_bytes())
        }
    }

    fn lcg(x: &mut u64) -> u64 {
        *x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *x >> 33
    }

    #[test]
    fn shape_and_root_are_independent_of_history() {
        let mut a: Hamt<V> = Hamt::default();
        let mut b: Hamt<V> = Hamt::default();
        for i in 0..2000u64 {
            a.insert(format!("k{i}"), V(i));
        }
        for i in (0..2000u64).rev() {
            b.insert(format!("k{i}"), V(i));
        }
        // b also takes a detour: extra keys inserted and removed.
        for i in 0..500u64 {
            b.insert(format!("tmp{i}"), V(i));
        }
        for i in 0..500u64 {
            assert!(b.remove(&format!("tmp{i}")));
        }
        assert_eq!(a.root_hash(), b.root_hash());
        assert_eq!(a.len(), 2000);
        assert_eq!(b.get("k1234"), Some(&V(1234)));
        assert!(a.diff(&b).is_empty());
    }

    #[test]
    fn diff_matches_naive_and_snapshots_are_untouched() {
        let mut seed = 7;
        let mut m: Hamt<V> = Hamt::default();
        let mut naive: BTreeMap<String, u64> = BTreeMap::new();
        for _ in 0..3000 {
            let k = format!("k{}", lcg(&mut seed) % 1500);
            let v = lcg(&mut seed) % 4;
            m.insert(k.clone(), V(v));
            naive.insert(k, v);
        }
        for _ in 0..200 {
            let snap = m.clone();
            let snap_naive = naive.clone();
            for _ in 0..(lcg(&mut seed) % 20) {
                let k = format!("k{}", lcg(&mut seed) % 1600);
                if lcg(&mut seed) % 3 == 0 {
                    m.remove(&k);
                    naive.remove(&k);
                } else {
                    let v = lcg(&mut seed) % 4;
                    m.insert(k.clone(), V(v));
                    naive.insert(k, v);
                }
            }
            let want: BTreeSet<String> = snap_naive
                .keys()
                .chain(naive.keys())
                .filter(|k| snap_naive.get(*k) != naive.get(*k))
                .cloned()
                .collect();
            assert_eq!(snap.diff(&m), want);
            assert_eq!(m.len(), naive.len());
            // Snapshot still reads its own version.
            for (k, v) in &snap_naive {
                assert_eq!(snap.get(k), Some(&V(*v)));
            }
        }
    }
}
