//! Tree-sitter content units for real source files.
//!
//! This crate splits a Rust or Python file into top-level items and gives
//! each item a name-free id. The id is a core unit key ([`rcevc_core::State::key`]):
//! it covers a normalized token body and the keys of dependencies, not the
//! slot name. Whitespace and comment extras are not tokens, so they do not
//! change those ids where the grammar treats them as extras. The exact
//! source is kept beside the draft, and [`project`] concatenates it.
//!
//! A dependency edge points only at an item that starts earlier in the same
//! file, so the core graph stays acyclic. A forward reference stays
//! identifier text, and renaming that later item changes the earlier body.
//! A file the grammar cannot parse, or a path that is not Rust or Python,
//! is one leaf over the original bytes.
//!
//! Tree-sitter-python does not record the indentation of a one-statement
//! block as a token, so a deeper indent of that statement does not change
//! the id. Spaces inside a string do, because they are part of the token.
//!
//! HANDOFF section 9 B names Rust, TypeScript, and Python. This crate
//! implements Rust and Python. TypeScript is not started. Python is the
//! smaller of those two remaining grammars. The core crate stays
//! dependency-free.
//!
//! Building the grammars compiles C through the `cc` crate and a system C
//! compiler. The crates are vendored, so `cargo test --locked --offline`
//! does not download them. This crate states no energy or throughput result.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use rcevc_core::{Draft, Slot, Unit};
use tree_sitter::{Language, Node, Parser, Tree};

/// Which grammar parsed a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceLanguage {
    /// Rust (`.rs`).
    Rust,
    /// Python (`.py`).
    Python,
}

impl SourceLanguage {
    /// Language implied by a file name, if this crate has a grammar for it.
    pub fn from_path(path: &str) -> Option<Self> {
        let file = path.rsplit('/').next().unwrap_or(path);
        if file.ends_with(".rs") {
            Some(SourceLanguage::Rust)
        } else if file.ends_with(".py") {
            Some(SourceLanguage::Python)
        } else {
            None
        }
    }

    fn grammar(self) -> Language {
        match self {
            SourceLanguage::Rust => tree_sitter_rust::LANGUAGE.into(),
            SourceLanguage::Python => tree_sitter_python::LANGUAGE.into(),
        }
    }
}

/// One exact slice of the file, in source order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// Item slot, or `None` for bytes that are not a top-level item.
    pub slot: Option<Slot>,
    /// Bytes of this slice, copied from the source.
    pub exact: String,
}

/// A split file.
///
/// [`Split::draft`] is the name-free projection. [`project`] rebuilds the
/// source from [`Split::parts`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Split {
    /// Grammar used, or `None` when the path selected the leaf fallback.
    pub language: Option<SourceLanguage>,
    /// The file was not split into items.
    pub fallback: bool,
    /// Exact slices whose concatenation is the source.
    pub parts: Vec<Part>,
    /// Name-free units. The file slot is `path`. An item slot is
    /// `{path}::{name}` or `{path}::{kind}@{byte}`.
    pub draft: Draft,
}

/// Split `source` at `path`.
///
/// Source text does not panic this function. A grammar that fails to load,
/// a parse that returns no tree, or a tree with an error node becomes one leaf.
pub fn split(path: &str, source: &str) -> Split {
    match SourceLanguage::from_path(path) {
        Some(language) => split_language(language, path, source),
        None => leaf(None, path, source),
    }
}

/// Concatenate the exact slices.
pub fn project(split: &Split) -> String {
    split.parts.iter().map(|part| part.exact.as_str()).collect()
}

fn split_language(language: SourceLanguage, path: &str, source: &str) -> Split {
    let mut parser = Parser::new();
    if parser.set_language(&language.grammar()).is_err() {
        return leaf(Some(language), path, source);
    }
    let Some(tree) = parser.parse(source, None) else {
        return leaf(Some(language), path, source);
    };
    if tree.root_node().has_error() {
        return leaf(Some(language), path, source);
    }
    split_tree(language, path, source, &tree)
}

fn leaf(language: Option<SourceLanguage>, path: &str, source: &str) -> Split {
    let mut draft = Draft::new();
    draft.put(path, Unit::new(source, &[]));
    Split {
        language,
        fallback: true,
        parts: vec![Part {
            slot: Some(path.to_string()),
            exact: source.to_string(),
        }],
        draft,
    }
}

fn split_tree(language: SourceLanguage, path: &str, source: &str, tree: &Tree) -> Split {
    let root = tree.root_node();
    let bytes = source.as_bytes();
    let mut parts: Vec<Part> = Vec::new();
    let mut nodes: Vec<Node> = Vec::new();
    let mut cursor = 0usize;
    for i in 0..root.named_child_count() {
        let Some(child) = root.named_child(i as u32) else {
            continue;
        };
        if child.is_extra() {
            continue;
        }
        let start = child.start_byte();
        let end = child.end_byte();
        if start < cursor || end > bytes.len() || start > end {
            return leaf(Some(language), path, source);
        }
        if start > cursor {
            parts.push(Part {
                slot: None,
                exact: source[cursor..start].to_string(),
            });
        }
        parts.push(Part {
            slot: Some(String::new()),
            exact: source[start..end].to_string(),
        });
        nodes.push(child);
        cursor = end;
    }
    if cursor < source.len() {
        parts.push(Part {
            slot: None,
            exact: source[cursor..].to_string(),
        });
    }

    let mut used = BTreeSet::new();
    let mut item_slots = Vec::with_capacity(nodes.len());
    for node in &nodes {
        let raw = item_slot(path, node, bytes);
        item_slots.push(unique_slot(&raw, &mut used));
    }
    let mut n = 0;
    for part in &mut parts {
        if part.slot.is_some() {
            part.slot = Some(item_slots[n].clone());
            n += 1;
        }
    }

    let mut draft = Draft::new();
    let mut earlier: BTreeMap<String, String> = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for (node, slot) in nodes.iter().zip(item_slots.iter()) {
        let own = item_name(node, bytes);
        let name_at = definition_name(node).map(|n| (n.start_byte(), n.end_byte()));
        let (body, deps) = normalize(node, bytes, name_at, own.as_deref(), &earlier, &ambiguous);
        let dep_refs: Vec<&str> = deps.iter().map(String::as_str).collect();
        draft.put(slot.clone(), Unit::new(body, &dep_refs));
        if let Some(name) = own {
            if earlier.contains_key(&name) || ambiguous.contains(&name) {
                earlier.remove(&name);
                ambiguous.insert(name);
            } else {
                earlier.insert(name, slot.clone());
            }
        }
    }
    let file_deps: Vec<&str> = item_slots.iter().map(String::as_str).collect();
    let mut file_body = String::new();
    for index in 0..item_slots.len() {
        file_body.push('$');
        file_body.push_str(&index.to_string());
    }
    draft.put(path, Unit::new(file_body, &file_deps));
    Split {
        language: Some(language),
        fallback: false,
        parts,
        draft,
    }
}

fn unique_slot(slot: &str, used: &mut BTreeSet<String>) -> String {
    if used.insert(slot.to_string()) {
        return slot.to_string();
    }
    let mut n = 2u32;
    loop {
        let next = format!("{slot}#{n}");
        if used.insert(next.clone()) {
            return next;
        }
        n += 1;
    }
}

fn item_slot(path: &str, node: &Node, bytes: &[u8]) -> String {
    if let Some(name) = item_name(node, bytes) {
        format!("{path}::{name}")
    } else {
        format!("{path}::{}@{}", node.kind(), node.start_byte())
    }
}

fn definition_name<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if let Some(name) = node.child_by_field_name("name") {
        return Some(name);
    }
    let last = node.named_child_count().saturating_sub(1);
    let inner = node.named_child(last as u32)?;
    if inner.kind() == "function_definition" || inner.kind() == "class_definition" {
        return inner.child_by_field_name("name");
    }
    None
}

fn item_name(node: &Node, bytes: &[u8]) -> Option<String> {
    definition_name(node)?
        .utf8_text(bytes)
        .ok()
        .map(str::to_string)
}

fn normalize(
    node: &Node,
    bytes: &[u8],
    name_at: Option<(usize, usize)>,
    own: Option<&str>,
    earlier: &BTreeMap<String, String>,
    ambiguous: &BTreeSet<String>,
) -> (String, Vec<Slot>) {
    let mut body = String::new();
    body.push_str("kind:");
    body.push_str(node.kind());
    body.push('\n');
    let mut deps = Vec::new();
    let mut walk = Walk {
        bytes,
        name_at,
        own,
        earlier,
        ambiguous,
        body: &mut body,
        deps: &mut deps,
    };
    walk.go(*node);
    (body, deps)
}

struct Walk<'a> {
    bytes: &'a [u8],
    name_at: Option<(usize, usize)>,
    own: Option<&'a str>,
    earlier: &'a BTreeMap<String, String>,
    ambiguous: &'a BTreeSet<String>,
    body: &'a mut String,
    deps: &'a mut Vec<Slot>,
}

impl Walk<'_> {
    fn go(&mut self, node: Node) {
        if node.is_extra() {
            return;
        }
        if self.name_at == Some((node.start_byte(), node.end_byte())) {
            self.body.push_str("~name~\n");
            return;
        }
        if node.child_count() == 0 {
            let text = node.utf8_text(self.bytes).unwrap_or("");
            if is_name_token(node.kind()) {
                if self.own == Some(text) {
                    self.body.push_str("~self~\n");
                    return;
                }
                if !self.ambiguous.contains(text) {
                    if let Some(slot) = self.earlier.get(text) {
                        let index = match self.deps.iter().position(|dep| dep == slot) {
                            Some(pos) => pos,
                            None => {
                                self.deps.push(slot.clone());
                                self.deps.len() - 1
                            }
                        };
                        self.body.push('$');
                        self.body.push_str(&index.to_string());
                        self.body.push('\n');
                        return;
                    }
                }
            }
            self.body.push_str(node.kind());
            self.body.push(':');
            push_escaped(self.body, text);
            self.body.push('\n');
            return;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i as u32) {
                self.go(child);
            }
        }
    }
}

fn is_name_token(kind: &str) -> bool {
    matches!(
        kind,
        "identifier" | "type_identifier" | "field_identifier" | "shorthand_field_identifier"
    )
}

fn push_escaped(out: &mut String, text: &str) {
    for ch in text.chars() {
        if ch == '$' {
            out.push_str("$$");
        } else {
            out.push(ch);
        }
    }
}
