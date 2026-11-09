//! Rename, move, edit, whitespace, and unparsable fallback.

use rcevc_core::{Change, Gate, Level, Repo};
use rcevc_keys::{SourceLanguage, project, split};

fn keys_of(path: &str, source: &str) -> (bool, Vec<(String, String)>) {
    let split = split(path, source);
    assert_eq!(project(&split), source);
    let state = split.draft.seal().expect("split draft is acyclic");
    let mut rows = Vec::new();
    for slot in state.slots() {
        rows.push((slot.clone(), state.key(slot).unwrap().hex()));
    }
    (split.fallback, rows)
}

fn key_at(path: &str, source: &str, slot: &str) -> String {
    let (_, rows) = keys_of(path, source);
    rows.into_iter().find(|(s, _)| s == slot).expect(slot).1
}

#[test]
fn rust_and_python_are_the_detected_languages() {
    assert_eq!(
        SourceLanguage::from_path("src/lib.rs"),
        Some(SourceLanguage::Rust)
    );
    assert_eq!(
        SourceLanguage::from_path("pkg/mod.py"),
        Some(SourceLanguage::Python)
    );
    assert_eq!(SourceLanguage::from_path("README.md"), None);
}

#[test]
fn split_is_deterministic_and_projects_the_exact_bytes() {
    let source = "// head\n\nfn foo() {\n    // inside\n    1\n}\n\nfn bar() {\n    foo()\n}\n";
    let once = split("src/lib.rs", source);
    let twice = split("src/lib.rs", source);
    assert!(!once.fallback);
    assert_eq!(once, twice);
    assert_eq!(project(&once), source);
    assert!(once.draft.seal().unwrap().key("src/lib.rs::foo").is_some());
    assert!(once.draft.seal().unwrap().key("src/lib.rs::bar").is_some());
    let slots: Vec<_> = once.parts.iter().filter_map(|p| p.slot.clone()).collect();
    assert!(
        !slots.iter().any(|s| s.contains("inner")),
        "nested fn is not its own item"
    );
}

#[test]
fn whitespace_and_comment_extras_do_not_change_rust_ids() {
    let tight = "fn foo(){1}\nfn bar(){foo()}\n";
    let loose = "fn foo() { 1 }\n\nfn bar() {\n    foo()\n}\n";
    let commented = "fn foo() { /* c */ 1 }\nfn bar() { foo() }\n";
    assert_eq!(
        key_at("a.rs", tight, "a.rs::foo"),
        key_at("a.rs", loose, "a.rs::foo")
    );
    assert_eq!(
        key_at("a.rs", tight, "a.rs::bar"),
        key_at("a.rs", loose, "a.rs::bar")
    );
    assert_eq!(
        key_at("a.rs", tight, "a.rs::foo"),
        key_at("a.rs", commented, "a.rs::foo")
    );
    assert_eq!(key_at("a.rs", tight, "a.rs"), key_at("a.rs", loose, "a.rs"));
    let spaced = "fn foo(){\"a b\"}\n";
    let tight_str = "fn foo(){\"ab\"}\n";
    assert_ne!(
        key_at("a.rs", spaced, "a.rs::foo"),
        key_at("a.rs", tight_str, "a.rs::foo")
    );
}

#[test]
fn python_whitespace_follows_the_grammar_tokens() {
    let base = "def foo():\n    return 1\n";
    let spaces = "def foo():\n    return  1\n";
    let deeper = "def foo():\n        return 1\n";
    assert_eq!(
        key_at("m.py", base, "m.py::foo"),
        key_at("m.py", spaces, "m.py::foo")
    );
    // This grammar does not emit an indent token for a one-statement block.
    assert_eq!(
        key_at("m.py", base, "m.py::foo"),
        key_at("m.py", deeper, "m.py::foo")
    );
    let spaced = "def foo():\n    return \"a b\"\n";
    let tight = "def foo():\n    return \"ab\"\n";
    assert_ne!(
        key_at("m.py", spaced, "m.py::foo"),
        key_at("m.py", tight, "m.py::foo")
    );
}

#[test]
fn rename_keeps_ids_and_is_name_only_for_the_kernel() {
    let before = "fn foo() -> i32 { 1 }\nfn bar() -> i32 { foo() }\n";
    let after = "fn qux() -> i32 { 1 }\nfn bar() -> i32 { qux() }\n";
    assert_eq!(
        key_at("a.rs", before, "a.rs::foo"),
        key_at("a.rs", after, "a.rs::qux")
    );
    assert_eq!(
        key_at("a.rs", before, "a.rs::bar"),
        key_at("a.rs", after, "a.rs::bar")
    );
    assert_eq!(
        key_at("a.rs", before, "a.rs"),
        key_at("a.rs", after, "a.rs")
    );

    let split = split("a.rs", before);
    let mut repo = Repo::new(Gate::new(), split.draft).unwrap();
    let base = repo.head_root();
    let outcome =
        repo.submit(Change::new("w", base, Level::NameOnly).rename("a.rs::foo", "a.rs::qux"));
    assert!(outcome.is_accepted(), "{outcome:?}");
    assert!(repo.head().key("a.rs::qux").is_some());
    assert!(repo.head().key("a.rs::foo").is_none());
}

#[test]
fn move_keeps_the_content_id_and_changes_the_slot() {
    let source = "fn foo() -> i32 { 1 }\nfn bar() -> i32 { foo() }\n";
    let here = key_at("src/a.rs", source, "src/a.rs::foo");
    let there = key_at("src/b.rs", source, "src/b.rs::foo");
    assert_eq!(here, there);
    assert_ne!(
        keys_of("src/a.rs", source)
            .1
            .iter()
            .map(|(s, _)| s.clone())
            .collect::<Vec<_>>(),
        keys_of("src/b.rs", source)
            .1
            .iter()
            .map(|(s, _)| s.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_edit_changes_that_item_and_later_dependents_only() {
    let before = "fn foo() -> i32 { 1 }\nfn bar() -> i32 { foo() }\nfn baz() -> i32 { 0 }\n";
    let after = "fn foo() -> i32 { 2 }\nfn bar() -> i32 { foo() }\nfn baz() -> i32 { 0 }\n";
    assert_ne!(
        key_at("a.rs", before, "a.rs::foo"),
        key_at("a.rs", after, "a.rs::foo")
    );
    assert_ne!(
        key_at("a.rs", before, "a.rs::bar"),
        key_at("a.rs", after, "a.rs::bar")
    );
    assert_eq!(
        key_at("a.rs", before, "a.rs::baz"),
        key_at("a.rs", after, "a.rs::baz")
    );
}

#[test]
fn unparsable_and_unknown_files_fall_back_to_one_leaf() {
    let broken = "fn foo( {\n";
    let split_broken = split("src/lib.rs", broken);
    assert!(split_broken.fallback);
    assert_eq!(project(&split_broken), broken);
    let state = split_broken.draft.seal().unwrap();
    assert_eq!(state.slots(), vec!["src/lib.rs"]);
    assert_eq!(state.get("src/lib.rs").unwrap().body, broken);

    let notes = "not source\n";
    let split_notes = split("README.md", notes);
    assert!(split_notes.fallback);
    assert!(split_notes.language.is_none());
    assert_eq!(project(&split_notes), notes);
}
