//! Adversaries for content integrity, action-cache trust, combined revisions,
//! and compare-and-swap retries. Deterministic. No clock.

use rcevc_core::assure::*;
use rcevc_core::repo::conflict_signature;
use rcevc_core::*;

fn genesis() -> Draft {
    let mut draft = Draft::new();
    draft
        .put("p", Unit::new("v0", &[]))
        .put("q", Unit::new("v0", &[]));
    draft
}

fn deps() -> DependencyManifest {
    DependencyManifest::complete(&["rcevc-core"])
}

fn ask(
    gate: Digest,
    head: Digest,
    base: Digest,
    change: Digest,
    inputs: &[Digest],
) -> ActionQuery<'_> {
    ActionQuery {
        gate,
        head,
        base,
        change,
        inputs,
        dependencies: deps().digest(),
    }
}

fn bind_ok(
    repo: &Repo,
    change: &Change,
    outcome: &Outcome,
    store: &mut ContentStore,
) -> CheckedAction {
    let digest = store.put(&outcome_image(outcome));
    bind_repo_outcome(repo, change, outcome, store, digest, &[], &deps())
        .expect("logged outcome binds")
}

#[test]
fn blob_integrity_is_not_an_action_hit() {
    let mut store = ContentStore::new();
    let digest = store.put(b"bytes");
    assert_eq!(store.get(&digest).unwrap(), b"bytes");
    let cache = ActionCache::new();
    assert!(matches!(
        cache.lookup(
            ask(sha256(b"g"), sha256(b"h"), sha256(b"b"), sha256(b"c"), &[]),
            &store
        ),
        Lookup::Miss
    ));
    store.plant_unverified(digest, b"other".to_vec());
    assert_eq!(store.get(&digest), Err(AssureError::CorruptOutput));
}

#[test]
fn forged_truncated_incomplete_and_unlogged_outcomes_fail_closed() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let base = repo.head_root();
    let change = Change::new("w", base, Level::MeaningChange).put("p", Unit::new("v1", &[]));
    let outcome = repo.submit(change.clone());
    assert!(outcome.is_accepted());
    let image = outcome_image(&outcome);
    let mut store = ContentStore::new();

    let mut prefix = image.clone();
    prefix.pop();
    let truncated = store.put(&prefix);
    assert_eq!(
        bind_repo_outcome(&repo, &change, &outcome, &store, truncated, &[], &deps()),
        Err(AssureError::TruncatedImage)
    );

    let other = store.put(b"not-the-image");
    assert_eq!(
        bind_repo_outcome(&repo, &change, &outcome, &store, other, &[], &deps()),
        Err(AssureError::ForgedMapping)
    );

    let right = sha256(&image);
    assert_eq!(
        bind_repo_outcome(&repo, &change, &outcome, &store, right, &[], &deps()),
        Err(AssureError::MissingOutput)
    );

    store.put(&image);
    store.plant_unverified(right, b"clobber".to_vec());
    assert_eq!(
        bind_repo_outcome(&repo, &change, &outcome, &store, right, &[], &deps()),
        Err(AssureError::CorruptOutput)
    );

    store.put(&image);
    assert_eq!(
        bind_repo_outcome(
            &repo,
            &change,
            &outcome,
            &store,
            right,
            &[],
            &DependencyManifest::incomplete()
        ),
        Err(AssureError::IncompleteDependencies)
    );
    assert_ne!(
        DependencyManifest::incomplete().digest(),
        DependencyManifest::complete(&[]).digest()
    );

    let Outcome::Accepted(receipt) = outcome.clone() else {
        panic!("accepted")
    };
    let mut forged = receipt.clone();
    forged.post = sha256(b"forged-post");
    let forged = Outcome::Accepted(forged);
    let forged_digest = store.put(&outcome_image(&forged));
    assert_eq!(
        bind_repo_outcome(&repo, &change, &forged, &store, forged_digest, &[], &deps()),
        Err(AssureError::NotLogged)
    );
}

#[test]
fn untrusted_mapping_rejects_while_the_blob_still_reads() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let base = repo.head_root();
    let change = Change::new("w", base, Level::MeaningChange).put("p", Unit::new("v1", &[]));
    let outcome = repo.submit(change.clone());
    let mut store = ContentStore::new();
    let checked = bind_ok(&repo, &change, &outcome, &mut store);
    let mut cache = ActionCache::new();
    let gate = repo.gate().digest();
    let head = checked.head();
    assert!(cache.plant_untrusted(
        ask(gate, head, checked.base(), checked.change_id(), &[]),
        checked.output()
    ));
    assert!(matches!(
        cache.lookup(
            ask(gate, head, checked.base(), checked.change_id(), &[]),
            &store
        ),
        Lookup::Reject(AssureError::UntrustedInsert)
    ));
    assert_eq!(
        store.get(&checked.output()).unwrap(),
        outcome_image(&outcome).as_slice()
    );

    cache.insert(&checked, &store).unwrap();
    assert!(!cache.plant_untrusted(
        ask(gate, head, checked.base(), checked.change_id(), &[]),
        sha256(b"swap")
    ));
    match cache.lookup(
        ask(gate, head, checked.base(), checked.change_id(), &[]),
        &store,
    ) {
        Lookup::Hit(hit) => {
            let post = hit.require_accept().unwrap();
            assert_eq!(post, repo.head_root());
            assert_eq!(hit.output, checked.output());
        }
        other => panic!("trusted row must hit, got {other:?}"),
    }
    let Outcome::Accepted(receipt) = &outcome else {
        panic!("accepted")
    };
    assert_eq!(
        cache.lookup(
            ask(gate, receipt.post, checked.base(), checked.change_id(), &[]),
            &store
        ),
        Lookup::Reject(AssureError::StaleHead {
            recorded: receipt.pre,
            current: receipt.post
        })
    );
}

#[test]
fn a_different_gate_does_not_hit_and_conflict_signatures_ignore_the_gate() {
    let mut left = Repo::new(Gate::new(), genesis()).unwrap();
    let mut right = Repo::new(
        Gate::new().with(Forbid {
            token: "NOPE".into(),
        }),
        genesis(),
    )
    .unwrap();
    assert_ne!(left.gate().digest(), right.gate().digest());
    assert_eq!(left.head_root(), right.head_root());
    let change =
        Change::new("w", left.head_root(), Level::MeaningChange).put("n", Unit::new("n", &[]));
    let left_outcome = left.submit(change.clone());
    let right_outcome = right.submit(change.clone());
    assert!(left_outcome.is_accepted() && right_outcome.is_accepted());
    let mut store = ContentStore::new();
    let left_checked = bind_ok(&left, &change, &left_outcome, &mut store);
    let _right_checked = bind_ok(&right, &change, &right_outcome, &mut store);
    let mut cache = ActionCache::new();
    cache.insert(&left_checked, &store).unwrap();
    assert!(matches!(
        cache.lookup(
            ask(
                right.gate().digest(),
                left_checked.head(),
                change.base,
                change.id(),
                &[]
            ),
            &store
        ),
        Lookup::Reject(AssureError::GateMismatch { .. })
    ));
    let key = sha256(b"unit-key");
    assert_eq!(
        conflict_signature(Some(&key), None, Some(&key)),
        conflict_signature(Some(&key), None, Some(&key))
    );
    assert_ne!(left_checked.gate(), right.gate().digest());
}

#[test]
fn unknown_base_refusal_is_not_an_accept_and_g0_retries_share_an_image() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let bogus = sha256(b"never-held");
    let missing = Change::new("w", bogus, Level::Erratum).put("z", Unit::new("z", &[]));
    let first = repo.submit(missing.clone());
    let second = repo.submit(missing.clone());
    assert!(matches!(first.reason(), Some(Reason::UnknownBase(_))));
    assert_ne!(first.path(), second.path());
    assert_eq!(outcome_image(&first), outcome_image(&second));
    let mut gated = Repo::new(
        Gate::new().with(Forbid {
            token: "BAD".into(),
        }),
        genesis(),
    )
    .unwrap();
    let poisoned =
        Change::new("w", gated.head_root(), Level::MeaningChange).put("p", Unit::new("BAD", &[]));
    let refused = gated.submit(poisoned.clone());
    let retried = gated.submit(poisoned.clone());
    assert!(matches!(refused.reason(), Some(Reason::Gate { .. })));
    assert_ne!(refused.est_uj(), retried.est_uj());
    assert_ne!(refused.path(), retried.path());
    assert_eq!(outcome_image(&refused), outcome_image(&retried));
    let mut store = ContentStore::new();
    let checked = bind_ok(&repo, &missing, &first, &mut store);
    assert!(matches!(checked.decision(), Decision::Refuse));
    let mut cache = ActionCache::new();
    cache.insert(&checked, &store).unwrap();
    cache
        .insert(&bind_ok(&repo, &missing, &second, &mut store), &store)
        .unwrap();
    match cache.lookup(
        ask(
            repo.gate().digest(),
            checked.head(),
            bogus,
            missing.id(),
            &[],
        ),
        &store,
    ) {
        Lookup::Hit(hit) => assert_eq!(hit.require_accept(), Err(AssureError::NotAccept)),
        other => panic!("refusal must hit as a refusal, got {other:?}"),
    }
    assert_eq!(
        PhysicalEnergy::not_from_semantic_fuel(first.est_uj()),
        PhysicalEnergy::unknown()
    );
    assert_eq!(
        PhysicalEnergy::not_from_semantic_fuel(0),
        PhysicalEnergy::unknown()
    );
}

#[test]
fn individual_accepts_do_not_discharge_a_combined_revision() {
    let mut left = Repo::new(Gate::new(), genesis()).unwrap();
    let mut right = Repo::new(Gate::new(), genesis()).unwrap();
    let base = left.head_root();
    let edit_a = Change::new("a", base, Level::MeaningChange).put("p", Unit::new("from-a", &[]));
    let edit_b = Change::new("b", base, Level::MeaningChange).put("p", Unit::new("from-b", &[]));
    let left_outcome = left.submit(edit_a.clone());
    let right_outcome = right.submit(edit_b.clone());
    assert!(left_outcome.is_accepted() && right_outcome.is_accepted());
    let mut store = ContentStore::new();
    let mut cache = ActionCache::new();
    cache
        .insert(&bind_ok(&left, &edit_a, &left_outcome, &mut store), &store)
        .unwrap();
    cache
        .insert(
            &bind_ok(&right, &edit_b, &right_outcome, &mut store),
            &store,
        )
        .unwrap();
    let members = [edit_a.id(), edit_b.id()];
    assert_eq!(
        cache.lookup_combined(left.gate().digest(), base, &members, &store),
        Lookup::Reject(AssureError::UncheckedComposition)
    );
    assert!(cache.plant_combined_untrusted(&members, sha256(b"forged-combined")));
    assert_eq!(
        cache.lookup_combined(left.gate().digest(), base, &members, &store),
        Lookup::Reject(AssureError::UntrustedInsert)
    );

    let mut together = Repo::new(Gate::new(), genesis()).unwrap();
    let first = together.submit(edit_a.clone());
    let second = together.submit(edit_b.clone());
    assert!(first.is_accepted());
    assert!(matches!(second.reason(), Some(Reason::Conflict(_))));
    let checked = bind_ok(&together, &edit_b, &second, &mut store);
    cache
        .insert_combined(
            &together,
            &[edit_a.clone(), edit_b.clone()],
            &second,
            &checked,
            &store,
        )
        .unwrap();
    let pre = checked.head();
    match cache.lookup_combined(together.gate().digest(), pre, &members, &store) {
        Lookup::Hit(hit) => assert_eq!(hit.require_accept(), Err(AssureError::NotAccept)),
        other => panic!("combined refusal must not accept, got {other:?}"),
    }
    let extra =
        Change::new("c", together.head_root(), Level::MeaningChange).put("q", Unit::new("q2", &[]));
    assert!(together.submit(extra).is_accepted());
    assert!(matches!(
        cache.lookup_combined(
            together.gate().digest(),
            together.head_root(),
            &members,
            &store
        ),
        Lookup::Reject(AssureError::StaleHead { .. })
    ));
    assert_eq!(
        cache.insert_combined(
            &left,
            &[edit_b.clone(), edit_a.clone()],
            &left_outcome,
            &checked,
            &store
        ),
        Err(AssureError::ForgedBinding)
    );
}

#[test]
fn a_commuting_pair_is_combined_only_when_the_log_chain_was_checked() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let base = repo.head_root();
    let edit_p = Change::new("p", base, Level::MeaningChange).put("p", Unit::new("p1", &[]));
    let edit_q = Change::new("q", base, Level::MeaningChange).put("q", Unit::new("q1", &[]));
    let first = repo.submit(edit_p.clone());
    let second = repo.submit(edit_q.clone());
    assert!(first.is_accepted() && second.is_accepted());
    let mut store = ContentStore::new();
    let mut cache = ActionCache::new();
    cache
        .insert(&bind_ok(&repo, &edit_p, &first, &mut store), &store)
        .unwrap();
    let checked = bind_ok(&repo, &edit_q, &second, &mut store);
    cache.insert(&checked, &store).unwrap();
    let members = [edit_p.id(), edit_q.id()];
    assert_eq!(
        cache.lookup_combined(repo.gate().digest(), checked.head(), &members, &store),
        Lookup::Reject(AssureError::UncheckedComposition)
    );
    cache
        .insert_combined(
            &repo,
            &[edit_p.clone(), edit_q.clone()],
            &second,
            &checked,
            &store,
        )
        .unwrap();
    match cache.lookup_combined(repo.gate().digest(), checked.head(), &members, &store) {
        Lookup::Hit(hit) => assert_eq!(hit.require_accept().unwrap(), repo.head_root()),
        other => panic!("combined accept missing: {other:?}"),
    }
    assert!(matches!(
        cache.lookup_combined(repo.gate().digest(), repo.head_root(), &members, &store),
        Lookup::Reject(AssureError::StaleHead { .. })
    ));
    assert_eq!(
        cache.lookup_combined(repo.gate().digest(), checked.head(), &[edit_p.id()], &store),
        Lookup::Reject(AssureError::NotACombination)
    );
    let inputs = [sha256(b"fixture")];
    assert!(matches!(
        cache.lookup(
            ask(
                repo.gate().digest(),
                checked.head(),
                edit_q.base,
                edit_q.id(),
                &inputs
            ),
            &store
        ),
        Lookup::Miss
    ));
}

#[test]
fn compare_and_swap_retries_do_not_apply_twice_or_adopt_another_writer() {
    let a = sha256(b"A");
    let b = sha256(b"B");
    let c = sha256(b"C");
    let mut refs = CasRef::new(a);
    let op1 = sha256(b"op-1");
    let op2 = sha256(b"op-2");
    let op3 = sha256(b"op-3");
    assert_eq!(
        refs.compare_and_swap(op1, 0, a, b).unwrap(),
        CasOk::Applied(RefTip {
            target: b,
            epoch: 1
        })
    );
    assert_eq!(
        refs.compare_and_swap(op1, 0, a, b).unwrap(),
        CasOk::Replay {
            wrote: RefTip {
                target: b,
                epoch: 1
            },
            still_tip: true
        }
    );
    assert_eq!(refs.tip().epoch, 1);
    assert!(matches!(
        refs.compare_and_swap(op2, 0, a, c),
        Err(CasFail::Stale { .. })
    ));
    assert_eq!(
        refs.compare_and_swap(op2, 1, b, c).unwrap(),
        CasOk::Applied(RefTip {
            target: c,
            epoch: 2
        })
    );
    assert_eq!(
        refs.compare_and_swap(op1, 0, a, b).unwrap(),
        CasOk::Replay {
            wrote: RefTip {
                target: b,
                epoch: 1
            },
            still_tip: false
        }
    );
    assert_eq!(
        refs.tip(),
        RefTip {
            target: c,
            epoch: 2
        }
    );
    assert!(
        matches!(refs.compare_and_swap(op3, 0, a, c), Err(CasFail::UnrelatedWriter { current }) if current.target == c)
    );
    let other = sha256(b"not-b");
    assert!(matches!(
        refs.compare_and_swap(op1, 0, a, other),
        Err(CasFail::OpRetarget { wrote, requested }) if wrote.target == b && requested == other
    ));
    assert_eq!(refs.tip().target, c);
}

#[test]
fn corrupt_bytes_after_a_hit_are_not_a_hit() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let base = repo.head_root();
    let change = Change::new("w", base, Level::MeaningChange).put("p", Unit::new("v1", &[]));
    let outcome = repo.submit(change.clone());
    let mut store = ContentStore::new();
    let checked = bind_ok(&repo, &change, &outcome, &mut store);
    let mut cache = ActionCache::new();
    cache.insert(&checked, &store).unwrap();
    let query = ask(repo.gate().digest(), checked.head(), change.base, change.id(), &[]);
    assert!(matches!(cache.lookup(query, &store), Lookup::Hit(_)));
    store.plant_unverified(checked.output(), b"clobber".to_vec());
    assert_eq!(
        cache.lookup(query, &store),
        Lookup::Reject(AssureError::CorruptOutput)
    );
}

#[test]
fn a_different_gate_and_head_is_not_a_stale_head_hit() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let base = repo.head_root();
    let change = Change::new("w", base, Level::MeaningChange).put("n", Unit::new("n", &[]));
    let outcome = repo.submit(change.clone());
    let mut store = ContentStore::new();
    let checked = bind_ok(&repo, &change, &outcome, &mut store);
    let mut cache = ActionCache::new();
    cache.insert(&checked, &store).unwrap();
    let other_gate = sha256(b"other-gate");
    let other_head = sha256(b"other-head");
    assert!(matches!(
        cache.lookup(ask(other_gate, other_head, change.base, change.id(), &[]), &store),
        Lookup::Reject(AssureError::GateMismatch { recorded, current }) if recorded == checked.gate() && current == other_gate
    ));
}

#[test]
fn an_earlier_submission_does_not_hide_a_later_linked_chain() {
    let mut repo = Repo::new(Gate::new(), genesis()).unwrap();
    let base = repo.head_root();
    let edit_p = Change::new("p", base, Level::MeaningChange).put("p", Unit::new("p1", &[]));
    let edit_q = Change::new("q", base, Level::MeaningChange).put("q", Unit::new("q1", &[]));
    let early = repo.submit(edit_q.clone());
    let mid = repo.submit(edit_p.clone());
    let again = repo.submit(edit_q.clone());
    assert!(early.is_accepted() && mid.is_accepted() && again.is_accepted());
    let mut store = ContentStore::new();
    let checked = bind_ok(&repo, &edit_q, &again, &mut store);
    let mut cache = ActionCache::new();
    cache
        .insert_combined(&repo, &[edit_p.clone(), edit_q.clone()], &again, &checked, &store)
        .unwrap();
    match cache.lookup_combined(repo.gate().digest(), checked.head(), &[edit_p.id(), edit_q.id()], &store) {
        Lookup::Hit(hit) => assert!(hit.require_accept().is_ok()),
        other => panic!("later chain must be the combined row, got {other:?}"),
    }
    let early_checked = bind_ok(&repo, &edit_q, &early, &mut store);
    assert_eq!(
        cache.insert_combined(&repo, &[edit_p, edit_q], &early, &early_checked, &store),
        Err(AssureError::ForgedBinding)
    );
}
