//! Tests for the RCE-VC propositions. Randomized tests use a fixed-seed
//! SplitMix64 so every run is identical.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use rcevc_core::*;

// ---------- helpers ----------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn body_for(tag: &str, ndeps: usize) -> String {
    let mut b = tag.to_string();
    for i in 0..ndeps {
        b.push_str(&format!(" ${i}"));
    }
    b
}

/// Random well-formed DAG: unit i may depend on units < i.
fn random_state(rng: &mut Rng, n: usize) -> State {
    random_draft(rng, n).seal().unwrap()
}

fn random_draft(rng: &mut Rng, n: usize) -> Draft {
    let mut s = Draft::new();
    for i in 0..n {
        let mut deps: Vec<String> = Vec::new();
        if i > 0 {
            for _ in 0..rng.below(3) {
                let d = format!("s{}", rng.below(i as u64));
                if !deps.contains(&d) {
                    deps.push(d);
                }
            }
        }
        let refs: Vec<&str> = deps.iter().map(|d| d.as_str()).collect();
        s.put(format!("s{i}"), Unit::new(body_for(&format!("b{i}"), deps.len()), &refs));
    }
    s
}

fn random_change(rng: &mut Rng, s: &State, writer: &str) -> Change {
    let slots: Vec<String> = s.slots().into_iter().cloned().collect();
    let mut c = Change::new(writer, s.root(), Level::MeaningChange);
    for _ in 0..1 + rng.below(2) {
        let pick = slots[rng.below(slots.len() as u64) as usize].clone();
        match rng.below(4) {
            0 | 1 => {
                // edit body, keep bindings
                let u = s.get(&pick).unwrap();
                let body = body_for(&format!("e{}", rng.below(1000)), u.deps.len());
                let deps: Vec<&str> = u.deps.iter().map(|d| d.as_str()).collect();
                c = c.put(pick, Unit::new(body, &deps));
            }
            2 => {
                // add a fresh unit depending on an existing one
                let fresh = format!("x{}", rng.below(40));
                c = c.put(fresh, Unit::new("new $0", &[pick.as_str()]));
            }
            _ => {
                let fresh = format!("r{}", rng.below(40));
                c = c.rename(pick, fresh);
            }
        }
    }
    c
}

fn arity_gate() -> Gate {
    Gate::new().with(Forbid { token: "BAD".into() }).with(FnChecker {
        statement: Statement {
            name: "arity".into(),
            property_class: "interface: call sites match declared arity".into(),
            linking_assumption: "first dependency of a call site is the callee".into(),
            trusted_base: "test parser".into(),
            authority: Authority::Proved,
            scope: Scope::Closure,
            version: "1".into(),
        },
        f: |s, slot, u| {
            fn num(body: &str, key: &str) -> Option<u32> {
                let i = body.find(key)? + key.len();
                body[i..].split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
            }
            if let (Some(args), Some(dep)) = (num(&u.body, "args="), u.deps.first()) {
                if let Some(arity) = s.get(dep).and_then(|d| num(&d.body, "arity=")) {
                    if args != arity {
                        return Err(format!("{slot} calls {dep} with {args} args, arity {arity}"));
                    }
                }
            }
            Ok(())
        },
    })
}

struct Joiner {
    calls: Rc<Cell<u32>>,
    poison: bool,
}
impl Proposer for Joiner {
    fn propose(&self, _: &str, _: Option<&Unit>, o: Option<&Unit>, t: Option<&Unit>) -> Option<Option<Unit>> {
        self.calls.set(self.calls.get() + 1);
        let (o, t) = (o?, t?);
        let body = if self.poison { "BAD".to_string() } else { format!("{}|{}", o.body, t.body) };
        Some(Some(Unit { body, deps: o.deps.clone() }))
    }
}

fn two_slot_genesis() -> Draft {
    let mut g = Draft::new();
    g.put("p", Unit::new("v0", &[])).put("q", Unit::new("v0", &[]));
    g
}

// ---------- VC1: totality, no limbo ----------

#[test]
fn vc1_every_submission_is_accepted_or_refused_and_logged() {
    let mut g = Draft::new();
    g.put("a", Unit::new("a", &[])).put("b", Unit::new("b $0", &["a"]));
    let mut r = Repo::new(Gate::new(), g).unwrap();
    let base = r.head_root();
    let bogus = sha256(b"never held");

    let cases = vec![
        (Change::new("w", bogus, Level::Erratum).put("c", Unit::new("c", &[])), "UnknownBase"),
        (Change::new("w", base, Level::Erratum).del("zz"), "Apply"),
        (Change::new("w", base, Level::Erratum).put("c", Unit::new("c $0", &["missing"])), "IllFormed"),
        (Change::new("w", base, Level::Erratum).put("a", Unit::new("a $0", &["b"])), "IllFormed"),
        (Change::new("w", base, Level::Erratum).put("c", Unit::new("c $3", &["a"])), "IllFormed"),
        (Change::new("w", base, Level::Erratum).del("a"), "IllFormed"),
        (Change::new("w", base, Level::NameOnly).put("a", Unit::new("a2", &[])), "LevelMismatch"),
    ];
    let n = cases.len();
    for (c, want) in cases {
        let o = r.submit(c);
        let got = format!("{:?}", o.reason().expect("must be refused"));
        assert!(got.starts_with(want), "wanted {want}, got {got}");
        assert_eq!(r.head_root(), base, "refusal never moves head");
    }
    assert_eq!(r.log().len(), n);
    verify_chain(&r.genesis(), r.log()).unwrap();
}

// ---------- VC2: green by induction ----------

#[test]
fn vc2_every_head_is_well_formed_and_passes_the_gate() {
    let mut rng = Rng(2);
    let mut r = Repo::new(Gate::new().with(Forbid { token: "BAD".into() }), random_draft(&mut rng, 30)).unwrap();
    let mut accepted = 0;
    for i in 0..400 {
        let base_root = r.log().iter().rev().nth(rng.below(5) as usize).map_or(r.head_root(), |e| match &e.outcome {
            Outcome::Accepted(rc) => rc.post,
            Outcome::Refused(rf) => rf.pre,
        });
        let base = r.snapshot(&base_root).unwrap().clone();
        let mut c = random_change(&mut rng, &base, &format!("w{i}"));
        if rng.below(10) == 0 {
            if let Some(Op::Put { unit, .. }) = c.ops.iter_mut().find(|o| matches!(o, Op::Put { .. })) {
                unit.body.push_str(" BAD");
            }
        }
        if r.submit(c).is_accepted() {
            accepted += 1;
        }
    }
    assert!(accepted > 100, "test is vacuous: {accepted}");
    for e in r.log() {
        if let Outcome::Accepted(rc) = &e.outcome {
            let s = r.snapshot(&rc.post).unwrap();
            assert!(r.gate().run(s).is_ok());
        }
    }
}

// ---------- VC3: commuting changes are order independent ----------

#[test]
fn vc3_commutation_implies_order_independence() {
    let mut rng = Rng(3);
    let mut commuting = 0;
    for t in 0..3000 {
        let s = random_state(&mut rng, 12 + (t % 10));
        let a = random_change(&mut rng, &s, "a");
        let b = random_change(&mut rng, &s, "b");
        let (Ok(sa), Ok(sb)) = (apply(&s, &a.ops), apply(&s, &b.ops)) else { continue };
        if !commutes(&a, &b, &s) {
            continue;
        }
        commuting += 1;
        let ab = apply(&sa, &b.ops).expect("b applies after a");
        let ba = apply(&sb, &a.ops).expect("a applies after b");
        assert_eq!(ab, ba, "trial {t}");
        assert_eq!(ab.root(), ba.root());
    }
    assert!(commuting > 500, "test is vacuous: {commuting}");
}

#[test]
fn vc3_disjoint_writers_integrate_at_g1_in_either_order() {
    let mut g = Draft::new();
    for i in 0..6 {
        g.put(format!("m{i}"), Unit::new(format!("v{i}"), &[]));
    }
    let base = g.seal().unwrap().root();
    let a = Change::new("agent-a", base, Level::MeaningChange).put("m1", Unit::new("A", &[]));
    let b = Change::new("human-b", base, Level::MeaningChange).put("m4", Unit::new("B", &[]));

    let mut r1 = Repo::new(Gate::new(), g.clone()).unwrap();
    r1.submit(a.clone());
    let o = r1.submit(b.clone());
    assert_eq!(o.path(), &[Gear::G1Commute]);

    let mut r2 = Repo::new(Gate::new(), g).unwrap();
    r2.submit(b);
    r2.submit(a);
    assert_eq!(r1.head_root(), r2.head_root());
}

// ---------- VC4: structural merge and semantic re-validation ----------

#[test]
fn vc4_identical_edits_merge_and_semantic_conflicts_are_caught_at_g3() {
    let mut g = Draft::new();
    g.put("x", Unit::new("fn arity=1", &[])).put("y", Unit::new("call args=1 $0", &["x"]));
    let mut r = Repo::new(arity_gate(), g).unwrap();
    let base = r.head_root();

    // a: change x's arity and update its caller consistently.
    let a = Change::new("a", base, Level::InterfaceChange)
        .put("x", Unit::new("fn arity=2", &[]))
        .put("y", Unit::new("call args=2 $0", &["x"]));
    assert!(r.submit(a).is_accepted());

    // b (same base): add a new caller using the old arity. Alone it is fine;
    // merged, no slot conflicts, but the closures meet at x.
    let b = Change::new("b", base, Level::MeaningChange).put("z", Unit::new("call args=1 $0", &["x"]));
    let o = r.submit(b);
    assert_eq!(o.path(), &[Gear::G2Structural, Gear::G3Revalidate]);
    match o.reason() {
        Some(Reason::Gate { checker, .. }) => assert_eq!(checker, "arity"),
        other => panic!("expected semantic refusal, got {other:?}"),
    }

    // d: changing x's arity alone breaks y, which is not in d's edit. The
    // Closure-scoped checker re-checks dependents of the delta, so it is caught.
    let head = r.head_root();
    let d = Change::new("d", head, Level::InterfaceChange).put("x", Unit::new("fn arity=3", &[]));
    match r.submit(d).reason() {
        Some(Reason::Gate { checker, message }) => assert!(checker == "arity" && message.starts_with("y ")),
        other => panic!("expected dependent to be re-checked, got {other:?}"),
    }

    // c (same base): the same edit as a, already in head: merges cleanly.
    let c = Change::new("c", base, Level::Erratum).put("x", Unit::new("fn arity=2", &[]));
    let o = r.submit(c);
    assert!(o.is_accepted());
}

// ---------- VC5: compounding; model last ----------

#[test]
fn vc5_resolved_conflicts_are_reused_by_name_free_signature() {
    let calls = Rc::new(Cell::new(0));
    let mut r = Repo::new(Gate::new().with(Forbid { token: "BAD".into() }), two_slot_genesis())
        .unwrap()
        .with_proposer(Joiner { calls: calls.clone(), poison: false });
    let r0 = r.head_root();

    r.submit(Change::new("a", r0, Level::MeaningChange).put("p", Unit::new("va", &[])));
    let first = r.submit(Change::new("b", r0, Level::MeaningChange).put("p", Unit::new("vb", &[])));
    assert!(first.is_accepted());
    assert!(first.path().contains(&Gear::G4Proposer));
    assert_eq!(calls.get(), 1);
    assert_eq!(r.head().get("p").unwrap().body, "va|vb");

    // The same conflict, under a different name.
    let r2 = r.head_root();
    r.submit(Change::new("a", r2, Level::MeaningChange).put("q", Unit::new("va", &[])));
    let second = r.submit(Change::new("b", r2, Level::MeaningChange).put("q", Unit::new("vb", &[])));
    assert!(second.is_accepted());
    assert!(second.path().contains(&Gear::G0Lookup));
    assert!(!second.path().contains(&Gear::G4Proposer));
    assert_eq!(calls.get(), 1, "no second model call");
    assert!(second.est_uj() < first.est_uj() / 100);
    assert_eq!(r.head().get("q").unwrap().body, "va|vb");
}

#[test]
fn model_output_is_a_candidate_never_trusted() {
    let calls = Rc::new(Cell::new(0));
    let mut r = Repo::new(Gate::new().with(Forbid { token: "BAD".into() }), two_slot_genesis())
        .unwrap()
        .with_proposer(Joiner { calls, poison: true });
    let r0 = r.head_root();
    r.submit(Change::new("a", r0, Level::MeaningChange).put("p", Unit::new("va", &[])));
    let head = r.head_root();
    let o = r.submit(Change::new("b", r0, Level::MeaningChange).put("p", Unit::new("vb", &[])));
    assert!(matches!(o.reason(), Some(Reason::Gate { .. })));
    assert_eq!(r.head_root(), head);
    assert_eq!(r.reuse_len(), 0, "refused proposals are never promoted");
}

#[test]
fn unresolvable_conflict_without_proposer_is_refused_with_slots() {
    let mut r = Repo::new(Gate::new(), two_slot_genesis()).unwrap();
    let r0 = r.head_root();
    r.submit(Change::new("a", r0, Level::MeaningChange).put("p", Unit::new("va", &[])));
    let o = r.submit(Change::new("b", r0, Level::MeaningChange).put("p", Unit::new("vb", &[])));
    assert_eq!(o.reason(), Some(&Reason::Conflict(vec!["p".into()])));
}

// ---------- G0 memo ----------

#[test]
fn g0_identical_retry_costs_one_lookup() {
    let mut r = Repo::new(Gate::new().with(Forbid { token: "BAD".into() }), two_slot_genesis()).unwrap();
    let c = Change::new("agent", r.head_root(), Level::Erratum).put("p", Unit::new("BAD", &[]));
    let first = r.submit(c.clone());
    let retry = r.submit(c);
    assert_eq!(first.reason(), retry.reason());
    assert_eq!(retry.path(), &[Gear::G0Lookup]);
    assert_eq!(retry.est_uj(), CostTable::default().g0);
}

// ---------- D: state is the fold of the log ----------

#[test]
fn replay_reproduces_head_without_any_proposer() {
    let calls = Rc::new(Cell::new(0));
    let mut r = Repo::new(Gate::new().with(Forbid { token: "BAD".into() }), two_slot_genesis())
        .unwrap()
        .with_proposer(Joiner { calls: calls.clone(), poison: false });
    let r0 = r.head_root();
    r.submit(Change::new("a", r0, Level::MeaningChange).put("p", Unit::new("va", &[])));
    r.submit(Change::new("b", r0, Level::MeaningChange).put("p", Unit::new("vb", &[])));
    r.submit(Change::new("c", r0, Level::MeaningChange).put("q", Unit::new("BAD", &[])));
    let calls_live = calls.get();

    let replayed = Repo::replay(Gate::new().with(Forbid { token: "BAD".into() }), two_slot_genesis(), r.log()).unwrap();
    assert_eq!(replayed.head_root(), r.head_root());
    assert_eq!(replayed.log().last().unwrap().hash, r.log().last().unwrap().hash);
    assert_eq!(calls.get(), calls_live, "replay never calls the model");

    let mut tampered = r.log().to_vec();
    tampered[1].change.writer = "someone-else".into();
    assert_eq!(verify_chain(&r.genesis(), &tampered), Err(1));
    assert!(matches!(
        Repo::replay(Gate::new().with(Forbid { token: "BAD".into() }), two_slot_genesis(), &tampered),
        Err(ReplayError::BrokenChain(1))
    ));

    // A different gate is a different genesis: the chain does not verify.
    assert!(Repo::replay(Gate::new(), two_slot_genesis(), r.log()).is_err());
}

// ---------- R: name-free keys ----------

#[test]
fn renames_change_no_keys_and_name_only_is_verified() {
    let mut g = Draft::new();
    g.put("parse", Unit::new("p", &[])).put("main", Unit::new("m $0", &["parse"]));
    let sealed = g.seal().unwrap();
    let k_main = sealed.key("main").unwrap();
    let content = sealed.content_root();
    let mut r = Repo::new(Gate::new(), g).unwrap();
    let base = r.head_root();

    let o = r.submit(Change::new("w", base, Level::NameOnly).rename("parse", "parse_v2"));
    assert!(o.is_accepted());
    let h = r.head();
    assert_eq!(h.get("main").unwrap().deps, vec!["parse_v2".to_string()]);
    assert_eq!(h.key("main").unwrap(), k_main, "dependent's key unchanged");
    assert_eq!(h.content_root(), content);
    assert_ne!(r.head_root(), base, "projection root does change");

    // Concurrent edit to main from the old base, which still says "parse".
    // Closures meet (rename rebinds main), structural merge conflicts on main.
    let edit = Change::new("x", base, Level::MeaningChange).put("main", Unit::new("m2 $0", &["parse"]));
    let o = r.submit(edit);
    assert!(!o.is_accepted());
}

#[test]
fn monotone_changes_commute() {
    let s = two_slot_genesis().seal().unwrap();
    let base = s.root();
    let a = Change::new("a", base, Level::MeaningChange).put("n1", Unit::new("x $0", &["p"]));
    let b = Change::new("b", base, Level::MeaningChange).put("n2", Unit::new("y $0", &["q"]));
    assert!(a.is_monotone(&s) && b.is_monotone(&s));
    assert!(commutes(&a, &b, &s));
    let reads: BTreeSet<_> = a.reads();
    assert!(reads.contains("p"));
}

// ---------- scoped gate is equivalent to the full gate ----------

#[test]
fn delta_gate_agrees_with_full_gate() {
    let gate = arity_gate();
    let mut rng = Rng(11);
    let (mut checked, mut refused) = (0, 0);
    for _ in 0..600 {
        let mut d = Draft::new();
        let arity = rng.below(3);
        d.put("x", Unit::new(format!("fn arity={arity}"), &[]));
        for i in 0..8 {
            d.put(format!("c{i}"), Unit::new(format!("call args={arity} $0"), &["x"]));
        }
        let s = d.seal().unwrap();
        if gate.run(&s).is_err() {
            continue; // the induction hypothesis: we only extend accepted states
        }
        let slot = if rng.below(2) == 0 { "x".to_string() } else { format!("c{}", rng.below(8)) };
        let body = if slot == "x" { format!("fn arity={}", rng.below(3)) } else { format!("call args={} $0", rng.below(3)) };
        let deps: Vec<&str> = if slot == "x" { vec![] } else { vec!["x"] };
        let t = s.with([(slot, Some(Unit::new(body, &deps)))]).unwrap();
        let delta = diff(&s, &t);
        let (full, scoped) = (gate.run(&t).is_ok(), gate.run_delta(&t, &delta).is_ok());
        assert_eq!(full, scoped);
        checked += 1;
        refused += usize::from(!full);
    }
    assert!(checked > 500 && refused > 100, "vacuous: {checked} checked, {refused} refused");
}

#[test]
fn snapshots_share_structure_and_diff_is_exact() {
    let mut rng = Rng(5);
    let s0 = random_state(&mut rng, 300);
    let mut s = s0.clone();
    let mut touched = std::collections::BTreeSet::new();
    for _ in 0..20 {
        let c = random_change(&mut rng, &s, "w");
        if let Ok(t) = apply(&s, &c.ops) {
            touched.extend(diff(&s, &t));
            s = t;
        }
    }
    // s0 is unchanged by later edits; diff equals the slots that really differ.
    let mut naive = std::collections::BTreeSet::new();
    let (a, b) = (s0.iter(), s.iter());
    let am: std::collections::BTreeMap<_, _> = a.into_iter().collect();
    let bm: std::collections::BTreeMap<_, _> = b.into_iter().collect();
    for k in am.keys().chain(bm.keys()) {
        if am.get(k) != bm.get(k) {
            naive.insert((*k).clone());
        }
    }
    assert_eq!(diff(&s0, &s), naive);
    assert!(naive.is_subset(&touched));
    // Rebuilding from scratch gives the same root and keys as incremental edits.
    let mut d = Draft::new();
    for (k, u) in s.iter() {
        d.put(k.clone(), u.clone());
    }
    let fresh = d.seal().unwrap();
    assert_eq!(fresh.root(), s.root());
    assert_eq!(fresh.keys(), s.keys());
}
