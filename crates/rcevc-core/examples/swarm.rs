//! Swarm: many writers, stale bases, one repository.
//!
//! Each round, every writer snapshots head, edits one unit, and submits.
//! All writers in a round share the same (soon stale) base, which is the
//! situation that makes merge queues serialize. A fifth of writers crowd one
//! hot module. A few submissions carry a forbidden token. True conflicts go
//! to a deterministic stand-in proposer (in production, a model, rung G4).
//!
//! Run: `cargo run --release --example swarm -- [writers] [rounds] [modules]`
//! (10 units per module)

use std::collections::BTreeMap;
use std::time::Instant;

use rcevc_core::*;

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
        self.next() % n
    }
}

/// Stand-in for a model: joins both bodies. Deterministic.
struct Join;
impl Proposer for Join {
    fn propose(&self, _: &str, _: Option<&Unit>, o: Option<&Unit>, t: Option<&Unit>) -> Option<Option<Unit>> {
        let (o, t) = (o?, t?);
        let strip = |b: &str| b.trim_end_matches(" $0").to_string();
        let tail = if o.deps.is_empty() { "" } else { " $0" };
        Some(Some(Unit { body: format!("{}+{}{tail}", strip(&o.body), strip(&t.body)), deps: o.deps.clone() }))
    }
}

const PER_MODULE: usize = 10;

fn genesis(modules: usize) -> Draft {
    let mut s = Draft::new();
    for m in 0..modules {
        for u in 0..PER_MODULE {
            let slot = format!("m{m:02}/u{u}");
            if u == 0 {
                s.put(slot, Unit::new(format!("m{m}u0"), &[]));
            } else {
                let dep = format!("m{m:02}/u{}", u - 1);
                s.put(slot, Unit::new(format!("m{m}u{u} $0"), &[dep.as_str()]));
            }
        }
    }
    s
}

fn gate() -> Gate {
    Gate::new().with(Forbid { token: "BAD".into() })
}

fn main() {
    let args: Vec<u64> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let writers = *args.first().unwrap_or(&64);
    let rounds = *args.get(1).unwrap_or(&20);
    let modules = *args.get(2).unwrap_or(&40) as usize;

    let mut repo = Repo::new(gate(), genesis(modules)).expect("genesis").with_proposer(Join);
    let mut rng = Rng(0x5eed);
    let mut paths: BTreeMap<String, u64> = BTreeMap::new();
    let mut reasons: BTreeMap<String, u64> = BTreeMap::new();
    let (mut stale, mut stale_admitted, mut total_uj) = (0u64, 0u64, 0u64);

    let t0 = Instant::now();
    for round in 0..rounds {
        let base_root = repo.head_root();
        let base = repo.head().clone();
        let mut batch = Vec::new();
        for w in 0..writers {
            let m = if rng.below(5) == 0 { 0 } else { rng.below(modules as u64) as usize };
            let u = rng.below(PER_MODULE as u64) as usize;
            let slot = format!("m{m:02}/u{u}");
            let old = base.get(&slot).expect("slot");
            let poison = if rng.below(50) == 0 { " BAD" } else { "" };
            let tail = if old.deps.is_empty() { "" } else { " $0" };
            let deps: Vec<&str> = old.deps.iter().map(|d| d.as_str()).collect();
            let unit = Unit::new(format!("r{round}w{w}{poison}{tail}"), &deps);
            let writer = if w % 2 == 0 { format!("agent-{w}") } else { format!("human-{w}") };
            batch.push(Change::new(writer, base_root, Level::MeaningChange).put(slot, unit));
        }
        for c in batch {
            let is_stale = c.base != repo.head_root();
            let o = repo.submit(c);
            total_uj += o.est_uj();
            let key = o.path().iter().map(|g| format!("{g:?}")).collect::<Vec<_>>().join(">");
            *paths.entry(format!("{} {}", if o.is_accepted() { "accept" } else { "refuse" }, key)).or_default() += 1;
            if let Some(r) = o.reason() {
                let name = format!("{r:?}");
                *reasons.entry(name.split(['(', ' ', '{']).next().unwrap_or("").to_string()).or_default() += 1;
            }
            if is_stale {
                stale += 1;
                if o.is_accepted() {
                    stale_admitted += 1;
                }
            }
        }
    }
    let elapsed = t0.elapsed();
    let n = repo.log().len() as u64;

    println!("RCE-VC swarm: {writers} writers x {rounds} rounds = {n} submissions, {} units", modules * PER_MODULE);
    println!("\npath (gears used)                                   count   share");
    for (k, v) in &paths {
        println!("  {k:<48} {v:>6}  {:>5.1}%", 100.0 * *v as f64 / n as f64);
    }
    println!("\nrefusals by reason: {reasons:?}");
    println!("submissions on a stale base:      {stale}");
    println!("  admitted with no writer rebase: {stale_admitted} ({:.1}%)", 100.0 * stale_admitted as f64 / stale.max(1) as f64);
    println!("proposer (G4) calls:              {}", repo.proposer_calls());
    println!("resolutions promoted for reuse:   {}", repo.reuse_len());
    println!("est_j total:                      {:.3} J (stated cost table, not measured)", total_uj as f64 / 1e6);
    println!("measured wall time:               {:.1} ms ({:.1} us per submission, debug={})",
        elapsed.as_secs_f64() * 1e3, elapsed.as_secs_f64() * 1e6 / n as f64, cfg!(debug_assertions));

    let t1 = Instant::now();
    let replayed = Repo::replay(gate(), genesis(modules), repo.log()).expect("replay");
    assert_eq!(replayed.head_root(), repo.head_root());
    println!("\nreplay from genesis, no proposer:  identical head {} in {:.1} ms",
        replayed.head_root().short(), t1.elapsed().as_secs_f64() * 1e3);
    println!("log chain verified:                {} entries", replayed.log().len());
}
