# RCE-VC — the Law of Version Control (reference implementation)

> Version control is the admission of changes to a canonical, name-free
> repository state. Each change is admitted only when a named checker accepts
> the post-state under a declared contract, or is refused with a recorded
> reason; changes whose dependency closures do not meet are admitted without
> coordination; among admissible integrations, a stated cost ranks the
> candidates; and every accepted result, including every resolved conflict,
> is reused.

This workspace covers milestones **M0**, **M1** and **M2** of the RCE-VC paper (v0.1, 6 Nov 2026):
`rcevc-core`, the deterministic heart (now on persistent Merkle state), and `rcevc-proj-git`, the Git projection. Std-only Rust, edition 2024,
`#![forbid(unsafe_code)]`, no clock, no randomness, no I/O, no dependencies.

## What is implemented

| Form part | Where | What it does |
|---|---|---|
| R name-free keys | `model.rs` | Unit bodies use positional refs `$0…`; key = H(body, keys of deps). Renames change no key. Units with no deps are literal text (any file). |
| S persistent state | `hamt.rs`, `model.rs` | Merkle HAMT: O(1) clone and root, diff in O(difference), canonical shape. Keys and the reverse-dependency index update incrementally. `Draft` (unvalidated) vs `State` (always well formed). |
| Δ typed changes | `change.rs` | Put / Del / Rename against a declared base, with a declared level (`NameOnly` is kernel-verified). |
| X commutation | `change.rs` | Writes = actual diff; closure = writes ∪ dependents (before and after) ∪ reads. Disjoint ⇒ commute. |
| K, G checker and gate | `gate.rs` | Each checker states property class, linking assumption, trusted base, authority, **scope** (Unit, Closure, Global), digest. The gate re-checks only the declared scope of each delta. |
| δ and the ladder | `repo.rs` | G0 lookup → G1 commutation → G2 three-way structural → G3 re-validation → G4 proposer. Gate runs on every path. |
| D log | `repo.rs` | Hash-chained entries; head is the fold of the log; `Repo::replay` rebuilds it with no proposer. |
| U reuse | `repo.rs` | Resolutions keyed by a name-free conflict signature, promoted only after the gate accepts them. |
| C cost | `repo.rs` | Stated per-rung cost table (`est_j` class); receipts carry it. |

Not here yet: storage beyond Git loose objects, leases, Wasmtime sandboxing
of checkers, measured energy. See the roadmap below.

## Assurance boundary

`rcevc-core::assure` keeps admission on `Repo::submit`. It does not add a
second receipt. A content digest proves the bytes, not that an action
produced them. A checked action is minted only from an outcome already in
that repository's log, and it applies only at the head and gate it was
checked against. Individual accepts do not discharge a combined sequence.
`CasRef` and `GitDir::compare_and_swap_ref` retry one op id; another writer's
identical target is not success. Stated `est_uj` is not electricity. The
in-repository conflict signature is unchanged and is not this cache.

The gap inventory, threat model, and the measurements from one machine are
in `docs/ingestion-2026-11-07.md`.

```
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
cargo run --release -p rcevc-proj-git --example isolate_bench -- /tmp/rcevc-isolate
```

`.github/workflows/ci.yml` runs `cargo test --locked --offline --all-targets`
and `cargo clippy --locked --offline --all-targets -- -D warnings` on pull
requests, with Rust 1.85.0. An empty check list is not a passing result.

## Content units (`rcevc-keys`)

`rcevc-keys` splits a Rust or Python file into top-level items. Each item's
id is the core name-free key of a normalized token body, so a rename of the
item does not change that key, and whitespace or comment extras do not either.
Exact bytes, including whitespace and comments, stay in `parts`. `project`
concatenates them back to the source. A dependency points only at an earlier
item in the same file. A path that is not `.rs` or `.py`, or a tree with a
parse error, is one leaf over the original bytes.

HANDOFF section 9 B also names TypeScript. That grammar is not in this crate.
Python is the other grammar from that list. Tree-sitter 0.27 needs Rust 1.90,
so the lock is `tree-sitter` 0.26.13, `tree-sitter-rust` 0.24.2, and
`tree-sitter-python` 0.25.0. Those crates, and their dependencies, are in
`vendor/`. `.cargo/config.toml` points Cargo at that directory, which is why
CI can stay `--locked --offline`. The grammar build compiles C and needs a
system C compiler (`cc`). It does not download anything at build time.

This layer does not state an energy or throughput result.

## Propositions → tests (`crates/rcevc-core/tests/propositions.rs`)

| Claim | Test |
|---|---|
| VC1 totality, no limbo: every submission is accepted or refused with a reason, and logged | `vc1_every_submission_is_accepted_or_refused_and_logged` |
| VC2 green by induction: every head is well formed and passes the gate | `vc2_every_head_is_well_formed_and_passes_the_gate` (400 random submissions, stale bases, poisoned changes) |
| VC3 commutation ⇒ order independence | `vc3_commutation_implies_order_independence` (3,000 random trials, >500 commuting pairs checked) and `vc3_disjoint_writers_integrate_at_g1_in_either_order` |
| VC4 semantic conflicts caught with no textual conflict | `vc4_identical_edits_merge_and_semantic_conflicts_are_caught_at_g3` (arity change vs new caller) |
| VC5 compounding, name-free reuse | `vc5_resolved_conflicts_are_reused_by_name_free_signature` (second conflict under another name: no model call, >100× cheaper) |
| Model last, never trusted | `model_output_is_a_candidate_never_trusted` |
| State is the fold of the log; tamper evident | `replay_reproduces_head_without_any_proposer` |
| Name-free keys; `NameOnly` verified | `renames_change_no_keys_and_name_only_is_verified` |
| G0 idempotent retries | `g0_identical_retry_costs_one_lookup` |
| Scoped gate ≡ full gate (VC2 stays sound at O(change)) | `delta_gate_agrees_with_full_gate` (600 trials, >100 refusals) |
| Snapshots untouched by later edits; diff exact; incremental = from-scratch | `snapshots_share_structure_and_diff_is_exact`, HAMT tests in `hamt.rs` |
| SHA-256 correctness | FIPS 180-4 vectors in `hash.rs` |

```
cargo test --offline                                   # 49 tests (core 29, keys 8, git 12)
cargo run --release --example swarm                    # 64 writers x 20 rounds, 400 units
cargo run --release --example swarm -- 64 5 10000      # same workload at 100,000 units
```

## Swarm result (measured on this build, release, 1 core)

64 writers per round, all on the round's starting base (so almost every
submission is stale), 20% crowding one hot module, 2% poisoned:

| Path | Share |
|---|---|
| accepted at G1 (commuted, no merge) | 57.0% |
| accepted at G2→G3 (structural merge, re-validated) | 27.3% |
| accepted at G2→G4→G3 (true conflict, proposer, re-validated) | 13.8% |
| refused by the gate (all poisoned changes, including 6 proposer outputs that inherited the poison) | 1.9% |

1,259 of 1,280 submissions were on a stale base; 98.1% of those were admitted
with no writer rebase. 182 proposer calls out of 1,280 submissions. Replay
from genesis with no proposer reproduced the identical head.

Cost figures in receipts are a stated table, not measurements.

## M1: integration cost follows the change, not the repository

Same swarm workload (64 writers × 5 rounds, same seed), release build, one
core, measured wall time per submission:

| Units | M0 (cloned maps) | M1 (persistent Merkle state) | Speed-up |
|---:|---:|---:|---:|
| 400 | 2,103 µs | 98 µs | 21× |
| 4,000 | 27,536 µs | 105 µs | 262× |
| 40,000 | not run | 136 µs | |
| 100,000 | not run | 188 µs | |

M0 grew linearly with repository size; M1 is close to flat (the slow rise is
trie depth and the size of what moved within a round). What made it flat:

1. **Persistent Merkle HAMT.** Snapshots of every admitted state share
   structure; the state root is the trie hash, so it is O(1).
2. **Hash-skipping diff.** `diff(base, head)` and the gate's delta skip equal
   subtrees, so they cost O(difference).
3. **Incremental keys.** An edit re-keys only edited units and their
   dependents, found through a persistent reverse-dependency index.
4. **Scoped gate.** Checkers declare Unit, Closure or Global scope; the gate
   re-checks the declared scope of the delta. Given the previous head passed,
   this is equivalent to a full check (tested differentially).

Replay from genesis is still O(n) once, for building genesis (2.4 s at
100,000 units); the log itself replays at integration speed.

## M2: the Git projection (`crates/rcevc-proj-git`)

Interface compatibility is where every Git successor has stalled, so the
projection ships before anything else. Nobody has to stop using Git.

- **Out.** `export` writes every admitted state as an ordinary Git commit on
  `main`, with the writer as author, the writer's stated intent as the
  message, and the receipt as Git trailers (`RCE-VC-Path`, `-Pre`, `-Post`,
  `-Evidence`, `-Resolved`, `-Est-uJ`, `-Entry`). `refs/rcevc/log` holds one
  commit per log entry, refusals included. Export is a pure function of the
  log and a time base: the same log gives byte-identical commit ids anywhere.
- **In.** `ingest` turns any plain `git commit` (or a chain of them on a
  branch) into one `Change` against the nearest admitted ancestor. The branch
  is the proposal; the ladder decides. No rebase is asked of the writer.
- **Files ↔ units.** A file is a leaf unit (literal text, `$` included). A
  unit with dependencies is a file with a short `#rcevc-unit v1` header. The
  mapping is a bijection on UTF-8 files.

Verified against git 2.43 (`tests/git_interop.rs`):

| Check | Result |
|---|---|
| `git fsck --full --strict` on exported history | clean |
| every commit on `main` re-imports to the exact root in its `RCE-VC-Post` trailer | yes |
| two exports of the same log in different directories | identical commit ids |
| git's own `%(trailers)` parser reads receipts | yes |
| a person's two plain git commits on a branch, base gone stale | ingested as one change, admitted at G1, `main` fast-forwards |
| reading git-written objects, including dynamic-Huffman deflate | yes (inflate implemented in `codec.rs`) |
| a plain git commit with a forbidden token | refused, recorded on `refs/rcevc/log`, `main` unmoved |

```
cargo run -p rcevc-proj-git --example git_roundtrip -- /tmp/rcevc-demo
git -C /tmp/rcevc-demo log --stat main
```

Limits of this version: loose objects and loose refs only (packfiles and
packed refs go to gix once the network allows it); file modes are 100644 on
the way out (the executable bit is not yet a unit attribute); symlinks,
submodules and non-UTF-8 files are refused with a reason rather than guessed.

## Toolchain

Written for stable Rust, edition 2024, MSRV 1.85 without `if`/`while` let-chains
(those need a newer compiler). Built and tested here with rustc 1.85.1. Hash is
SHA-256 on std; BLAKE3 is the design target for internal keys and replaces
`hash.rs` only.

## Roadmap (from the paper)

- **M1** in progress: persistent state, incremental keys, scoped gate, and `rcevc-keys` for Rust and Python top-level items. TypeScript units, and a byte-identical corpus round trip, are not done.
- **M2** done in std-only form (below); next: move storage to gix with packfiles, and run the round trip on 1,000 public repositories.
- **M3** `rcevc-gate` on Wasmtime: checkers as fuel-limited, deterministic Wasm modules with pinned digests.
- **M4** leases and the real-time channel (CALM-monotone changes stream without coordination).
- **M5** replay corpora: Merge-Bench, CONGRA, AgenticFlict through the ladder (protocol P1).
- **M6** `rcevc-meter`: `measured_j` replaces `est_j`.
