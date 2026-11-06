# RCE-VC hand-off (for grokbot)

Date: Friday 6 November 2026. From: Claude (Anthropic), cloud coding session.
Owner: David (OpenIE, research.openie.dev). State: v0.1, milestones M0, M1
and M2 done; 24 tests green; std-only Rust.

Read this file first, then `README.md`, then the code. Everything below is
checked against the code as it stands; where something is a plan or a
guess, it says so.

---

## 1. What this project is

**Goal.** Replace the "branch, diff, merge into one main" model of Git with
something that works for any number of humans and agents writing at once,
without asking anyone to stop using Git. The owner's framing: diffing and
merging parallel branches is a legacy concept, interface compatibility is
the bottleneck that keeps it alive, and the fix should take *the AI out of
the loop* wherever a deterministic rule can decide.

**The RCE family.** RCE (the owner's thesis at research.openie.dev) is
organised around Laws: Law of Coding (RCE), Law of Intent (RCE-JEPA), Law of
Compilation (RCE-Compile). RCE-VC adds the **Law of Version Control**. It
borrows RCE's framing (a Form, a total deterministic transition, a
hash-chained log whose fold is the state, name-free hashing, a gear ladder
with the model last) but is *not* built on the RCE language.

**The Law, verbatim (do not paraphrase in code docs):**

> Version control is the admission of changes to a canonical, name-free
> repository state. Each change is admitted only when a named checker
> accepts the post-state under a declared contract, or is refused with a
> recorded reason; changes whose dependency closures do not meet are
> admitted without coordination; among admissible integrations, a stated
> cost ranks the candidates; and every accepted result, including every
> resolved conflict, is reused.

**Design stance on users:** assume any arbitrary writer. Admission never
depends on who wrote a change (`Change.writer` is an opaque label).

## 2. Where everything is

| What | Where |
|---|---|
| Paper draft v0.1: theory, nine-part Form, propositions VC1–VC8, hypotheses, falsifiers, roadmap | Claude Doc "RCE-VC: The Law of Version Control", https://claude.ai/artifact/DYrF9g5iWQ8nj5hSbcFCs5 (private to the owner; ask them to share) |
| Landscape and prior art (Pijul, Unison, jj, Mergiraf, semistructured merge, SafeMerge, SubmitQueue, Japan's Historef/CCFinder, agent-era corpora, patents) | Claude Doc "Beyond Git", https://claude.ai/artifact/CVRbBzKB96twCQ9fGsVxkC |
| Code | this workspace (`rce-vc/`), shipped as `rce-vc.zip` |
| Overview and benchmark tables | `README.md` |

There is no git remote yet. The zip is the source of truth.

## 3. Build, test, run

```
cargo test --offline                                    # 24 tests: core 18, git 6 (~15 s debug)
cargo clippy --offline --all-targets                    # must stay at 0 warnings
cargo run --release -p rcevc-core --example swarm -- 64 5 10000     # 100k units
cargo run -p rcevc-proj-git --example git_roundtrip -- /tmp/rcevc-demo
git -C /tmp/rcevc-demo log --format='%h %an %s%n%(trailers)' main
```

Toolchain used: rustc/cargo 1.97.0, edition 2024, MSRV 1.85; git 2.43 for
the interop tests (they skip with a message if git is missing). Current
stable is 1.99.1; nothing used is newer than 1.85.

**Environment gotcha.** The session that wrote this had **no network**
(crates.io did not resolve), so there are **zero dependencies**: SHA-256,
SHA-1, zlib inflate and Git object I/O are hand-written. If you have
network, see §9 for what to swap in. Do not add a dependency to
`rcevc-core` without a strong reason: "no clock, no randomness, no I/O, no
dependencies, no unsafe" is a design property of the core, not just a
constraint we worked around.

## 4. Layout

```
Cargo.toml                       workspace (resolver 3, edition 2024)
crates/rcevc-core/               the deterministic core
  src/hash.rs      199  SHA-256, Digest, Enc (canonical domain-separated encoder)
  src/hamt.rs      339  persistent Merkle HAMT (16-way over SHA-256(name))
  src/model.rs     460  Unit, Draft, State (persistent), Edit, incremental keys, diff
  src/change.rs    245  Op, Level, Change, apply, writes/reads/closure, commutes
  src/gate.rs      235  Authority, Scope, Statement, Checker, Gate, Forbid, FnChecker
  src/repo.rs      598  δ (submit), the ladder, receipts, log, replay, reuse
  tests/propositions.rs 476  VC1–VC5 and M1 property tests
  examples/swarm.rs     134  many-writer simulation and benchmark
crates/rcevc-proj-git/           the Git projection Π_git
  src/codec.rs     325  SHA-1, Adler-32, zlib store, full inflate (RFC 1950/1951)
  src/store.rs     177  GitDir: loose objects, loose refs, Oid, ProjError
  src/project.rs   341  unit⇄file mapping, trees, commits, export, ingest
  tests/git_interop.rs  194  verified against the real git binary
  examples/git_roundtrip.rs 92  narrated demo
```

## 5. How it works (the parts you must understand before editing)

### 5.1 Data model (`model.rs`)

- **Unit** = `{ body: String, deps: Vec<Slot> }`. If `deps` is non-empty,
  `$i` in the body refers to `deps[i]` and `$$` is a literal `$`. If `deps`
  is empty the unit is a **leaf** and its body is literal text: any file is
  a leaf, `$1` in a shell script included.
- **Key** (name-free identity) = `H("rcevc/unit/v1", body, keys of deps)`.
  A rename changes bindings, never keys. **Content** digest =
  `H(body, dep names)` and is what the trie hashes.
- **Draft**: an unvalidated `BTreeMap`. Use it for genesis and for anything
  read from outside. `Draft::seal()` validates into a State.
- **State**: always well formed (deps resolve, every `$i` bound, acyclic).
  It holds three persistent maps: `units` (Merkle), `keys` and `users`
  (reverse-dependency index), both non-Merkle. Cloning is O(1).
  `root()` is O(1). Equality is root equality.
- **Edit**: `state.edit()`, then `set(slot, Some/None)` repeatedly, then
  `finish()`. Validation and re-keying happen once at the end, only over
  `rdep_closure(touched)`. Intermediate states inside an Edit may be
  ill formed; that is intended, for example a delete followed by a put.
- **diff(a, b)**: slots whose unit differs, found by skipping equal-hash
  subtrees. Cost is O(difference). Dependents whose *key* changed but whose
  unit did not are **not** in the diff, deliberately (see §6, invariant 7).

### 5.2 Changes and commutation (`change.rs`)

- `Op::{Put, Del, Rename}`; `Level::{NameOnly, Erratum, MeaningChange,
  InterfaceChange}`. `NameOnly` is verified by the kernel: the multiset of
  keys must be unchanged.
- `Change { writer, base, level, ops, message }`. `id()` covers all fields.
  `message` is the stated intent (for example a commit message); admission
  never reads it.
- `writes(s)` = diff(s, apply(s)); `reads()` = deps of puts and rename
  sources; `closure_in(s, post)` = writes ∪ dependents before ∪ dependents
  after ∪ reads.
- `commutes(a, b, s)` ⇔ writes(a) ∩ closure(b) = ∅ and the same the other
  way round. Property-tested: commuting ⇒ both orders give the same root.

### 5.3 The transition δ and the ladder (`repo.rs`, `Repo::submit`)

`submit` is **total**: it always returns `Accepted(Receipt)` or
`Refused(Refusal)` and appends exactly one hash-chained `Entry`.

1. **G0 lookup.** An identical (head, change id) pair that was refused
   before returns the memoised refusal for one unit of cost.
2. Resolve `base` from snapshots (else `UnknownBase`). `theirs =
   apply(base, ops)` (else `Apply` or `IllFormed`). Check the NameOnly
   claim.
3. **G1 commute.** Let `moved = diff(base, head)`. If the change's closure
   (in base and in head) misses `moved`, apply it to head directly.
4. **G2 structural.** Otherwise do a per-slot three-way merge over `moved ∪
   diff(base, theirs)` only.
   - One side unchanged: take the other side.
   - Both sides equal: take either.
   - Otherwise it is a conflict:
     - **G0 reuse**: look up the conflict's name-free signature
       `H(key_base, key_head, key_theirs)`.
     - Otherwise **G4 proposer** (the model).
     - Otherwise refuse with `Conflict(slots)`.
5. **G3 re-validate.** The merged state is built with `head.with(assign)`,
   which checks well-formedness.
6. **Gate on every path.** `gate.run_delta(candidate, diff(head,
   candidate))`.
7. On accept, promote proposer resolutions into the reuse store **only
   now**. Snapshot the new head and write the receipt (path of gears,
   evidence, resolution, `est_uj`).

`Repo::replay(gate, genesis, log)` verifies the hash chain, then
re-integrates every entry in replay mode. Conflicts take their recorded
resolution; **no proposer is ever called**. Replay checks each pre/post root
and each refusal reason.

### 5.4 Gate and scope (`gate.rs`)

Each checker states its name, property class, linking assumption, trusted
base, authority (Pinned, Replay, Proved, Derived, Inferred), **scope**, and
version. All of these are covered by `Statement::digest()`, and the gate's
digest feeds the genesis hash.

- `Scope::Unit`: the gate re-checks only units in the delta.
- `Scope::Closure`: the verdict depends on the unit and its transitive
  dependencies, so the gate re-checks the delta plus its dependents.
- `Scope::Global`: the gate checks the whole state.

Given that the previous head passed, a scoped re-check equals a full check,
*if the declared scope is true*. Test: `delta_gate_agrees_with_full_gate`.
A checker that lies about its scope breaks VC2. That is why the plan is to
enforce scope in a sandbox (§9).

### 5.5 Git projection (`rcevc-proj-git`)

- **Files ⇄ units.** A leaf is the raw file. A unit with deps is written as:

  ```
  #rcevc-unit v1
  #dep <slot>        (one line per dependency)
  #body
  <body>
  ```

  This mapping is a bijection on UTF-8 files.
- **`export(g, repo, genesis, branch, time_base)`.**
  - Writes `main` with one commit per *accepted* entry. Author is the
    writer; the subject is `Change.message`, or `admit <id> via <gears>`
    if there is no message.
  - Receipt trailers on each commit: `RCE-VC-Change`, `-Pre`, `-Post`,
    `-Path`, `-Evidence`, `-Resolved`, `-Est-uJ`, `-Entry`.
  - Also writes `refs/rcevc/log`, with one commit per entry, refusals
    included (message prefix `log: `).
  - Deterministic: same log and same time base give the same commit ids.
- **`ingest(g, tip, repo)`.**
  - Walks first parents from `tip` until it finds a commit carrying
    `RCE-VC-Post` whose root is a snapshot. That snapshot is the base.
  - Reads the tip's tree into a Draft and emits one Change: `Put`/`Del`
    ops via `Draft::changes_from`.
  - The message is the folded commit messages. If the content multiset is
    unchanged, the level is `NameOnly`.
- **Verified against git:** `fsck --full --strict` is clean; every `main`
  commit re-imports to its `RCE-VC-Post` root; export is reproducible; a
  person's plain git branch is admitted at G1 without a rebase; a forbidden
  token is refused and logged with `main` unmoved; git-written
  dynamic-Huffman objects are read correctly.

## 6. Invariants you must not break

Each is enforced by a named test. Run the full suite after any change.

1. **Totality (VC1).** `submit` never panics on user input and always logs
   one entry. No `unwrap` on anything derived from a Change.
2. **Green by induction (VC2).** Only well-formed, gate-passing states
   become head. The gate runs on *every* path, G1 included.
3. **Model last, never trusted.** Proposer output is a candidate. It must
   pass the gate, and it is promoted to reuse only after acceptance.
   Replay never calls a proposer.
4. **Determinism.** No `HashMap` iteration, no clock, no randomness in
   `rcevc-core`. BTreeMap/BTreeSet or trie order only. Tests use a
   fixed-seed SplitMix64.
5. **Canonical encoding.** Everything hashed goes through `Enc` with a
   versioned domain tag (`rcevc/<thing>/vN`). Changing what a tag covers
   means bumping its version.
6. **Canonical trie shape.** A prefix holds nothing, a single leaf, or a
   branch over two or more keys (`mk_branch` collapses). Roots must not
   depend on history (`shape_and_root_are_independent_of_history`).
7. **diff is unit-level, not key-level.** Including re-keyed dependents in
   the diff would turn harmless shared dependents into false conflicts. The
   closure handles dependents instead.
8. **`#![forbid(unsafe_code)]`** in both crates; clippy at zero warnings.
9. **Non-vacuous tests.** Every randomised test asserts that it exercised
   enough cases. Keep doing that.

## 7. Measured results (release build, one core, same seed)

Swarm workload: 64 writers per round, all on the round's starting base, 20%
of writers crowding one hot module, 2% poisoned changes.

| Units | M0 (cloned maps) | M1 (persistent state) |
|---:|---:|---:|
| 400 | 2,103 µs/submission | 98 µs |
| 4,000 | 27,536 µs | 105 µs |
| 40,000 | not run | 136 µs |
| 100,000 | not run | 188 µs |

- At 400 units over 20 rounds (M0 run):
  - 57% accepted at G1, 27% at G2→G3, 14% at G2→G4→G3.
  - All refusals were the poisoned changes.
  - 98% of stale submissions were admitted with no writer rebase.
- Replay reproduces the identical head with no proposer.
- `est_uj` figures are a **stated cost table, not measurements**. Keep the
  labels `est_`, `reported_` and `measured_` distinct in anything you
  publish.

## 8. Known limits and debts (prioritised)

1. **No real parsing.** Files are whole units (leaves). The semantic claims
   in the paper (function-level units, interface changes) need tree-sitter
   splitting. This is the biggest gap between the paper and the code.
2. **Git storage:** loose objects and loose refs only. No packfiles, no
   packed-refs. Exports write file mode 100644 only (the executable bit is
   lost). Symlinks, submodules and non-UTF-8 files are refused, not guessed.
3. **Export is O(n) per commit** (`write_tree` rebuilds the whole tree).
   Fix: build trees incrementally from `diff` and cache directory tree oids.
4. **`users` sets are cloned on update.** A hub unit with 10k dependents
   makes each edit to its users O(10k). Fix: a persistent set, for example
   a nested HAMT.
5. **`key_rec` is recursive.** Very deep dependency chains (>~10k) could
   overflow the stack. Make it iterative.
6. **`content_root()` is O(n).** Only used by `ingest`'s NameOnly guess;
   the kernel uses the O(delta) `same_content`.
7. **Snapshots are kept forever in memory.** They need a store and a
   retention policy (`rcevc-store`).
8. **Single-threaded `submit`.** Changes that commute are admitted in
   sequence. The leases and real-time channel (M4) are not built.
9. **Checker scope is trusted, not enforced.**
10. **Cost model is stated, not measured** (M6).

## 9. Next tasks, with acceptance criteria

Do them roughly in this order. Each should land with tests and a README
update.

**A. Get network, then swap the hand-written parts (half a day).**
- The cloud environment needs Network access set to Trusted: caret next to
  the session title → Edit cloud environment.
- `hash.rs`: BLAKE3 for internal keys. Bump every `rcevc/*/v1` tag that
  covers a digest. Keep the SHA-256 FIPS vectors as a separate test.
- `codec.rs` and `store.rs`: use `gix` (gitoxide) for objects, packfiles
  and refs.
  - Note: gix has merge but its push support was closed as not planned in
    July 2026, so keep using the git CLI or a remote helper for push.
  - Acceptance: the existing interop tests pass unchanged, plus a test that
    reads a `git gc`-packed repository.

**B. `rcevc-keys`: real units from real source (M1 remainder, 2–4 days).**
- Use tree-sitter (Rust, TypeScript and Python grammars first) to split a
  file into top-level items. Each item becomes a unit; references to other
  items become `deps` with positional `$i`; the file becomes a unit listing
  its items in order.
- Must stay a bijection: projecting back gives byte-identical files,
  formatting and comments included. Test on a corpus.
- Acceptance:
  - Round-trip on at least 50 real crates and packages.
  - Two agents editing different functions in one file commute at G1.
  - Renaming a function is `NameOnly` and changes no keys.
- Mergiraf (structured merge on tree-sitter) is the closest prior art for
  the parse layer.

**C. The 1,000-repository round trip (the paper's SOTA criterion).**
- Import the full history of public repositories through `ingest`, export
  back, and compare trees byte for byte.
- Report the share that round-trips, plus a categorised failure list
  (modes, symlinks, encodings).

**D. Replay corpora through the ladder (protocol P1).**
- Corpora: Merge-Bench (the Gemini 2.5 Pro baseline is 52.6%), CONGRA, and
  AgenticFlict (agentic PR conflicts).
- Measure the share resolved at G0, G1, G2 or G3 *without* a model, the
  share needing G4, and the gate-caught semantic conflicts.
- This is the headline experiment: it tests hypothesis VC-H1, that most
  agent-era conflicts never need a model.

**E. `rcevc-gate` on Wasmtime.**
- Checkers become fuel-limited Wasm modules with pinned digests, no clock
  and no I/O.
- Scope is enforced by exposing only the declared slice of the state.

**F. Leases and live channel (M4).**
- CALM-monotone changes (`Change::is_monotone`) stream without
  coordination; leases reserve closures for long edits.
- This is the SpacetimeDB and real-time-channel idea the owner raised.

**G. Incremental export and persistent `users` sets** (debts 3 and 4).

**H. Paper.** Update the RCE-VC doc with the M1/M2 results and the scope
argument (§5.4). Keep claims matched to evidence.

## 10. Legal and claims discipline

- **Patent.** US 11,294,665 B1 (Foster et al.) is believed active, with
  anticipated expiry 2035-04-22. Its independent claims 1, 12 and 15 each
  require a software database, *plus* a separately versioned human
  (natural-language) database, *plus* a token-level history query.
  RCE-VC's current design (one repository state; messages as unversioned
  intent; unit-level, not token-level, history) was kept away from that
  combination.
  - Do not add a separately versioned natural-language store with
    token-level history queries without counsel review.
  - US 9,535,664 and US 10,698,682 are expired (fee related).
    US 10,042,637's status is unverified.
  - None of this is legal advice; the owner was told to get counsel review,
    including for the RCE and RCE-VC names.
- **Claims.**
  - Every number in the README was measured in this environment and says
    so.
  - Do not state SOTA results until protocol P1 has run.
  - "Gemini 2.5 Pro 52.6% on Merge-Bench" is a published baseline, not our
    result.

## 11. Conventions

- Rust edition 2024 with let-chains. Doc comments on every public item
  (`#![warn(missing_docs)]`).
- Errors are values: `Reason`, `ApplyError`, `WfError`, `ProjError`. No
  panics on input.
- Tests: deterministic seeds, non-vacuity assertions, names of the form
  `vcN_<claim>` for propositions.
- Writing style for docs: plain, specific, no hype. State limits next to
  results.
- Git commits made from Claude sessions carry the session's attribution
  trailers. Use your own convention.
