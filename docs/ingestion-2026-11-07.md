# RCE-VC ingestion note, 2026-11-07

This note records one slice implemented in `rce-vc` and a map of where the
rest of the attached research applies. It is not a production claim, not a
merge, and not a change to any other repository. The attached research
handoff was used as evidence. It was not treated as extra authorization.

Parent of this work: `8bf9c9af60c913891b05c318f1edfb4dceec8927` on `main`.
Only `main` existed on `openIE-dev/rce-vc`. No open pull request and no
tree-sitter branch were present. `rcevc-keys` is still absent.

## What was implemented

`Repo::submit` is still the admission transition. `Receipt` and `Refusal`
are unchanged. There is no second receipt schema, and nothing here is
`rce-prod-claim/1` or `rce-prod-evidence/1`.

`crates/rcevc-core/src/assure.rs` adds a boundary the ladder did not have:

- A [`ContentStore`](../crates/rcevc-core/src/assure.rs) addresses bytes by
  SHA-256. `get` returns them only when the bytes hash to the requested
  digest. Putting bytes does not record an action.
- [`bind_repo_outcome`](../crates/rcevc-core/src/assure.rs) mints a
  `CheckedAction` only when that repository's log already contains the
  outcome, the dependency manifest is complete, and the output blob is the
  canonical outcome image. Stated `est_uj` and the gear path are not part of
  the image, so a G0 retry of the same decision hashes the same image.
- [`ActionCache`](../crates/rcevc-core/src/assure.rs) returns a hit only for
  a trusted row at the requested head and gate, with bytes that still hash.
  A different head is `StaleHead`. A different gate at that head is
  `GateMismatch`. A planted row is `UntrustedInsert` even when the blob
  reads. A forged, truncated, missing, corrupt, incomplete, or unlogged
  image fails closed.
- Individual accepts do not discharge a combined sequence.
  `insert_combined` requires the members to appear in one log as a
  head-linked chain, and the last logged outcome to be the one just bound.
  Two green edits of the same slot, each accepted on its own repository,
  do not become a combined accept. On one repository the second is a
  conflict refusal, and that refusal is not an accept. Asking for the
  combined row at a later head is `StaleHead`.
- [`CasRef`](../crates/rcevc-core/src/assure.rs) moves a ref only when the
  expected epoch and target match. A repeated op id does not apply twice.
  `still_tip == false` means a later op has moved the ref; it is not
  authority to treat the old target as current. The same target written by
  a different op id is `UnrelatedWriter`.
- [`PhysicalEnergy::unknown`](../crates/rcevc-core/src/assure.rs) is the only
  electricity result this crate can construct.
  `not_from_semantic_fuel` discards `est_uj`, including zero.

`GitDir::compare_and_swap_ref` is the same rule on a loose ref. The op id is
an RCE-VC digest, not a Git object id. The op log under `.git/rcevc-cas/` is
executor-local state, not a Git object and not an admission receipt. A held
`{ref}.lock` returns `Busy` instead of waiting. Copying a loose object into
another workspace does not copy the ref or the op log. `set_ref` is
unchanged and is still what export uses.

`conflict_signature` is unchanged. It covers the three unit keys and not the
gate. That remains an index inside one `Repo`, whose gate cannot be swapped.
It is not safe to export as a shared action cache. The test
`a_different_gate_does_not_hit_and_conflict_signatures_ignore_the_gate`
locks that difference.

`measure_isolated` times one fixed workload and runs the adversaries in the
same call. The printed nanoseconds are that call's `Instant` samples. The
harness has no joule field.

### Threat model

Trusted, in this process only: the gate installed on the `Repo` that logged
the outcome, and `bind_repo_outcome` / `insert` / `insert_combined`, which
accept only a `CheckedAction`. There is no signature, no remote
authenticator, and no SLSA level.

Untrusted: the writer label, any bytes in the content store, rows inserted
by `plant_untrusted` or `plant_combined_untrusted`, and a claim that
separately checked changes compose.

A content digest is not an action result. A compare-and-swap is not
admission. A refusal hit is not an accept.

### Tests

`cargo test --offline` on rustc 1.85.0: 35 tests, 0 failed.

| Crate | Tests |
|---|---|
| `rcevc-core` lib | 4 |
| `rcevc-core` `tests/assure.rs` | 8 |
| `rcevc-core` `tests/propositions.rs` | 14 |
| `rcevc-proj-git` lib | 3 |
| `rcevc-proj-git` `tests/git_interop.rs` | 3 |
| `rcevc-proj-git` `tests/ref_cas.rs` | 2 |
| `rcevc-proj-git` `tests/isolate.rs` | 1 |

`cargo clippy --offline --all-targets -- -D warnings` exited 0 on the same
compiler. Digest and Git object-id hex encoding append with `write!` so this
compiler's `format_collect` lint stays quiet. The deflate inflater is
unchanged; its existing symbol comparisons and the test helper that prints
SHA-1 vectors keep a local `allow` for lints that this compiler raises on
the original form. SHA-256, inflate, SHA-1, and the git interop tests passed.

## Commands and one machine's samples

Toolchain: rustc 1.85.0 (`4d91de4e4`, 2025-02-17). This machine's default
`rustc` is 1.83.0, which cannot build edition 2024, so the commands used
`cargo +1.85.0`. Git 2.43.0. Host: Linux 6.12.113+ x86_64, `nproc` = 4,
`/proc/cpuinfo` model name `Intel(R) Xeon(R) Processor` (no stepping
recorded). No crates.io dependency was added. No network during the test
run (`--offline`).

```
cargo +1.85.0 test --offline --all-targets
cargo +1.85.0 clippy --offline --all-targets -- -D warnings
cargo +1.85.0 run --offline --release -p rcevc-proj-git --example isolate_bench -- /tmp/rcevc-isolate-release
cargo +1.85.0 run --offline -p rcevc-proj-git --example isolate_bench -- /tmp/rcevc-isolate-debug
```

Workload, both runs: 32 loose Git blobs of 56 bytes and one ref
compare-and-swap, then the same writes and the same op id. Cache: in-process
`ContentStore` and `ActionCache`, loose objects in that scratch directory,
no remote cache. Dependencies: std only. Target: that process and that
scratch directory. Physical energy: unknown. Adversaries held on both runs
(`poison_rejected`, `corrupt_blob_rejected`, `isolation_held`,
`stale_cas_rejected`, `replay_still_tip` all true).

Single samples, not a rate and not a comparison with any other machine:

| Build | `debug_assertions` | cold wall | warm wall |
|---|---|---:|---:|
| debug | true | 2,154,234 ns | 476,446 ns |
| release | false | 1,591,593 ns | 91,401 ns |

Those two pairs are the runs above. They are not a speed-up claim for
RCE-VC admission, and they are not joules. `est_uj` from a one-change
repository in the same process was discarded by
`PhysicalEnergy::not_from_semantic_fuel`.

## Left prepared-only

Extending RCE acceptance stays on `openIE-dev/rce` pull request 154. That
pull request, at `fdc4640582408392d24494cb70a8b216bce1514d`, already defines
`rce-prod-claim/1`, `rce-prod-evidence/1`, `rce-prod-obligations/1`, and
`rce-prod-manifest/1` (`scripts/acceptance/README.md` and `accept.py` read
via the GitHub API). Those files are not on `rce` `main`
(`50294e05c84ec80fcb40578d90f523ead6a04443`; `scripts/acceptance` returns
404). This repository does not copy that schema.

The same pull request's body, in the attached metadata snapshot, reports
the main baseline as exact syntax 5/60, semantic 0, whole modules 0/60, and
nine off-floor byte mismatches: `03_fib_loop`, `10_comptime`, `22_tuples`,
`25_labels`, `36_multiline_brackets`, `43_simd_lanes`, `45_byte_text`,
`46_u64`, `49_loop_limit`. This run did not rerun that driver, so those
counts stay the pull request's report.

Nested break accounting was not edited. The carried exit count, as clarified
for the RCE checker, is the remaining blocks and loops to exit, decremented
once per exited block or loop and not for `if`. Normative RCE documents were
not changed. That clarification belongs with pull request 155's witness
tests, after the semantics are checked against the checker, not in this
repository.

No storage rewrite, no packfile reader, and no replacement of Git. Pando and
Scion were read as evidence against that rewrite, below.

## Gap inventory

"Inspected" means a git object, a GitHub contents listing, or a page fetched
in this run. "Handoff report" means the attached ledger or pull-request
body, not a rerun. "Hypothesis" means a destination inferred from the
research, not a behavior this run executed.

| Component | Ref inspected | Research finding | What is actually there | Next test, if any | Depends on |
|---|---|---|---|---|---|
| `rce-vc` `main` before this slice | `8bf9c9af60c913891b05c318f1edfb4dceec8927` | Revision-bound evidence, stale combined revisions, blob integrity vs action trust, ref CAS, isolated workspaces | Ladder, receipts, G0 refusal memo, conflict reuse inside one repo, loose Git objects, unconditional `set_ref`. No action cache, no ref CAS, no energy meter. No tree-sitter units. No other branch or PR | Done here for the in-process boundary. Not a Git-server benchmark | This crate only |
| `rce` `main` | `50294e05c84ec80fcb40578d90f523ead6a04443` | Baseline exact 5/60, semantic 0, modules 0/60 | Commit message is the form-bridge halt merge. Root listing includes `spec/`, `scripts/`, `compile/`. `scripts/acceptance` is absent | Do not recount coverage from this note | None for the map |
| `rce` PR 154 | `fdc4640582408392d24494cb70a8b216bce1514d`, open, base = main above | Revision-bound acceptance receipts | `scripts/acceptance/` with `accept.py`, `obligations.json`, `spec-examples.txt`, driver,  README. Schema names read from source. Not merged | After it lands, add stale-revision and forged-mapping adversaries to that validator. Do not invent a parallel format | PR 154's schema and a pinned checker commit |
| `rce` PR 153 | `52343a162e1b460f4bf5237999586b1dcf511fb5`, files `spec/checker/src/form/bridge.rs`, `spec/checker/tests/form_bridge.rs`, `spec/proposals/LEDGER.md` | Removes catch first refusals, not coverage | Diff not read and tests not rerun. Handoff report: catch-first tags 0, coverage unchanged | Keep the existing bridge tests. Do not treat a green count as module coverage | The checker at that commit |
| `rce` PR 151 | `011a75abf485f170fd29e0df992ae567c3958488`, five Lean files under `spec/lean/RCE/FormBridge/` | Local lemmas, not Rust linkage | File list only. No proof correspondence inferred | Any fidelity claim needs a correspondence bridge or an explicit model-only label | Lean and the Rust checker |
| `rce` PR 155 | `3b0dc859500438b340fb915bdd3dec7c43004262`, `spec/checker/tests/break_fg8_witness.rs`, `spec/proposals/break-fg8-impl-contract.md` | Contract and refusal witnesses. Exit count is remaining blocks/loops | Files not reread. Normative text not edited here | Witness tests for decrement-per-block/loop, never `if`, before any normative edit | Checker semantics |
| `rce` PR 152 | `8f7325e30797f6f026a1534b4c8570deba516ada`, `.github/workflows/ui-web.yml`, `xarch-parity.yml` | Not in the research handoff | Title: pin DOM and s390x jobs to ubuntu-24.04. Logs not read. Not called green or blamed | Separate log diagnosis only if authorized | CI retention |
| `rce-stdlib` | `44deddde5dae6f25ef17bfa3e076d7ab5f6ec065` | Crypto review needs security contracts, not only functional parity | Root has `lib/`, `tests/`, `vectors/`. Not read further | Hypothesis: contract tests beside vectors. Not started | A security-contract format that does not fork PR 154 |
| `rce-conformance` | `054642813f8a519b5e323e9810e0476662e1de2e` | Cross-implementation fixtures | Root has `clauses.json`, `harness/`, `tests/`. Not read further | Hypothesis: shared negative fixtures for stale evidence, only after the RCE schema is stable | PR 154 |
| `rce-examples` | `3f5c45381bfa4497e931fddc379a0e8ac56c556a` | Publish revision/backend support, not inferred readiness | Root area directories. Not read further | Hypothesis: a support matrix pinned to a checker revision | Checker revision |
| `rce-book` | `a06a4c035dea54b5178e5348a1e47e766e75aff5` | Same support-matrix point | `src/`, `listings/`, `book.toml`. Not read further | Hypothesis only | Same |
| `rce-ide` | `ce63396c9282f949334df955ca8301ab245301f1` | Distinguish measured, simulated, and unknown energy | Repo description says signed receipts and simulated vs measured energy. Code not read. Not edited | Hypothesis: unknown must stay distinct from 0. This crate's `PhysicalEnergy` is the VC-side rule, not the IDE | A meter that does not exist here |
| `tree-sitter-rce` | `66492e590541219b72be08bd0be1b9d9db9c9570` | Grammar for the RCE language | `grammar.js` present. This is not `rcevc-keys` for Rust, TypeScript, or Python | HANDOFF task B remains unstarted in `rce-vc` | Network and grammars, when authorized |
| `research-openie-web` | `48765e0b5decb6fbe99298f8f57563b68dddb887` | Production site | Not edited | None from this slice | Out of scope |
| `mixture-of-limits` | `5289d8d5f0d887fdbd4f3e4dc4eb353d6af7ee76` | MoL peer | Description only. Not contacted | None | Parent said not to contact |
| `flow-g` | `8fcf478ceb134009eca1ed680d9296c9d7ddc944` | FlowG peer | Description: typed FunctionGraph IR, energy-metered. Not contacted, not read | Hypothesis: external graphs stay untrusted inputs. Not implemented | Parent said not to contact |
| `mgai` | `3bd4b2a061c2afddeb5a8be806897aff42192620` | Mathground peer | Description mentions a joule receipt CLI. Not contacted, not read | Do not treat that CLI as this crate's meter | Parent said not to contact |
| `joule-lang` | `662906682c4cb2283da055c4c359d24636e994d5` | Not an RCE fuel oracle | Description: energy-aware language. Not read | RCE semantic fuel stays fuel | None |
| notational-intel, AI-Leapfrog | Org repository search returned no name match | Named peers | Not found from this token's org listing. Not contacted | None until a repository is identified | Parent said not to contact |
| RCE-JEPA, RCE-ISC, RCE-Decision, World Coding, Cleanroom | No repository path confirmed | Priority 3 architectural hypotheses in the handoff | Conceptual. Not inspected | None in this slice | A real repository |

`openIE-dev` also has other repositories (`jouledb`, `pattern-lang`, humanoid
and hardware corpora, `openloco`, `shoal`, and others). They were listed and
not mapped, because the research handoff does not name them and this run did
not read them.

## Sources read in this run

Fetched and read as article or manual text. Interactive figures, videos, and
linked source trees were not executed.

| Source | What was read | What it supports here | Limit |
|---|---|---|---|
| OpenAI, "Scaling Git at OpenAI", 2026-11-02, https://openai.com/index/scaling-git-at-openai | Fetched article prose, including the architecture sections | Pando keeps the Git client and protocol. It stores immutable pack blobs, records a ref version, and updates the ref with a multi-key transaction. Per-ref serialization; a multi-ref read is not one snapshot. Compare-and-swap of a shared manifest was a design they modeled and did not ship as the production writer | Author-reported latency. The interactive simulation was not run. Not a reason to replace Git in RCE-VC |
| Anthropic, "Redesigning source control at Anthropic", 2026-10-13, https://www.anthropic.com/research/redesigning-source-control | Fetched article, including the closing section | Scion uses server-side changesets, content-addressed blobs, and tiered caches. The article says: "Scion is by no means a suitable replacement for git for general use." Ref move is a separate compare-and-swap | Author-reported scale. Post-merge testing is their choice, not an RCE acceptance rule |
| Git partial-clone manual, https://git-scm.com/docs/partial-clone | The fetched manual, including limitations | Partial clone omits objects and fills them from promisor remotes. It composes with shallow and single-branch fetches. Promisor availability is required for missing objects | This machine's git is 2.43.0. The manual's change list names 2.56.0. No partial clone was performed |
| Git sparse-checkout manual, https://git-scm.com/docs/git-sparse-checkout | The fetched manual through the internals sections | Sparse checkout chooses which tracked files are materialized. Cone mode and the sparse index are different switches. Merge can materialize paths. The sparse index is marked experimental and is not a network filter | No sparse checkout was performed |
| Bazel remote caching, https://bazel.build/remote/caching | The fetched English page | The remote cache stores an action cache (action hash to result metadata) separately from a content-addressable store of outputs. Writers should be limited. Known issues: concurrent input edits, untracked tools, environment variables | Configuration was not executed. The ledger's S18 is the pt-BR page; this run read the English page, not that translation |
| Stripe, "Fast builds, secure builds. Choose two", https://stripe.dev/blog/fast-secure-builds-choose-two | The fetched article | Only trusted isolated executors should populate the action cache. An output blob a tenant can write is not a trusted mapping. Date was not on the fetched page | Sandbox design is theirs. Not a mandated implementation |
| GitHub, "Managing a merge queue", https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue | The fetched page | A queued change is checked against the latest base and earlier queued changes. Reorder invalidates in-progress groups. Required checks are only as strong as the checks that were configured | No setting was changed |

Attached ledger, used as a scope list and not re-fetched in this run except
where the table above says otherwise: S01 and S04–S17, S19, S21–S23, S25–S41,
and the unread build-systems PDF (S39 body). S04 and S05 were re-read (the
partial-clone and sparse-checkout manuals). S02, S03, S18's English
counterpart, S20, and S24 were re-read. The ledger's own limits still apply
to anything not in the table: author-reported numbers, translations that are
not replications, and papers whose bodies were not read (S39 PDF downloaded
unread; S35 pp. 1–5; S40 abstract only). Query languages recorded in the
ledger: English, Chinese, Japanese, Korean, French, German, Spanish,
Portuguese, and Russian. German searches did not add a fully read German
primary source. This run did not repeat those searches.

Alive2 and iCoq PDFs are in the attached archive and were not re-read here.
The ledger marks them full. Nothing in this slice ports their algorithms.

## Applicability limits

- This is not a measured checkout, fetch, or pack benchmark. The harness
  workload is 32 small loose blobs and one ref update.
- `bind_repo_outcome` does not re-run checkers. It binds an outcome the log
  already contains. Replaying the log is still `Repo::replay`.
- `insert_combined` checks log order and head linkage. It does not prove the
  ops are a merge beyond what `submit` already decided for that sequence.
- The action cache is in-process. It is not a remote cache, and copying it
  between machines is not authenticated.
- `compare_and_swap_ref` does not fsync. A crash after the ref rename and
  before the op log fails closed on retry (`Unrelated` if the bytes match
  and the op id is absent). That is not a durability proof.
- Conflict reuse inside `Repo` is still keyed without the gate. Do not share
  that map across gates.
- No joule number was measured. Unknown is not zero. Semantic `est_uj` is
  not joules.
- No repository other than `rce-vc` was modified.

## Highest-value next integration

On `openIE-dev/rce`, after pull request 154, add executable adversaries to
the existing acceptance validator: a changed checker commit, a moved base,
and a correct blob with a forged action mapping must fail closed, using
`rce-prod-evidence/1` as it stands. Do not open a second claim format.

Inside `rce-vc`, the next code gap that is still empty is HANDOFF task B:
tree-sitter units for real source files, with a byte-identical projection.
That work was not started on any branch of this repository at the parent
commit above. It needs grammars and a corpus, and it should not be mixed
into the acceptance schema.
