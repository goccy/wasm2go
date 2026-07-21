# SSA mid-end optimization plan — closing the wasmtime gap

Status: in progress on branch `feat/ssa-memopt-licm-gvn`.

## FINDINGS after Phase A (2026-07-20) — read this first

Phase A (intra-block RLE + store-to-load forwarding) was implemented,
unit-tested, verified correct on go-python (non-shared) and — through the
PROPER wasmify pipeline — on go-spidermonkey (`go test` + `-race`, both
with MemOpt gated and forced on its shared memory). **Its runtime effect
is within noise (~0), and the evidence indicates Phases B/C would be
similar.** See the `Phase A (memopt)` snapshot in `bench-metrics.md` for
numbers. The load-count reduction on the CPython bundle was 47 / 179,794
= 0.02 %. MemOpt is gated off for shared-memory modules (defensive; see
below).

Why the headroom is near-zero, and what this implies:

1. **The input wasm is already `clang -O2`.** RLE / GVN / LICM ran at the
   C→wasm stage, so little classic redundancy survives to wasm2go's SSA.
2. **gc re-optimizes the emitted Go.** Any SSA-level optimization of
   *pure* values (CSE, const-fold, and the pure part of GVN/LICM) is
   redundant with what gc already does on the generated source — so it
   cannot move runtime, only source size.
3. **The only thing gc structurally cannot do is reason across wasm2go's
   *unsafe* memory accesses** (it reloads after every unsafe store/call).
   That is exactly what Phase A targets — but (1) caps the payoff, and
   the intra-block measurement confirms it is ~0.
4. **The wasm→Go lowering's two big introduced costs are already paid
   down:** the heap-base reload (Phase P1 `mBase` hoist) and per-access
   bounds checks (wasm2go emits none — parity with wasmtime's guard-page
   elision).

Conclusion: the residual asm-vs-wasmtime gap is in the **backend**
(register allocation via gc + the gcasm ABI0 marshalling), not the
mid-end. This matches `docs/pure-vs-asm-benchmarks.md`: the pure path —
same SSA/mid-end, different backend — beats the asm path several-fold on
go-python. Cranelift's mid-end (egraph GVN/LICM/alias-RLE) helps *it*
because its lowering re-introduces the redundancy (heap base, bounds
checks) that wasm2go has already eliminated by other means.

Consumer-verification correction (the earlier draft here mis-stated the
cause): the spidermonkey and googlesql failures I first hit were NOT
version skew — they were my using the direct `wasm2go` CLI instead of the
wasmify pipeline, which omits the generated host-import bridge. Through
the proper wasmify e2e, MemOpt (gated OR forced on shared) passes
go-spidermonkey including `-race`; the shared-memory gate is a DEFENSIVE
measure (preserves wasm2go's non-atomic-shared-load re-read guarantee),
not a fix for a demonstrated miscompile. See the `Phase A (memopt)` entry
in `bench-metrics.md`.

Consequences for Phases B/C:
- **Phase C (cross-block RLE / dom-scoped GVN):** low expected ROI by the
  same clang-preopt argument, and it is the correctness-sensitive class
  the project rules require googlesqlite to validate. It should be built
  and A/B-verified through the wasmify e2e (both googlesqlite and
  go-spidermonkey), not a direct-CLI bundle.
- **Phase B (pure-value LICM):** gc has no LICM, so it is the one classic
  transform with *some* unique headroom — but clang already hoisted the C
  loop invariants before emitting wasm, so what remains are lowering
  artifacts only. Memory-safer than C (moves pure values only).

Recommended next direction (backend, where the gap actually is):
(a) measure current pure-vs-asm on the target machine and, if pure still
wins, treat "ship/serve pure" as the primary lever; (b) attack the gcasm
ABI0 marshalling cost directly (the 17k custom-ABI attempt is documented
as reverted — a *profiled*, narrower version); (c) shape the emitted Go
to reduce live-value pressure so gc's allocator keeps hot values in
registers. Phase A is kept as a correct, neutral foundation; B/C are
paused pending (i) a decision given the ~0 ROI evidence and (ii)
googlesqlite being buildable again.

Author context: the ~25% residual gap vs. wasmtime (after accounting for
the gcasm ABI0 marshalling overhead) is investigated below and attributed
to missing **mid-end** optimizations, not register allocation.

## 1. Why the gap is NOT register allocation

The current `main` asm backend is **gcasm**: wasm2go emits Go source, runs
the host Go toolchain with `-gcflags=-S`, captures the assembly, and
rewrites it to ABI0. **Register allocation, instruction selection,
addressing-mode folding, and compare+branch fusion are all done by the Go
compiler (`gc`)** — not by wasm2go. There is no in-house allocator left to
tune (the Phase 10b/12/16/H own-emitter allocator was deleted in PR #19).

So a regalloc2-style rewrite has no home in this architecture. What wasm2go
*does* own is a small SSA mid-end (`internal/codegen/translate.go`
`compileBodyViaSSA`) running, to fixpoint:

    ConstProp → BranchFold → Simplify → CSE (intra-block) → DCE

Confirmed **absent**: GVN (CSE is intra-block only, see `cse.go:14-15`),
LICM (no loop-invariant motion anywhere), and — most importantly — **any
memory optimization**: loads are explicitly excluded from CSE
(`cse.go:93-106`) and there is no load-forwarding / redundant-load pass.
The SSA memory token (`OpLoad` args `[base, mem]`, `OpStore` args
`[base, value, mem]` producing a new mem) exists but no pass exploits it.

## 2. Why gc cannot recover these itself

Every wasm load/store is emitted as `*(*T)(unsafe.Add(mBase, off))`
(`emit_memops.go`). Because these are **unsafe** pointer accesses, gc's
alias analysis must assume any unsafe store may alias any unsafe load, so
gc **invalidates every cached load after every store and every call** and
cannot do store-to-load forwarding or redundant-load elimination across
them. Evidence: Phase P1 (hoisting `m.M` into an `mBase` local — a single
one of these unsafe-aliasing hazards) produced −30% to −70% on
generated-code-dominated CPython workloads. The whole class of "gc can't
see through unsafe memory" is where the wasmtime gap lives.

wasmtime/Cranelift recovers exactly this with, at default `opt_level=speed`:

- **Alias analysis + redundant-load elimination + store-to-load forwarding**
  (`cranelift/codegen/src/alias_analysis.rs`), keyed on
  `(last_store, address, offset, type)`.
- **LICM** via egraph elaboration into loop preheaders
  (`cranelift/codegen/src/egraph/elaborate.rs`), which hoists invariant
  loads (incl. the heap base) and address arithmetic out of hot loops.
- **Dominator-scoped GVN** by hash-consing pure enodes
  (`egraph/mod.rs:204-283`).

wasmtime's single biggest structural win — guard-page **bounds-check
elimination** — is a non-issue for us: wasm2go already emits **no** bounds
checks (`emit_memops.go:35-44`), so we are at parity or better there.
regalloc2, addressing-mode fusion, and block layout are all gc's job and
out of scope.

Therefore the porting targets, in impact order, are the three Cranelift
mid-end passes above — reimplemented on wasm2go's SSA.

## 3. Implementation phases

### Phase A — memory optimization pass (`internal/ssa/pass/memopt.go`)

Two sound transforms that need no alias analysis, exploiting the mem token:

**A1. Store-to-load forwarding.** A load `L` whose mem arg is a store `S`
(`L.Args[memIdx]` is the store's result) where:
- `S`'s base value == `L`'s base value (same SSA value ID),
- offsets equal (`S.AuxInt == L.AuxInt`),
- **full-width exact match**: `OpStore32→OpLoad32` (i32),
  `OpStore64→OpLoad64` (i64), `OpStoreF32→OpLoadF32`, `OpStoreF64→OpLoadF64`.
  (Sub-width stores like `OpStore8` are excluded — the load's
  zero/sign-extension of the stored i32 differs from the stored value.)
→ replace `L` with `S`'s stored value (`S.Args[1]`). Sound with no
scoping: `S` dominates `L` because `L` uses `S`'s mem result.

**A2. Same-mem-state redundant load elimination.** Two loads with identical
`(op, baseID, offset, memID)` observe an identical memory state (same mem
token ⇒ no store between them) ⇒ merge the later into the earlier. This
needs the earlier def to **dominate** the later, so it runs as a
dominator-tree DFS with a scoped hashmap (push entries on entry to a block,
pop on exit) — the same shape as Cranelift's `insert_pure_enode` scoped
map. Dominators come from `internal/ssa/domtree.go` (`Dominators`).

Both transforms are things gc structurally cannot do. Wire the pass into
the `compileBodyViaSSA` fixpoint after CSE, before DCE. Gate behind
`WASM2GO_SSA_PASSES_OFF=memopt` for bisection.

Correctness guards:
- Never forward/merge across an `OpAtomicCall`, `OpCallDirect/Indirect/
  Import`, `OpMemoryCopy/Fill/Init`, or `OpMemGrow` — these all thread a
  fresh mem token, so keying on memID already prevents it, but assert it.
- Preserve trapping/side-effecting values untouched.

### Phase A-ext (only if A's wins are store-broken) — alias-class RLE

If profiling shows the remaining redundant loads are separated by stores to
**provably-disjoint** addresses, extend A2 into an available-loads map that
survives a store when `ClassifyMemory` (`memclass.go`) proves disjointness
(e.g. an `AliasRodata` load is never invalidated by an `AliasSlab`/
`AliasFrame` store; two `AliasFrame` accesses at distinct constant offsets
don't alias). Conservative default: any store not proven disjoint
invalidates everything. Deferred until A is measured — a wrong
disambiguation is a miscompile.

### Phase B — LICM (`internal/ssa/pass/licm.go`)

Using `BackEdges`/`LoopHeaders` (already in `domtree.go`):
1. For each natural loop, materialize a **preheader** block on the entry
   edge(s) (split the pre-header edge if the header has multiple non-back
   preds).
2. Compute the loop's block set (nodes that reach the back-edge source
   without leaving via the header).
3. Hoist a **pure** value (`!v.HasSideEffect()`, not a phi/param) into the
   preheader when **all** its args are defined outside the loop (or already
   hoisted). Iterate to fixpoint so chains hoist.
4. **Invariant loads**: only hoist a load out of a loop when Phase A/A-ext
   proves no store inside the loop can alias it (e.g. rodata loads, or a
   frame/slab load with no aliasing store in the loop body). Start with the
   safe subset (rodata + no-store-in-loop) and widen only with alias info.
   Do not speculatively hoist a load that executes only on some loop paths
   unless it is provably safe to execute unconditionally (wasm2go already
   assumes validated input / no OOB traps, so an unconditional in-bounds
   load is safe; a load whose address is only computed on one branch is
   not — guard on args-defined-in-preheader).

### Phase C — dominator-scoped GVN (`cse.go` extension)

Replace the intra-block `seen` map with a dominator-tree DFS carrying a
scoped value-numbering map, so two pure values with the same key merge when
the earlier dominates the later — closing the `cse.go:14-15` TODO. Composed
with Phase A's mem-keyed load numbering, this makes redundant-load
elimination work across dominating blocks too. Keep the intra-block fast
path; only add the scoping walk.

Order rationale: **A → C → B**. A is the highest-value, lowest-risk change
and gc-uncoverable; C generalizes A's numbering across blocks cheaply
(reusing domtree); B is the most invasive (CFG edits) and depends on A's
alias facts to hoist loads safely.

## 4. Verification method (MANDATORY, per CLAUDE.md test-honesty rules)

Every phase runs three gates. **If any consumer test fails, STOP — do not
push, do not proceed.** Record exact commands + observed exit codes in
`bench-metrics.md`.

### Gate 1 — wasm2go unit tests

    cd /Users/goccy/Development/goccy/wasm2go && go test ./...

Includes the new `memopt_test.go` / `licm_test.go` and the existing
`internal/ssa`, `internal/codegen` suites. Must exit 0.

### Gate 2 — consumer correctness (three engines), via local generation + replace

Build the local CLI once per change:

    cd /Users/goccy/Development/goccy/wasm2go && go build -o /tmp/wasm2go-dev ./cmd/wasm2go

Regenerate each consumer bundle into a temp dir with the SAME params the
release used, then point the consumer at it with `go mod edit -replace`.

**(a) go-spidermonkey** (new this round; release wasm =
`spidermonkey-wasm/build/spidermonkey.wasm`, v0.2.2):

    /tmp/wasm2go-dev -i /Users/goccy/Development/goccy/spidermonkey-wasm/build/spidermonkey.wasm \
      -out-dir /tmp/smwasm2go -pkg spidermonkeywasm2go \
      -import github.com/goccy/spidermonkeywasm2go -bulk-export-prefix w_
    # copy base/ hand-written support files the release ships but the CLI
    # does not regenerate (base/, alias.go, data.bin) from the released
    # spidermonkeywasm2go into /tmp/smwasm2go, then:
    cd /Users/goccy/Development/goccy/go-spidermonkey \
      && go mod edit -replace github.com/goccy/spidermonkeywasm2go=/tmp/smwasm2go \
      && go test ./... && go mod edit -dropreplace github.com/goccy/spidermonkeywasm2go

**(b) googlesql** (per reference_e2e_path / CLAUDE.md — the canonical e2e):

    /tmp/wasm2go-dev -i /Users/goccy/Development/goccy/go-googlesql/googlesql.wasm \
      -out-dir /tmp/gsqlwasm2go -pkg googlesqlwasm2go \
      -import github.com/goccy/googlesqlwasm2go -bulk-export-prefix w_
    cd /Users/goccy/Development/goccy/googlesqlite \
      && go mod edit -replace github.com/goccy/googlesqlwasm2go=/tmp/gsqlwasm2go \
      && go test ./... && go mod edit -dropreplace github.com/goccy/googlesqlwasm2go

(For a release-gate change, run the strict 5-step wasmify chain from
project CLAUDE.md instead; for iteration the replace path above is
sufficient to catch miscompiles.)

**(c) go-python** (CPython — most sensitive to the mid-end, per Phase P1):

    /tmp/wasm2go-dev -i /Users/goccy/Development/goccy/python-wasm/<release>.wasm \
      -out-dir /tmp/pywasm2go -pkg pythonwasm2go \
      -import github.com/goccy/pythonwasm2go -bulk-export-prefix w_
    cd /Users/goccy/Development/goccy/go-python \
      && go mod edit -replace github.com/goccy/pythonwasm2go=/tmp/pywasm2go \
      && go test ./... && go mod edit -dropreplace github.com/goccy/pythonwasm2go

Run `-race` on at least one engine per phase. Restore every `go.mod`
(`-dropreplace`) after each run so no consumer is left pointing at /tmp.

### Gate 3 — bench (only after Gates 1–2 are green)

Per the bench-metrics.md protocol: `-benchtime=200x -count=5` minimum,
report mean AND range, treat sub-2% deltas as noise. Bench targets:

- go-spidermonkey: `cd go-spidermonkey/bench && go test -bench=GoSpiderMonkey -benchmem -count=5 .`
  (FibRecursive, LoopSum, Startup)
- googlesqlite: the window suite (array_agg_window, lag_lead,
  rank_dense_rank, row_number_partition, sum_running_total) — the historical
  gap concentrator.
- go-python: fib(28), loop-sum, startup (pure + asm).

Compare against a baseline bundle generated from the pre-change HEAD with
identical params. Append a dated snapshot to `bench-metrics.md` keyed by the
producing commit SHA; never overwrite prior entries.

### Honesty rule

No phase is "done" until Gate 1 + Gate 2 are observed exit 0 in the same
session. Bench wins below the 2% noise floor are reported as "within noise",
not as wins. A SIGSEGV/panic/wrong-answer in any consumer is a bug to fix
before proceeding — not a follow-up.
