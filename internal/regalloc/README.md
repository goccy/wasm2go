# regalloc — cross-block linear-scan register allocator

This package implements a greedy linear-scan register allocator with
Belady eviction, modeled on Go's `cmd/compile/internal/ssa/regalloc.go`.
It is the successor to `asmgen.computeRegHomes` (the block-local
allocator) and is the foundation for closing the spill/reload gap to
Pure-Go: a representative hot function on a real wasm bundle currently
emits 4263 spill/reload pairs (60% of its asm), versus an estimated
800-1500 with a true cross-block allocator.

## Status — landed in this branch

| Module | What it does |
|--------|--------------|
| `types.go`, `arch.go`, `amd64arch.go`, `arm64arch.go` | Core types (regMask, register, regClass, regInfo) and per-arch register pools. amd64: 11 allocatable GP + 14 SSE. arm64: 26 allocatable GP + 32 SSE (the 65-register file is laid out with allocatable indices in the mask-safe 0..57 range and reserved indices in the unmaskable 58..64 tail). |
| `critedge.go` | Critical-edge splitting. Inserts a synthetic empty BlockPlain on every edge whose source has >1 successors and whose destination has >1 predecessors. Idempotent and shape-preserving for phis. |
| `liveness.go` | Backward-iterative liveness with branch-distance weighting and a `+UnlikelyDistance` penalty on values live across a CALL. Also computes `NextCall[b.ID][i]` so the forward walk can drop a value from registers when its next use is past a CALL barrier. |
| `desired.go` | computeDesired affinity hints. Per-block snapshot of "what register would value V like" derived from single-bit input masks on downstream consumers and IsResultInArg0 propagation. Plus an `Avoid` mask of registers other defs are saving. |
| `state.go` | The per-function mutable state struct + `allocReg` with Belady eviction (farthest-next-use) and the "copy victim to free reg" rescue. |
| `walk.go` | The main `Allocate(f, info)` entry point. Per-block forward walk with input allocation (3-pass: pin, pin-free, free-pick), output allocation (hint-biased, avoid-aware), CALL clobber sweep, and single-pred / first-merge-pred adoption of EndRegs as start state. |
| `shuffle.go` | Per-edge shuffle solver. Computes the move list (reg→reg, slot→reg, reg→slot) needed to transform a predecessor's end-state into a successor's expected start-state. Handles cycles by picking a temp register or, if none is free, going through a slot. |
| `stackalloc.go` | Interference-graph-based slot sharing. Two values whose live ranges don't overlap share a slot, dramatically shrinking the frame compared to "one slot per SSA value". Per-type pools so 4-byte and 8-byte slots stay separate. |

## Status — pending follow-up work

| Refinement | What it does | Why it's needed |
|------------|--------------|-----------------|
| Primary-pred selection | Primary-pred selection by spillLive size (Go's heuristic) + phi 2-pass sibling-pred register reuse. | Better merge-block phi register choices reduce per-edge shuffle work. |
| placeSpills hoisting | placeSpills dominator-tree hoisting. | Currently spills go at def-site; hoisting out of loops cuts redundant spill stores. |
| Rematerialise wiring | The allocator marks OpConst rematerialisable but the emit-side doesn't yet reissue at use sites. | Lower spill cost for cheap-to-recompute values. |
| usedSinceBlockStart trim | Trim startRegs entries that were never read inside the block. | Eliminates dead per-edge reloads when an entry expectation turned out unused. |
| emit integration | Wire the new Result through to emit. | The biggest piece. The existing `emit_amd64.go` / `emitarm64.go` read `plan.regHome[v.ID]` (a string-keyed map populated by `computeRegHomes`) and assume "v lives in regHome[v] for its entire lifetime." The new allocator's Belady eviction can result in "v in R10 for the first half of the block, in slot for the second half" — a temporal aspect the existing emit doesn't model. Integration requires a per-use-site accessor `regNameAt(v, position)` and an audit of the CALL clobber path (spills must be emitted when the new allocator's liveness says a value crosses a CALL). |

## How to test

Unit tests (50+):
```
go test ./internal/regalloc/
```

asmgen integration (bridge is currently instrumentation-only — runs the
new allocator as a side-effect for crash testing but does not modify
`plan.regHome` or `plan.offsets`):
```
go test ./internal/asmgen/                          # default path
WASM2GO_NEWREGALLOC=1 go test ./internal/asmgen/    # bridge active
```

End-to-end downstream test (regenerate any real wasm bundle the
project uses for integration testing, run the consumer's test
packages with `WASM2GO_NEWREGALLOC=1` to flip the bridge on):

```
WASM2GO_NEWREGALLOC=1 go test -timeout 300s -count=1 ./...
```

Both modes currently pass — the bridge does not yet override
placement, so output is identical to the default path.

## Pure-Go regalloc reference

The full deep-dive reading of Go's cmd/compile/internal/ssa/regalloc.go
that informed this design is preserved in commits 84-86 of the
parent feature branch. Key file:line citations are scattered through
the package's docstrings; the most load-bearing are:

- `regalloc.go:5-25` — high-level algorithm overview (greedy linear-scan + Belady).
- `regalloc.go:247-342` — `regAllocState` struct.
- `regalloc.go:436-521` — `allocReg` choice function with Belady eviction.
- `regalloc.go:1580-1656` — 3-pass input allocation.
- `regalloc.go:2058-2076` — end-state recording.
- `regalloc.go:2321-2519` — `shuffle` / `edgeState.process` per-edge fixup.
- `stackalloc.go` — interference-based slot sharing.
