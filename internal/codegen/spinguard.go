package codegen

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// Bare atomic spin loops
//
// A loop that waits on an inline atomic load and makes no call — the
// shape ggml's barrier emits, `while (atomic_load(p) == x) {}` — is
// legal Go after emission and preemptible as such, but the gcasm
// bundler captures the compiled function into a .s TEXT, and the Go
// runtime refuses to async-preempt assembly functions. A goroutine
// spinning inside the captured loop then blocks every stop-the-world:
// if the store it waits for comes from a goroutine the GC already
// parked, the process livelocks with all cores burning. Observed in
// production against llama.cpp's ggml_barrier (intermittent multi-
// minute stalls, GC-timing dependent).
//
// spinGuardHeaders finds the headers of such loops so the emitters can
// prepend one spinRelax(&__spinGuard) call per iteration (see the
// helper's comment for the policy and its measured cost — parity with
// the unguarded loop). The call is the fix: a loop whose body calls a
// //go:noinline function periodically executes ordinary Go code, which
// the runtime can preempt, no matter how the surrounding function is
// lowered.
//
// A loop qualifies when its body
//   - performs an inline atomic load (the atomicInlineSpecs load
//     entries — sync/atomic intrinsics, a bare LDAR/MOV in machine
//     code), and
//   - contains no call that survives to machine code: direct, indirect,
//     and import calls, and the helper-form atomic ops (their //go:noinline
//     helper chain) all count as calls. OpHelperCall does NOT count —
//     small pure helpers routinely inline away, and a guard next to a
//     call that then disappears would leave the loop bare again.
//
// Over-approximation is deliberately cheap: a guarded loop that never
// spins long pays one counter increment and a predictable branch per
// iteration.
//
// The returned value per header is the guard MASK: the cold call runs
// when __spinGuard&mask == 0. The interval is derived from the loop
// body's size so the stop-the-world arrival bound is a TIME budget,
// not an iteration count that would stretch with the body: a minimal
// barrier spin (a handful of values) checks every 16384th iteration,
// while an interpreter-style loop carrying hundreds of values per
// iteration checks every few hundred — either way the budget lands in
// the tens-to-low-hundreds of microseconds of spinning.
func spinGuardHeaders(f *ssa.Func) map[ssa.BlockID]int {
	if f == nil || f.Entry == nil {
		return nil
	}
	idom := ssa.Dominators(f)
	dominates := func(a, b *ssa.Block) bool {
		for cur := b; cur != nil; cur = idom[cur.ID] {
			if cur == a {
				return true
			}
			if cur == f.Entry {
				break
			}
		}
		return a == f.Entry
	}

	// Natural loop bodies, merged per header: every back-edge b→h
	// (h dominating b) contributes the blocks that reach b without
	// passing through h.
	bodies := map[*ssa.Block]map[*ssa.Block]bool{}
	for _, b := range f.Blocks {
		for _, e := range b.Succs {
			h := e.Block
			if !dominates(h, b) {
				continue
			}
			body := bodies[h]
			if body == nil {
				body = map[*ssa.Block]bool{h: true}
				bodies[h] = body
			}
			stack := []*ssa.Block{b}
			for len(stack) > 0 {
				n := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if body[n] {
					continue
				}
				body[n] = true
				for _, pe := range n.Preds {
					stack = append(stack, pe.Block)
				}
			}
		}
	}
	if len(bodies) == 0 {
		return nil
	}

	var headers map[ssa.BlockID]int
	for h, body := range bodies {
		sawAtomicLoad := false
		sawCall := false
		bodyValues := 0
	scan:
		for blk := range body {
			bodyValues += len(blk.Values)
			for _, v := range blk.Values {
				switch v.Op {
				case ssa.OpCallDirect, ssa.OpCallIndirect, ssa.OpCallImport:
					sawCall = true
					break scan
				case ssa.OpAtomicCall:
					name, _ := v.Aux.(string)
					if spec, ok := atomicInlineSpecs[name]; ok {
						if !spec.isStore {
							sawAtomicLoad = true
						}
					} else {
						// Helper-form atomic (RMW, wait/notify,
						// sub-word): a real //go:noinline call.
						sawCall = true
						break scan
					}
				}
			}
		}
		if sawAtomicLoad && !sawCall {
			if headers == nil {
				headers = map[ssa.BlockID]int{}
			}
			headers[h.ID] = spinGuardMask(bodyValues)
		}
	}
	return headers
}

// Spin-guard interval policy. The single tunable is a stop-the-world
// latency budget expressed in value-iterations: interval × body size
// ≈ spinGuardBudget, i.e. roughly constant TIME between preemption
// points across guests, assuming ~ns-scale SSA values. The clamps keep
// the derivation honest at the extremes: intervals above 2^14 buy
// nothing (the cold call is already <0.1% there), and intervals below
// 2^8 would let the guard itself become a per-iteration cost on very
// large bodies (which already reach the budget in few iterations).
const (
	spinGuardBudget      = 1 << 18
	spinGuardMinInterval = 1 << 8
	spinGuardMaxInterval = 1 << 14
)

// spinGuardMask derives a power-of-two guard interval from the loop
// body size and returns interval-1, the literal the emitters test the
// counter against.
func spinGuardMask(bodyValues int) int {
	if bodyValues < 1 {
		bodyValues = 1
	}
	interval := spinGuardMaxInterval
	for interval > spinGuardMinInterval && interval*bodyValues > spinGuardBudget {
		interval >>= 1
	}
	return interval - 1
}
