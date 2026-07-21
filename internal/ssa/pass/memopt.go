package pass

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// MemOpt performs intra-block memory optimization the Go compiler cannot:
// redundant-load elimination and store-to-load forwarding across the
// unsafe linear-memory accesses wasm2go emits.
//
// Why gc can't do this. Every wasm load/store lowers to an *unsafe*
// pointer access (`*(*T)(unsafe.Add(mBase, off))`). gc's alias analysis
// must assume any unsafe store may alias any unsafe load, so it reloads
// every value after every store and every call and never forwards a
// stored value to a later load. wasmtime/Cranelift recovers exactly this
// with its last-store alias analysis (redundant-load elimination +
// store-to-load forwarding); MemOpt is the wasm2go analogue.
//
// Ordering model. The SSA has no memory token: loads carry only
// [base] and stores [base, value] (see internal/ssa/op.go). Memory
// ordering is preserved purely by emission order — the emitter
// force-hoists every load (internal/emit/hoist.go) so it renders as a
// `vN = <load>` statement at the value's position in blk.Values, and
// stores render as statements at theirs. So two memory ops execute in
// their blk.Values index order. MemOpt therefore reasons in that same
// linear order and never moves an access across a barrier.
//
// Scope is intentionally intra-block: forwarding a value across a block
// boundary needs a meet over predecessors (available-expressions
// dataflow) and is deferred. Even intra-block, this beats gc because gc
// gives up at the first unsafe store or call regardless of block.
//
// Soundness. A candidate load L is replaced by a value X (a prior
// load's result, or a store's value operand) only when X is defined
// earlier in the same block and no barrier sits between X's producer and
// L. X therefore dominates L and every value L dominates, so the
// substitution is SSA-valid. Barriers (calls, atomics, bulk-memory ops,
// memory.grow) clear all availability; a store clears only the cells it
// may alias.
//
// Returns true if anything changed.
func MemOpt(f *ssa.Func) bool {
	// canon maps a replaced load to its surviving equivalent value.
	canon := make(map[ssa.ValueID]*ssa.Value)

	changed := false
	for _, b := range f.Blocks {
		// avail holds, per address, the value currently known to be
		// resident there since the last barrier that could have
		// invalidated it. Reset at each block entry (intra-block scope).
		avail := map[addrKey]*memCell{}
		for _, v := range b.Values {
			if v == nil || v.Op == ssa.OpInvalid {
				continue
			}
			switch {
			case isLinearLoad(v.Op):
				k, ok := memKeyOf(v)
				if !ok {
					continue
				}
				cell := avail[k]
				if cell != nil {
					if x := cell.readableAs(v); x != nil {
						canon[v.ID] = x
						changed = true
						continue
					}
					// Address is live but this exact width/op isn't
					// available yet; record this load so a later
					// identical load can reuse it.
					cell.addLoad(v)
					continue
				}
				avail[k] = newLoadCell(v)

			case isLinearStore(v.Op):
				k, ok := memKeyOf(v)
				if !ok {
					// Unknown address: a store we can't key may alias
					// anything → full barrier.
					avail = map[addrKey]*memCell{}
					continue
				}
				w := byteWidth(v.Op)
				// Invalidate every cell this store may alias. A cell at a
				// different address only survives when both addresses share
				// the same base SSA value and their [off,off+width) byte
				// ranges are provably disjoint — sound because identical
				// base values denote identical runtime addresses and the
				// offsets/widths are compile-time constants.
				for ck, cc := range avail {
					if ck == k {
						continue
					}
					if !mayAlias(ck.base, ck.off, cc.width, k.base, k.off, w) {
						continue
					}
					delete(avail, ck)
				}
				// The bytes at k now hold this store's value operand.
				avail[k] = newStoreCell(v)

			case isMemBarrier(v):
				avail = map[addrKey]*memCell{}
			}
		}
	}

	if !changed {
		return false
	}

	// Resolve chains (a replacement may itself have been replaced) and
	// rewrite every reference, then bury the replaced loads.
	resolve := func(v *ssa.Value) *ssa.Value {
		for v != nil {
			r, ok := canon[v.ID]
			if !ok || r == v {
				return v
			}
			v = r
		}
		return v
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v == nil || v.Op == ssa.OpInvalid {
				continue
			}
			for i, a := range v.Args {
				if a == nil {
					continue
				}
				if r := resolve(a); r != a {
					v.Args[i] = r
				}
			}
		}
		if b.Control != nil {
			b.Control = resolve(b.Control)
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v == nil || v.Op == ssa.OpInvalid {
				continue
			}
			if _, ok := canon[v.ID]; ok {
				v.Op = ssa.OpInvalid
				v.Args = nil
			}
		}
	}
	return true
}

// addrKey identifies a memory address as base-value + constant offset.
// Two accesses with the same key touch the same runtime address.
type addrKey struct {
	base ssa.ValueID
	off  int64
}

// loadKey identifies a load flavour by op AND result type. The type is
// load-bearing: a single op can carry two result types — i32.load8_s and
// i64.load8_s both lower to OpLoad8S but yield i32 vs i64 — so two loads
// are interchangeable only when their op and type both match.
type loadKey struct {
	op  ssa.Op
	typ ssa.Type
}

// memCell records what is known to be resident at one address since the
// last invalidating event. `storeVal`, when set, is the value operand of
// the most recent store to this address (usable for store-to-load
// forwarding); `loads` maps each (op,type) load flavour already performed
// at this address to its result value (usable for redundant-load
// elimination).
type memCell struct {
	width    int64
	storeVal *ssa.Value
	storeOp  ssa.Op
	loads    map[loadKey]*ssa.Value
}

func newLoadCell(v *ssa.Value) *memCell {
	return &memCell{
		width: byteWidth(v.Op),
		loads: map[loadKey]*ssa.Value{{v.Op, v.Type}: v},
	}
}

func newStoreCell(v *ssa.Value) *memCell {
	return &memCell{
		width:    byteWidth(v.Op),
		storeVal: v.Args[1],
		storeOp:  v.Op,
	}
}

func (c *memCell) addLoad(v *ssa.Value) {
	if c.loads == nil {
		c.loads = map[loadKey]*ssa.Value{}
	}
	c.loads[loadKey{v.Op, v.Type}] = v
	if w := byteWidth(v.Op); w > c.width {
		c.width = w
	}
}

// readableAs returns the value that satisfies load v from this cell, or
// nil if the cell holds nothing v can consume without a conversion.
func (c *memCell) readableAs(v *ssa.Value) *ssa.Value {
	// Prior identical load (same op AND type ⇒ same width, signedness and
	// result type ⇒ same value): reuse its result directly.
	if c.loads != nil {
		if prev, ok := c.loads[loadKey{v.Op, v.Type}]; ok {
			return prev
		}
	}
	// A store whose width matches the load exactly and whose value type
	// equals the load's result type: forward the stored value. Requiring
	// an exact full-width pair avoids any truncation/extension mismatch
	// (e.g. i64.store32 feeding i32.load, or i32.store8 feeding
	// i32.load8_u, both of which would need a runtime conversion).
	if c.storeVal != nil && forwardable(c.storeOp, v.Op) && c.storeVal.Type == v.Type {
		return c.storeVal
	}
	return nil
}

// memKeyOf returns the (base, offset) key of a linear load/store, or
// ok=false when the base operand is missing.
func memKeyOf(v *ssa.Value) (addrKey, bool) {
	if len(v.Args) == 0 || v.Args[0] == nil {
		return addrKey{}, false
	}
	return addrKey{base: v.Args[0].ID, off: v.AuxInt}, true
}

// mayAlias reports whether two accesses might touch overlapping bytes.
// When the base SSA values are identical the addresses are identical
// runtime pointers, so overlap is decided exactly by the constant byte
// ranges; otherwise the bases are unknown and must be assumed to alias.
func mayAlias(baseA ssa.ValueID, offA, widthA int64, baseB ssa.ValueID, offB, widthB int64) bool {
	if baseA != baseB {
		return true
	}
	return offA < offB+widthB && offB < offA+widthA
}

// forwardable reports whether a store of op storeOp can have its value
// operand forwarded, without conversion, to a load of op loadOp. Only
// exact full-width, same-type pairs qualify.
func forwardable(storeOp, loadOp ssa.Op) bool {
	switch storeOp {
	case ssa.OpStore32:
		return loadOp == ssa.OpLoad32
	case ssa.OpStore64:
		return loadOp == ssa.OpLoad64
	case ssa.OpStoreF32:
		return loadOp == ssa.OpLoadF32
	case ssa.OpStoreF64:
		return loadOp == ssa.OpLoadF64
	}
	return false
}

// byteWidth returns the number of bytes a linear memory op reads/writes.
func byteWidth(op ssa.Op) int64 {
	switch op {
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpStore8:
		return 1
	case ssa.OpLoad16U, ssa.OpLoad16S, ssa.OpStore16:
		return 2
	case ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpStore32,
		ssa.OpLoadF32, ssa.OpStoreF32:
		return 4
	case ssa.OpLoad64, ssa.OpStore64, ssa.OpLoadF64, ssa.OpStoreF64:
		return 8
	}
	return 0
}

func isLinearLoad(op ssa.Op) bool {
	switch op {
	case ssa.OpLoad8U, ssa.OpLoad8S, ssa.OpLoad16U, ssa.OpLoad16S,
		ssa.OpLoad32, ssa.OpLoad32U, ssa.OpLoad32S, ssa.OpLoad64,
		ssa.OpLoadF32, ssa.OpLoadF64:
		return true
	}
	return false
}

func isLinearStore(op ssa.Op) bool {
	switch op {
	case ssa.OpStore8, ssa.OpStore16, ssa.OpStore32, ssa.OpStore64,
		ssa.OpStoreF32, ssa.OpStoreF64:
		return true
	}
	return false
}

// isMemBarrier reports whether evaluating v may write linear memory at
// an unknown location — clearing all availability. Real calls, atomics
// and bulk-memory ops qualify. Pure helper calls (clz, sqrt, div, ...)
// do NOT touch linear memory and are deliberately not barriers, so
// arithmetic-heavy loops keep forwarding across them. Globals live in a
// separate address space and are ignored here.
func isMemBarrier(v *ssa.Value) bool {
	switch v.Op {
	case ssa.OpCallDirect, ssa.OpCallIndirect, ssa.OpCallImport,
		ssa.OpAtomicCall,
		ssa.OpMemoryCopy, ssa.OpMemoryFill, ssa.OpMemoryInit, ssa.OpDataDrop,
		ssa.OpMemGrow:
		return true
	}
	return false
}
