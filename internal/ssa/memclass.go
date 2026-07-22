package ssa

import "math"

// AliasClass classifies where a memory access lands. It is the
// observability backbone of memory promotion: every wasm
// load / store is tagged so the transpiler can report — and act on —
// how much of the linear-memory traffic is provably function-local.
type AliasClass uint8

const (
	// AliasUnknown: not yet classified.
	AliasUnknown AliasClass = iota
	// AliasSlab: a generic linear-memory access through the shared
	// m.Memory byte slab. Not promotable — the address provenance is
	// dynamic, escapes, or could not be proven local.
	AliasSlab
	// AliasFrame: the access targets a function-local stack frame
	// (the `g0 -= N` prologue allocation) whose frame pointer provably
	// does not escape the function. Promotable to a Go `[N]byte`.
	AliasFrame
	// AliasRodata: the access reads a compile-time-constant address
	// inside a data segment that is never written. Promotable to a
	// shared readonly byte slice.
	AliasRodata
)

func (c AliasClass) String() string {
	switch c {
	case AliasSlab:
		return "slab"
	case AliasFrame:
		return "frame"
	case AliasRodata:
		return "rodata"
	}
	return "unknown"
}

// MemClass is the per-function result of ClassifyMemory: a class for
// every memory-op value, plus the detected stack-frame facts.
type MemClass struct {
	// Class maps each load/store value ID to its AliasClass.
	Class map[ValueID]AliasClass
	// FramePtr is the SSA value identified as the stack-frame pointer
	// (`g0 - N`), or nil if no frame prologue was found.
	FramePtr *Value
	// FrameSize is the byte size N of the detected frame (0 if none).
	FrameSize int64
	// FrameEscapes is true when a frame-pointer-derived value is used
	// in a way that lets the frame outlive / leave the function (passed
	// to a call, stored to memory, used in opaque arithmetic). When
	// true, frame accesses are demoted to AliasSlab.
	FrameEscapes bool
	// EscapeReason, when FrameEscapes, names why (for the JSON / debug
	// report).
	EscapeReason string

	// Slot-granular measurement (observability only — nothing rewrites
	// on these yet). The whole-frame escape analysis above is
	// all-or-nothing: one escaping pointer demotes EVERY frame access.
	// These fields measure what a per-slot analysis would recover under
	// the upward-extent model: an escaped pointer `fp+e` grants the
	// callee/store access to [e, frameSize) — the C object the pointer
	// names and everything above it — while slots strictly below every
	// escaped offset remain provably private to the function.
	//
	// FrameAccesses counts every access through an fp-derived address
	// (whether or not the frame escapes). SlotPromotable, meaningful
	// only when FrameEscapes, counts the subset whose byte range lies
	// entirely below EscapeMinOff. EscapeMinOff is the lowest
	// fp-relative offset that escapes; -1 means an escape with no
	// attributable offset (dynamic pointer arithmetic, an opaque use)
	// poisons the whole frame.
	FrameAccesses  int
	SlotPromotable int
	EscapeMinOff   int64
}

// ClassifyMemory analyses one SSA function and classifies every memory
// access. It is intraprocedural and conservative: anything it cannot
// prove function-local stays AliasSlab.
//
// Frame detection: the standard LLVM/Emscripten prologue is
//
//	g0' = g0 - N      ; OpSub32(OpGlobalGet[0], OpConst32[N])
//	(local.tee fp)    ; fp = g0'
//	global.set 0 g0'  ; OpGlobalSet[0]
//
// The result of that subtraction is the frame pointer. Loads/stores
// whose address is `fp` or `fp + const` are frame accesses. The frame
// is promotable only if the frame pointer never escapes.
func ClassifyMemory(f *Func) *MemClass {
	mc := &MemClass{Class: map[ValueID]AliasClass{}}

	// 1. Locate the frame pointer.
	mc.FramePtr, mc.FrameSize = findFramePointer(f)

	// 2. Compute the set of frame-pointer-derived values — fp itself,
	// plus fp+const (any number of constant offsets), plus copies —
	// each with its constant fp-relative offset.
	frameOff := map[ValueID]int64{}
	if mc.FramePtr != nil {
		frameOff[mc.FramePtr.ID] = 0
		// Fixpoint: a value is frame-derived if it is OpAdd32 /
		// OpSub32 of a frame-derived value and a constant, or a copy.
		changed := true
		for changed {
			changed = false
			for _, v := range f.Values {
				if v == nil {
					continue
				}
				if _, seen := frameOff[v.ID]; seen {
					continue
				}
				if off, ok := frameOffsetOf(v, frameOff); ok {
					frameOff[v.ID] = off
					changed = true
				}
			}
		}
	}

	// 3. Escape analysis: walk every use of every frame-derived value.
	minEsc := int64(math.MaxInt64)
	if mc.FramePtr != nil {
		users := buildUseMap(f)
		mc.FrameEscapes, mc.EscapeReason, minEsc = frameEscapes(f, frameOff, users)
		mc.EscapeMinOff = minEsc
		if minEsc == math.MinInt64 {
			mc.EscapeMinOff = -1
		}
	}

	// 4. Classify each memory op.
	for _, v := range f.Values {
		if v == nil || !isMemoryAccess(v.Op) {
			continue
		}
		addr := constFoldAddr(memAddr(v))
		off, isFrameAddr := int64(0), false
		if addr != nil {
			off, isFrameAddr = frameOff[addr.ID]
		}
		switch {
		case mc.FramePtr != nil && isFrameAddr && !mc.FrameEscapes:
			mc.Class[v.ID] = AliasFrame
		case addr != nil && addr.Op == OpConst32 && isLoadOp(v.Op):
			// A load from a compile-time-constant linear-memory address
			// is a rodata-promotion candidate: such addresses point at
			// module data segments (string tables, vtables, ...).
			// Whether the segment is provably never written is a
			// whole-module property the rewrite stage must confirm;
			// for observability this is the candidate set.
			mc.Class[v.ID] = AliasRodata
		default:
			mc.Class[v.ID] = AliasSlab
		}
		// Slot-granular measurement: the access's byte range is
		// [off + AuxInt, off + AuxInt + width) relative to fp.
		if mc.FramePtr != nil && isFrameAddr {
			mc.FrameAccesses++
			if mc.FrameEscapes && off+v.AuxInt+accessWidth(v.Op) <= minEsc {
				mc.SlotPromotable++
			}
		}
	}
	return mc
}

// accessWidth returns the byte width a load/store touches.
func accessWidth(op Op) int64 {
	switch op {
	case OpLoad8U, OpLoad8S, OpStore8:
		return 1
	case OpLoad16U, OpLoad16S, OpStore16:
		return 2
	case OpLoad32, OpLoad32U, OpLoad32S, OpLoadF32, OpStore32, OpStoreF32:
		return 4
	}
	return 8
}

// isLoadOp reports whether op is a memory load (as opposed to a store).
func isLoadOp(op Op) bool {
	switch op {
	case OpLoad8U, OpLoad8S, OpLoad16U, OpLoad16S, OpLoad32,
		OpLoad32U, OpLoad32S, OpLoad64, OpLoadF32, OpLoadF64:
		return true
	}
	return false
}

// constFoldAddr peels OpCopy and folds `OpConst + OpConst` /
// `OpAdd(OpConst, OpConst)` so a memory address that is constant after
// trivial arithmetic is recognised as such. Returns a synthetic
// const-typed value when it folds, else the original.
func constFoldAddr(v *Value) *Value {
	if v == nil {
		return nil
	}
	if v.Op == OpCopy && len(v.Args) == 1 {
		return constFoldAddr(v.Args[0])
	}
	if v.Op == OpAdd32 && len(v.Args) == 2 {
		a := constFoldAddr(v.Args[0])
		b := constFoldAddr(v.Args[1])
		if a != nil && b != nil && a.Op == OpConst32 && b.Op == OpConst32 {
			// Return a stand-in const value (not registered on the
			// Func — used only for classification, never emitted).
			return &Value{Op: OpConst32, Type: TypeI32, AuxInt: a.AuxInt + b.AuxInt}
		}
	}
	return v
}

// findFramePointer scans f for the prologue subtraction
// `OpSub32(OpGlobalGet[0], OpConst32[N])` and returns that value and N.
func findFramePointer(f *Func) (*Value, int64) {
	for _, v := range f.Values {
		if v == nil || v.Op != OpSub32 || len(v.Args) != 2 {
			continue
		}
		base, off := v.Args[0], v.Args[1]
		if base == nil || off == nil {
			continue
		}
		if base.Op == OpGlobalGet && base.AuxInt == 0 && off.Op == OpConst32 {
			return v, off.AuxInt
		}
	}
	return nil, 0
}

// frameOffsetOf reports whether v is `frameDerived ± const` or a copy
// of a frame-derived value, and if so its fp-relative offset.
func frameOffsetOf(v *Value, frameOff map[ValueID]int64) (int64, bool) {
	switch v.Op {
	case OpCopy:
		if len(v.Args) == 1 && v.Args[0] != nil {
			if o, ok := frameOff[v.Args[0].ID]; ok {
				return o, true
			}
		}
	case OpAdd32, OpSub32:
		if len(v.Args) != 2 || v.Args[0] == nil || v.Args[1] == nil {
			return 0, false
		}
		a, b := v.Args[0], v.Args[1]
		// frameDerived + const  (or const + frameDerived for Add)
		if o, ok := frameOff[a.ID]; ok && b.Op == OpConst32 {
			if v.Op == OpAdd32 {
				return o + b.AuxInt, true
			}
			return o - b.AuxInt, true
		}
		if v.Op == OpAdd32 {
			if o, ok := frameOff[b.ID]; ok && a.Op == OpConst32 {
				return o + a.AuxInt, true
			}
		}
	}
	return 0, false
}

// buildUseMap returns, per value ID, the list of values that reference
// it as an argument.
func buildUseMap(f *Func) map[ValueID][]*Value {
	users := map[ValueID][]*Value{}
	for _, v := range f.Values {
		if v == nil {
			continue
		}
		for _, a := range v.Args {
			if a != nil {
				users[a.ID] = append(users[a.ID], v)
			}
		}
	}
	return users
}

// frameEscapes returns whether any frame-derived value is used in a way
// that lets the frame escape the function, the first reason found, and
// the minimum escaped fp-relative offset (math.MaxInt64 when nothing
// escapes; math.MinInt64 when an escape has no attributable offset and
// poisons the whole frame under the upward-extent model).
func frameEscapes(f *Func, frameOff map[ValueID]int64, users map[ValueID][]*Value) (bool, string, int64) {
	escaped, reason := false, ""
	minOff := int64(math.MaxInt64)
	escape := func(off int64, why string) {
		if !escaped {
			escaped, reason = true, why
		}
		if off < minOff {
			minOff = off
		}
	}
	for _, v := range f.Values {
		if v == nil {
			continue
		}
		off, ok := frameOff[v.ID]
		if !ok {
			continue
		}
		for _, u := range users[v.ID] {
			switch u.Op {
			case OpGlobalSet:
				// Frame management (prologue set / epilogue restore).
			case OpAdd32, OpSub32:
				// `fp ± const` stays frame-derived; non-const operands
				// were already excluded from frameOff, but a use of fp
				// as `fp - dynamicValue` is opaque → the derived
				// pointer can reach any slot: whole-frame poison.
				if _, derived := frameOff[u.ID]; !derived {
					escape(math.MinInt64, "frame pointer used in non-constant arithmetic")
				}
			case OpCopy:
				// A copy of a frame value is itself frame-derived.
			case OpStore8, OpStore16, OpStore32, OpStore64, OpStoreF32, OpStoreF64:
				// Address operand (Args[0]) is fine — a frame store.
				// Value operand (Args[1]) means the pointer itself is
				// written into memory → escape at its offset.
				if len(u.Args) >= 2 && u.Args[1] == v {
					escape(off, "frame pointer stored to memory")
				}
			case OpLoad8U, OpLoad8S, OpLoad16U, OpLoad16S, OpLoad32,
				OpLoad32U, OpLoad32S, OpLoad64, OpLoadF32, OpLoadF64:
				// Address operand — a frame load. Fine.
			case OpEq32, OpNe32, OpLtS32, OpLtU32, OpLeS32, OpLeU32:
				// Comparing the frame pointer (stack-limit checks,
				// pointer equality) consumes it as a NUMBER — no alias
				// is created and no frame memory becomes reachable.
			case OpCallDirect, OpCallIndirect, OpCallImport:
				escape(off, "frame pointer passed to a call")
			default:
				// Bulk-memory ops, selects, comparisons, … — no offset
				// attribution attempted: whole-frame poison.
				escape(math.MinInt64, "frame pointer used by "+u.Op.String())
			}
		}
	}
	return escaped, reason, minOff
}

// isMemoryAccess reports whether op is a load or store.
func isMemoryAccess(op Op) bool {
	switch op {
	case OpLoad8U, OpLoad8S, OpLoad16U, OpLoad16S, OpLoad32,
		OpLoad32U, OpLoad32S, OpLoad64, OpLoadF32, OpLoadF64,
		OpStore8, OpStore16, OpStore32, OpStore64, OpStoreF32, OpStoreF64:
		return true
	}
	return false
}

// memAddr returns the address operand of a memory-access value.
func memAddr(v *Value) *Value {
	if len(v.Args) == 0 {
		return nil
	}
	return v.Args[0]
}
