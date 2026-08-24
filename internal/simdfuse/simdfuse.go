package simdfuse

// Package simdfuse holds the fused-SIMD-region descriptor shared
// between the code generator and the gcasm backend.
//
// The scalarizer fuses a nested tree of pairable SIMD calls — the
// shape quantized dot kernels are made of, e.g.
//
//	i32x4_add(i32x4_dot_i16x8(load(x), load(y)), acc)
//
// into ONE synthetic helper call. The generated Go body of that helper
// is the naive chain of the member helpers, which is what the pure
// fallback runs and what the capture compile type-checks against. The
// gcasm transform, however, replaces the whole call with a synthesized
// body composed from the members' splice sequences, keeping every
// internal edge inside the vector register file. gc therefore never
// sees the intermediate v128 values at all — nothing to shuttle
// through GPR pairs, nothing to spill.
//
// codegen produces these descriptors (one per distinct tree shape) and
// transpile hands them to gcasm.Build. The tree is meaning, not
// syntax: gcasm resolves fused calls by symbol name against this
// table, never by parsing the name.

// Node is one member of a fused tree, identified by its pair-splice op
// name (the simd_/simd_p_ prefix stripped): "i16x8_add",
// "v128_load_rng", ...
type Node struct {
	// Op is the pair-splice table key.
	Op string
	// Args describes the member's arguments in helper-signature order,
	// EXCLUDING the leading *Module receiver of memory ops (gcasm
	// re-adds it from the fused call's own m argument).
	Args []Arg
}

// NodeClass is the result class of a member op. Most members produce a
// v128; the scalar vocabulary below produces an int32 or float32
// instead, letting the leaf computation that FEEDS a region (a kernel's
// per-block scale chains: u16 load, shift, table base add, f32 load,
// f32 multiply) run inside the splice instead of as gc-compiled code
// around it.
type NodeClass uint8

const (
	ClassV128 NodeClass = iota
	ClassI32
	ClassF32
)

// scalarOpClass is the scalar vocabulary. Scalar loads mirror the
// emitter's own unchecked scalar accesses (the memoryGrow hard cap
// keeps every u32 offset inside the reserved region); the arithmetic
// ops wrap mod 2^32 exactly like their wasm counterparts.
//
//	scalar_i32_load16_u  (addr)            -> i32   zero-extended
//	scalar_i32_shl       (v, const)        -> i32
//	scalar_i32_add       (a, b)            -> i32
//	scalar_f32_load      (addr)            -> f32
//	scalar_f32_mul       (a, b)            -> f32
var scalarOpClass = map[string]NodeClass{
	"scalar_i32_load16_u": ClassI32,
	"scalar_i32_shl":      ClassI32,
	"scalar_i32_add":      ClassI32,
	"scalar_f32_load":     ClassF32,
	"scalar_f32_mul":      ClassF32,
}

// Class reports the node's result class.
func (n *Node) Class() NodeClass {
	if c, ok := scalarOpClass[n.Op]; ok {
		return c
	}
	return ClassV128
}

// ScalarMemOp reports whether the op is a scalar memory load (needs
// the Module receiver in the fallback body and the memory base in the
// splice).
func ScalarMemOp(op string) bool {
	return op == "scalar_i32_load16_u" || op == "scalar_f32_load"
}

// IsStore reports whether the op is a memory-store sink: it consumes
// a v128 value, produces nothing, and must keep its order relative to
// every other memory op in the region.
func IsStore(op string) bool {
	return op == "v128_store" || op == "v128_f16x4_cvt_store"
}

// ArgKind says where a member argument comes from.
type ArgKind uint8

const (
	// ArgNode: the v128 result of another member, Index into
	// Tree.Nodes. Always an earlier node (the tree is in post-order).
	ArgNode ArgKind = iota
	// ArgPairIn: a v128 leaf input of the fused function, Index'th
	// pair parameter (each rides as two uint64 GPR args).
	ArgPairIn
	// ArgScalar: an int32 leaf input (address, lane, shift count,
	// ...), Index'th scalar parameter of the fused function.
	ArgScalar
	// ArgConst: a compile-time int32 constant (memarg offsets, rng
	// window bounds). Rides the descriptor as Const and takes no ABI
	// slot — the synthesized splice emits it as an immediate. Baking
	// constants into the shape multiplies distinct shapes, but kernel code
	// kernels reuse the same handful of offsets, and it is what lets
	// a whole dot-kernel iteration fit the amd64 integer-register
	// budget.
	ArgConst
	// ArgFloat: a float32 leaf input, Index'th float parameter. Float
	// parameters ride the FLOAT argument registers (F0../X0..), a
	// register class the rest of the fused signature never touches —
	// free capacity that lets f32x4_splat scale factors join regions.
	ArgFloat
	// ArgSum: the Index'th scalar parameter plus Const, truncated to
	// u32 — exactly wasm's Add32. Unrolled kernels address k blocks as
	// base+stride*i: with the base deduplicated into one scalar and
	// the byte offsets riding the descriptor, sixteen loads cost two
	// argument registers instead of sixteen.
	ArgSum
)

// Arg is one argument slot of a member op.
type Arg struct {
	Kind  ArgKind
	Index int
	// Const is the immediate for ArgConst.
	Const int32
}

// Tree is a fused region: Nodes in post-order (every ArgNode refers
// backward). Roots lists the nodes whose v128 results the fused
// function returns, two uint64s each, in order; an empty Roots means
// the single-root form (the last node). Multi-root regions exist for
// the common kernel shape where one load feeds several trees: the load
// becomes an internal node executed once, and each consuming tree a
// root.
type Tree struct {
	// Name is the synthetic helper's base name (e.g. "simd_p_fx3").
	Name string
	// NumScalars, NumFloats and NumPairs size the fused signature:
	// func (m *Module, s0..s{NumScalars-1} int32,
	//       f0..f{NumFloats-1} float32,
	//       p0lo, p0hi, .. uint64) (r0lo, r0hi[, r1lo, r1hi, ...] uint64)
	NumScalars int
	NumFloats  int
	NumPairs   int
	// NeedsMem reports whether any member is a memory op (the fused
	// splice then needs the Module field offsets and the trap stub).
	NeedsMem bool
	// Addr64 marks a memory64 module's tree: every scalar parameter is
	// int64, the addresses/offsets of memory members ride as OPAQUE
	// scalars (the builder never const-folds them — Arg.Const is
	// 32-bit), the fallback body calls the simd_m64_* helpers, and the
	// splicers widen the address glue with carry-checked sums. The
	// vector node bodies are identical either way.
	Addr64 bool
	Nodes  []Node
	Roots  []int
	// NoResult marks a pure-sink region (every value flows into
	// stores): the fused function returns nothing.
	NoResult bool
	// ConstPairs records pair parameters whose value is the same
	// compile-time v128 constant at EVERY call site (the builder folds
	// the constant into the shape key, so distinct constants intern
	// distinct trees). Splicers may specialize on the value — e.g.
	// recognizing an even/odd lane-combine shuffle pattern — while the
	// ABI still passes the pair, keeping the fallback body and the
	// other splicer untouched. Keyed by pair-parameter index.
	ConstPairs map[int][2]uint64
}

// RootList resolves the effective root set.
func (t *Tree) RootList() []int {
	if t.NoResult {
		return nil
	}
	if len(t.Roots) > 0 {
		return t.Roots
	}
	return []int{len(t.Nodes) - 1}
}

// F32Homes assigns a float-home slot to every ClassF32 node that a
// VECTOR node consumes (an f32 intermediate consumed by another scalar
// node chains through scratch instead). Slots continue after the leaf
// float parameters: home k means lane NumFloats+k of the packed float
// register on amd64, register (15 - NumFloats - k) on arm64. Returns
// per-node slots (-1 for none) and the number of slots used. Both the
// splicers and the capacity walk derive the SAME assignment from the
// descriptor, so they can never disagree.
func (t *Tree) F32Homes() ([]int, int) {
	consumedByVector := make([]bool, len(t.Nodes))
	for _, n := range t.Nodes {
		if n.Class() != ClassV128 {
			continue
		}
		for _, a := range n.Args {
			if a.Kind == ArgNode && t.Nodes[a.Index].Class() == ClassF32 {
				consumedByVector[a.Index] = true
			}
		}
	}
	homes := make([]int, len(t.Nodes))
	used := 0
	for i := range t.Nodes {
		homes[i] = -1
		if consumedByVector[i] {
			homes[i] = used
			used++
		}
	}
	return homes, used
}

// Loop is a fused COUNTDOWN LOOP: the body region runs repeatedly
// with its loop-carried state held in registers across iterations,
// so nothing round-trips through GPR pairs or the caller's frame at
// the backedge. The splicers emit prologue + body + bumps + counter
// check as one block; the pure fallback is an ordinary Go for loop.
//
// Iteration semantics (do-while): the body always runs once; after
// each iteration the counter scalar is decremented by Dec, the bump
// scalars advance by their deltas (mod 2^32, like Add32), the carried
// pair inputs take their mapped roots' values, and the loop repeats
// while the counter is non-zero. Callers guarantee the initial
// counter is non-zero and a multiple of Dec.
type Loop struct {
	Tree *Tree
	// CarriedPairs maps pair-argument index -> node index: at entry
	// the pair argument seeds the value; at each backedge the node's
	// result becomes the next iteration's value; at exit it is
	// returned in root order (carried nodes are the Tree's Roots).
	CarriedPairs [][2]int
	// Bumps advance scalar arguments at each backedge:
	// scalar[idx] += delta (u32 wrap).
	Bumps []LoopBump
	// NumDeltas is how many variable-stride parameters follow the
	// counter in the fused-loop signature.
	NumDeltas int
	// CounterWide marks an int64 loop counter (the counter parameter,
	// its arithmetic and its exit result are 64-bit).
	CounterWide bool
	// CounterScalar is the scalar argument holding the trip counter;
	// Dec is subtracted each iteration and the loop exits at zero.
	CounterScalar int
	Dec           int32
	// ExitScalars lists scalar-argument indices whose FINAL values the
	// fused function returns (as int32 results after the root pairs) —
	// the pointers and counter the code after the loop still reads.
	ExitScalars []int
	// PreTest marks the while-form (counter tested BEFORE the first
	// iteration); false is the do-while form, whose callers guarantee
	// a non-zero initial counter.
	PreTest bool
	// ExitGT switches the do-while backedge from the exact-zero
	// (non-equal) test to a SIGNED greater-than test against
	// ExitThresh: the loop repeats while counter > ExitThresh. This
	// mirrors source loops that count down to a floor (`while --c >
	// K`), whose compare the emitter preserves verbatim. Only the
	// do-while form may set it.
	ExitGT     bool
	ExitThresh int32
}

// LoopBump advances one scalar argument at each backedge. The step is
// the constant Delta, or — when DeltaScalar is >= 0 — the value of
// one of the loop's extra delta parameters (loop-invariant strides
// appended after the counter in the fused signature).
type LoopBump struct {
	Scalar      int
	Delta       int32
	DeltaScalar int
}
