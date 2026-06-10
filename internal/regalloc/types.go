// Package regalloc implements a greedy linear-scan register allocator with
// Belady-style farthest-next-use eviction, modeled on Go's
// cmd/compile/internal/ssa/regalloc.go. It produces a side-table mapping
// each SSA value to either a register or a stack slot, plus per-edge
// shuffle plans, per-block start/end register state, and spill placements.
//
// Unlike Go's compiler we do NOT mutate the SSA — every allocation
// decision is recorded in Result, and asmgen reads Result back when
// emitting Plan9 asm. The walk shape, the data flow, and the heuristics
// (Belady, computeDesired, call-distance penalties, dom-tree spill
// hoisting, interference-graph slot sharing) all match Go's design.
//
// The package is arch-agnostic — the per-arch register pool, calling
// convention, and per-op register requirements come in through the
// ArchInfo interface. We supply ArchAMD64 and ArchARM64 implementations
// in arch_amd64.go and arch_arm64.go.
package regalloc

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// regMask is a bitset over the architecture's registers. With at most 64
// registers per arch (matching Go's regalloc), uint64 suffices. Bit i is
// set iff register index i is in the mask. The empty mask (0) is the
// usual "no register" sentinel.
type regMask uint64

// register is a per-arch numeric index into ArchInfo's register list.
// Indices are stable for the lifetime of an allocator run; they do NOT
// match any external numbering scheme. noRegister sits past every valid
// index so the zero value of a register slot still distinguishes
// "uninitialised" from "register 0".
type register uint8

// noRegister marks an unset register field. We use 255 (not 0) so the
// zero value of a register inside a struct can mean "register 0 (AX)"
// rather than "absent". Callers that need an "absent" sentinel must
// explicitly set noRegister.
const noRegister register = 255

// regClass partitions registers into the families the type system
// distinguishes. Float and integer values cannot share a register;
// flags have no asm-level register at all. The allocator picks from
// the mask matching the value's class.
type regClass uint8

const (
	// ClassGP names the general-purpose integer registers (AX/BX/... on
	// amd64; R0..R30 on arm64). Int / pointer / bool values land here.
	ClassGP regClass = iota
	// ClassSSE names the floating-point / SIMD registers (X0..X15 on
	// amd64; F0..F31 on arm64). Float32 / Float64 values land here.
	ClassSSE
	// ClassFlags marks comparison results that live only in the flags
	// register. The allocator gives them no home; downstream consumers
	// must read flags inline or the value must be re-materialised.
	ClassFlags
)

// regInfo describes the register constraints for one SSA opcode — what
// each input wants, what each output produces, and what the op clobbers
// independent of its inputs / outputs. Modeled on Go's regInfo at
// cmd/compile/internal/ssa/op.go.
//
// Inputs and Outputs are per-position lists (indexed by Value.Args
// position for inputs, by output index for outputs — every op has
// exactly one output in our SSA, mirrored as Outputs[0]). Each entry's
// regs mask says "any of these registers is acceptable for this
// position". A single-bit mask means "this register exactly" (used for
// ABI args, MUL's hard-wired AX/DX, etc.).
type regInfo struct {
	// Inputs lists the per-arg register constraints. Inputs[i] applies
	// to v.Args[i]. Args whose value has no register home (memory, void,
	// flags) are omitted by ArchInfo.RegSpec — the allocator iterates
	// Inputs against the matching v.Args positions.
	Inputs []regParam
	// Outputs lists the per-result register constraints. Our SSA has at
	// most one result per op, so Outputs always has 0 or 1 entries.
	Outputs []regParam
	// Clobbers is the union of registers the op trashes besides its
	// outputs. For a CALL this is the full caller-save GP / SSE set
	// (Go's ABI0 treats every GP as caller-save); for IDIV it's
	// {AX, DX}; for most ALU ops this is empty.
	Clobbers regMask
}

// regParam describes the register acceptance for one input or output
// position. `idx` is the Value.Args index (or 0 for outputs); `regs` is
// the set of registers the position will accept.
type regParam struct {
	// Idx is the position this constraint applies to: for Inputs, the
	// index into v.Args; for Outputs, always 0 (we have single-result
	// ops). The redundant field keeps the regInfo shape identical to
	// Go's so future multi-output ops can extend without restructuring.
	Idx int
	// Regs is the mask of registers acceptable for this position. A
	// single-bit mask is a hard ABI requirement; a multi-bit mask gives
	// the allocator freedom to pick.
	Regs regMask
}

// liveInfo is the persistent per-block live-out summary computed by
// computeLive. One entry per value live at the end of the block, plus
// its distance to the next use measured in instructions across the
// successor frontier. Matches Go's regalloc.go:2827–2831.
type liveInfo struct {
	// ID identifies the SSA value that's live out.
	ID ssa.ValueID
	// Dist is the instruction count from the end of this block to the
	// next use of ID. Smaller = use sooner = prefer to keep in a
	// register. Values whose dist is bumped by unlikelyDistance (because
	// they live across a CALL) get deprioritised by the eviction
	// heuristic.
	Dist int32
}

// Distance constants for liveness propagation, matching Go's regalloc.go
// constants. Likely branches shorten the apparent distance to consumers
// in the taken side; unlikely branches lengthen it. CALL barriers add
// the full unlikelyDistance so post-call uses lose to anything that
// hits before the call.
const (
	// LikelyDistance applies to the likely successor of a conditional
	// branch. Smaller than normal so the allocator prefers to keep
	// values live into the likely path.
	LikelyDistance int32 = 1
	// NormalDistance applies to every successor when the block has no
	// likelihood hint, or to the second arm of a hinted branch.
	NormalDistance int32 = 10
	// UnlikelyDistance applies to the unlikely successor of a
	// conditional branch. Anything live only into the unlikely arm is
	// strongly deprioritised — the allocator will spill it before
	// touching values used on the likely path.
	UnlikelyDistance int32 = 100
	// UnknownDistance is the sentinel for "use lies past a successor
	// whose own distances are still being computed". The fixpoint pass
	// in computeLive replaces -1 entries with the correct distance once
	// the successor stabilises.
	UnknownDistance int32 = -1
)

// use is a node in the per-block use list. The allocator builds this
// list freshly at the top of each block from the global liveInfo plus
// the in-block value walk; it is consumed during the forward walk to
// know "when does this value die" and "is its next use past a CALL".
// Matches Go's regalloc.go:219–228.
type use struct {
	// Dist is the instruction index within the block at which this use
	// occurs. Distances past len(b.Values) represent uses in successor
	// blocks (the value is live-out) — the allocator uses these as the
	// next-use distance when picking eviction victims.
	Dist int32
	// Next links the next use of the same value in dist-increasing
	// order, so popping from the front gives the nearest use first.
	Next *use
}

// endReg records one (register, value) pair from the register file at
// the end of a block. It is the per-block "ABI" the cross-block
// machinery exposes: a single-pred successor adopts a predecessor's
// endRegs as its start state. Matches Go's regalloc.go:344–348.
type endReg struct {
	// R names the register that holds the value.
	R register
	// V is the SSA value ID currently in R at end of block.
	V ssa.ValueID
}

// startReg records the register state a merge block expects on entry.
// Populated when the allocator first visits the merge block; the
// shuffle pass later emits compensation MOVs on each predecessor edge
// so the predecessor's endRegs match this set. Matches Go's
// regalloc.go:351–356.
type startReg struct {
	// R names the register the merge block expects the value in.
	R register
	// V is the SSA value ID the merge block wants in R.
	V ssa.ValueID
}

// valState is per-value mutable state during the allocator's forward
// walk. One entry per SSA value, indexed by Value.ID. Matches Go's
// regalloc.go:231–239 modulo the spill placement details (we record
// spill metadata in a separate Result struct rather than mutating SSA).
type valState struct {
	// Regs is the set of registers that currently hold this value.
	// Usually 0 (in slot or dead) or a single bit (in one register);
	// can transiently hold two bits while the eviction-by-copy path is
	// moving a value out of one register into another.
	Regs regMask
	// Uses is the head of this block's use list for this value, with
	// the nearest use first.
	Uses *use
	// SpillNeeded is set when the allocator has decided this value
	// will need a stack slot (e.g. it survives a CALL or was evicted
	// without a free reg). Slot allocation happens in spill.go.
	SpillNeeded bool
	// NeedReg caches whether the value's type asks for a register at
	// all. Memory tokens, void, and flag results have NeedReg == false
	// and skip the allocator entirely.
	NeedReg bool
	// Rematerializeable caches whether the value can be cheaply
	// recomputed at any reload site (e.g. OpConst32 with a fits-in-32
	// immediate). Rematerializeable values are never spilled — they
	// reissue at each use.
	Rematerializeable bool
}

// regState is per-register mutable state during the forward walk: the
// SSA value currently held in this register, or 0 if free. We split
// 'v' (the abstract pre-allocator value) from any concrete carrier
// produced by a copy / reload — see Go's regState at regalloc.go:241–
// 245 for the dual representation. Our asmgen reads only V here
// because we never insert OpCopy / OpLoadReg / OpStoreReg Values back
// into the SSA; the carrier identity is implicit in the emit stream.
type regState struct {
	// V is the SSA value ID currently resident, or 0 if the register
	// is free. Use V == 0 as the "free" check; the actual ssa.ValueID
	// type uses 0 as its invalid sentinel as well.
	V ssa.ValueID
}

// desiredEntry holds the priority-ordered register list for one
// hinted value. Up to MaxDesiredHints entries — the same cap Go uses
// (4 hints) — keeps the per-value memory small while still capturing
// "this value would like to be in AX or BX, and if neither, CX or DX".
type desiredEntry struct {
	// Regs is the priority list. Regs[0] is the most-preferred
	// register; subsequent slots are fallbacks. Unset slots hold
	// noRegister so a simple linear scan is the lookup.
	Regs [MaxDesiredHints]register
}

// MaxDesiredHints caps how many distinct register hints we record per
// value. 4 matches Go's choice; one common shape (two-address arith
// with a CALL ABI consumer) saturates 2–3 of the slots in practice.
const MaxDesiredHints = 4
