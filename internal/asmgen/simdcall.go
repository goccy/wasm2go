package asmgen

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/emit"
	"github.com/goccy/wasm2go/internal/ssa"
)

// SIMD helper calls (OpSimdCall / OpSimdMemCall) are emitted as plain
// ABI0 CALLs to the bundle's simd_* helper symbols — the same symbols
// the pure-Go backend calls and the gcasm splicer later inlines.
// Unlike scalar helpers there is no static signature registry: the
// helper family is large and every signature is fully determined by
// the SSA value itself (arg types, result type, and whether the
// module pointer leads the frame), so the spec is derived per call.

// SimdSpliceOperand describes where one SIMD call operand lives in
// the emitting function's frame: asm operand strings for the value's
// 8-byte halves (Hi only for v128). IsPtr marks the module pointer
// that leads an OpSimdMemCall's argument list.
type SimdSpliceOperand struct {
	Type  ssa.Type
	IsPtr bool
	Lo    string
	Hi    string
	// InSlot / SlotOff: the value lives in the emitting function's
	// frame at this SP-relative byte offset. For v128 operands a
	// splicer can then read the argument from (or write the result
	// to) the value's own slot directly, skipping the scratch-area
	// staging copies entirely.
	InSlot  bool
	SlotOff int
	// Reg names a vector register the value is resident in (a v128
	// loop-carry home). Splicers read the argument from — or write
	// the result to — the register instead of any slot.
	Reg string
}

// SimdSplicer supplies arch-specific inline bodies for SIMD helper
// call sites, replacing the marshalled CALL entirely (the gcasm
// backend implements it over its splice tables). Splice appends the
// staging and body for helper `name`: args are the operand locations
// in call order (module pointer first for memory ops), ret is the
// destination location or nil when the result is void/unused, and
// scratchBase is the SP-relative byte offset of the caller-owned
// scratch area (the callee-argument region — always large enough,
// since the ABI0 call frame for the same signature is a superset of
// the splice's stack traffic). It reports whether it spliced (false
// keeps the CALL path) and whether the body branches to the
// per-function trap stub, which the emitter then appends once at
// body end via TrapStub.
//
// Contract: a splice body confines its register usage to the splice
// clobber set (arm64: R0–R15 / R25–R27 and the V registers). The
// emitter runs SIMD-containing functions without block-local register
// homes or the m-cache (both live in the clobber set), but loop-carry
// scalars MAY be coalesced into the splice-safe registers (arm64
// R19–R24, see runSpliceCoalescePass) and survive across splices.
type SimdSplicer interface {
	Splice(b *strings.Builder, name string, args []SimdSpliceOperand, ret *SimdSpliceOperand, scratchBase int) (spliced, wantsTrap bool)
	TrapStub() string
	// HoistPrologue returns instructions staging the module state the
	// splice bodies consume (the linear-memory data pointer and the
	// memory-size pointer) into splice-safe registers. The emitter
	// places it at function entry, right after the m-cache prime, and
	// re-issues it after every value that actually emitted a CALL
	// (Go's ABI is caller-save, and a callee may have grown memory).
	// Empty disables hoisting: splices then reload the state per
	// site.
	HoistPrologue() string
}

// simdCallSpec is one SIMD helper call's ABI0 layout.
type simdCallSpec struct {
	name    string
	withM   bool // OpSimdMemCall: helper(m, args...); pure calls have no m
	args    []ssa.Type
	argOffs []int
	ret     ssa.Type // TypeInvalid for void stores
	retOff  int
	frame   int // total callee-frame bytes (8-aligned)
}

// simdABISize returns (size, alignment) for a SIMD helper param or
// result in the ABI0 frame; v128 travels as [2]uint64 by value.
func simdABISize(t ssa.Type) (size, align int) {
	if t == ssa.TypeV128 {
		return 16, 8
	}
	return helperABISize(t)
}

// simdCallSpecOf derives the call spec from the SSA value. Errors are
// per-function fallback triggers, not bundle failures: an arg type
// the frame cannot carry or a missing Aux name. Whether the CALL
// spelling can resolve is a call-time question — spliced sites need
// no symbol at all, so multi-package functions stay eligible as long
// as every SIMD site splices (the emitters enforce this).
func simdCallSpecOf(v *ssa.Value, plan *funcPlan) (simdCallSpec, error) {
	name, _ := v.Aux.(string)
	if name == "" {
		return simdCallSpec{}, fmt.Errorf("v%d: %v without a helper name", v.ID, v.Op)
	}
	sp := simdCallSpec{name: name, withM: v.Op == ssa.OpSimdMemCall}
	off := 0
	if sp.withM {
		off = 8 // *Module at SP+0
	}
	for i, a := range v.Args {
		if a == nil {
			return simdCallSpec{}, fmt.Errorf("v%d: %s arg %d is nil", v.ID, name, i)
		}
		size, align := simdABISize(a.Type)
		if size == 0 {
			return simdCallSpec{}, fmt.Errorf("v%d: %s arg %d type %v not carriable", v.ID, name, i, a.Type)
		}
		off = alignUp(off, align)
		sp.args = append(sp.args, a.Type)
		sp.argOffs = append(sp.argOffs, off)
		off += size
	}
	sp.ret = ssa.TypeInvalid
	if !emit.IsVoidAtomicStore(v) {
		size, _ := simdABISize(v.Type)
		if size == 0 {
			return simdCallSpec{}, fmt.Errorf("v%d: %s result type %v not carriable", v.ID, name, v.Type)
		}
		sp.ret = v.Type
		// ABI0: results start at the 8-aligned offset after the args.
		sp.retOff = alignUp(off, 8)
		off = sp.retOff + size
	}
	sp.frame = alignUp(off, 8)
	return sp, nil
}

// v128Parts resolves the two 8-byte halves of a v128 value's storage:
// a parameter's FP slots or the value's stack slot. spName is the
// arch's stack-pointer spelling ("SP" amd64, "RSP" arm64). Constants
// are materialized into their slot by the OpSimdConst emit, so the
// slot path covers them.
func v128Parts(v *ssa.Value, plan *funcPlan, frame argFrame, spName string) (lo, hi string) {
	v = resolveCopy(v)
	if v.Op == ssa.OpParam && !plan.packed {
		idx := int(v.AuxInt)
		if idx >= 0 && idx < len(frame.paramOffsets) {
			base := frame.paramOffsets[idx]
			return fmt.Sprintf("l%d+%d(FP)", idx, base), fmt.Sprintf("l%d+%d(FP)", idx, base+8)
		}
	}
	base := plan.offsets[v.ID]
	return fmt.Sprintf("%d(%s)", base, spName), fmt.Sprintf("%d(%s)", base+8, spName)
}

// trySpliceSimdCall offers the call site to the plan's SimdSplicer.
// Returns done=true when the splice replaced the CALL entirely; the
// caller then emits nothing else for this value. spName / scratchBase
// are the arch's stack-pointer spelling and callee-area base offset.
func trySpliceSimdCall(b *strings.Builder, v *ssa.Value, sp *simdCallSpec, plan *funcPlan, frame argFrame, spName string, scratchBase int) (bool, error) {
	if plan.splicer == nil {
		return false, nil
	}
	args := make([]SimdSpliceOperand, 0, len(v.Args)+1)
	if sp.withM {
		mOp := "m+0(FP)"
		if plan.mCacheReg != "" {
			mOp = plan.mCacheReg
		}
		args = append(args, SimdSpliceOperand{Type: ssa.TypeI64, IsPtr: true, Lo: mOp})
	}
	for i, arg := range v.Args {
		t := sp.args[i]
		op := SimdSpliceOperand{Type: t}
		if t == ssa.TypeV128 {
			r := resolveCopy(arg)
			if home := plan.regHome[r.ID]; strings.HasPrefix(home, "V") {
				op.Reg = home
			} else {
				op.Lo, op.Hi = v128Parts(arg, plan, frame, spName)
				if r.Op != ssa.OpParam || plan.packed {
					op.InSlot, op.SlotOff = true, plan.offsets[r.ID]
				}
			}
		} else {
			switch t {
			case ssa.TypeI32:
				if spName == "SP" {
					op.Lo = operandSrc32(arg, plan, frame, spName)
				} else {
					op.Lo = operandSrc32ARM64(arg, plan, frame)
				}
			case ssa.TypeI64:
				if spName == "SP" {
					op.Lo = operandSrc64(arg, plan, frame, spName)
				} else {
					op.Lo = operandSrc64ARM64(arg, plan, frame)
				}
			case ssa.TypeF32, ssa.TypeF64:
				op.Lo = operandSrcFloat(arg, plan, frame, spName)
			default:
				if plan.mustSplice[v.ID] {
					return false, fmt.Errorf("v%d: %s arg %d type %v not spliceable inside a register-coalesced loop", v.ID, sp.name, i, t)
				}
				return false, nil // let the CALL path report it
			}
		}
		args = append(args, op)
	}
	var ret *SimdSpliceOperand
	if sp.ret != ssa.TypeInvalid && !plan.unusedResult[v.ID] {
		if home := plan.regHome[v.ID]; sp.ret == ssa.TypeV128 && strings.HasPrefix(home, "V") {
			ret = &SimdSpliceOperand{Type: sp.ret, Reg: home}
		} else {
			dst := plan.offsets[v.ID]
			ret = &SimdSpliceOperand{
				Type:    sp.ret,
				Lo:      fmt.Sprintf("%d(%s)", dst, spName),
				Hi:      fmt.Sprintf("%d(%s)", dst+8, spName),
				InSlot:  true,
				SlotOff: dst,
			}
		}
	}
	spliced, wantsTrap := plan.splicer.Splice(b, sp.name, args, ret, scratchBase)
	if !spliced {
		if plan.mustSplice[v.ID] {
			// A CALL here would clobber the loop-carry registers the
			// coalesce reserved on the strength of this op splicing.
			return false, fmt.Errorf("v%d: %s did not splice inside a register-coalesced loop", v.ID, sp.name)
		}
		return false, nil
	}
	if wantsTrap {
		plan.wantsTrapStub = true
	}
	return true, nil
}

// simdConstAux returns the [2]uint64 lane payload of an OpSimdConst.
func simdConstAux(v *ssa.Value) ([2]uint64, error) {
	c, ok := v.Aux.([2]uint64)
	if !ok {
		return [2]uint64{}, fmt.Errorf("v%d: OpSimdConst without [2]uint64 aux", v.ID)
	}
	return c, nil
}
