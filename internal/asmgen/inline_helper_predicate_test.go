package asmgen

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/ssa"
)

// TestInlineHelperPredicateMatchesEmit pins inlineHelperNamesAMD64 to
// the emitInlineHelper switch: for every registered helper name, the
// predicate must agree with what a dry-run of the emitter actually
// does. A helper added to the switch without updating the set (or
// vice versa) fails here — the set feeds the CALL-barrier analyses
// (block-local regalloc, loop-carry coalesce, m-cache refresh), so a
// drift in either direction is a silent perf or correctness hazard.
func TestInlineHelperPredicateMatchesEmit(t *testing.T) {
	synth := func(id ssa.ValueID, typ ssa.Type) *ssa.Value {
		v := &ssa.Value{ID: id, Type: typ}
		switch typ {
		case ssa.TypeI32:
			v.Op = ssa.OpConst32
			v.AuxInt = 1
		case ssa.TypeI64:
			v.Op = ssa.OpConst64
			v.AuxInt = 1
		case ssa.TypeF32:
			v.Op = ssa.OpConstF32
		case ssa.TypeF64:
			v.Op = ssa.OpConstF64
		default:
			t.Fatalf("unexpected helper param type %v", typ)
		}
		return v
	}
	for name, spec := range helperSigs {
		args := make([]*ssa.Value, len(spec.params))
		for i, pt := range spec.params {
			args[i] = synth(ssa.ValueID(i+1), pt)
		}
		retType := spec.ret
		if retType == ssa.TypeInvalid {
			retType = ssa.TypeMem
		}
		v := &ssa.Value{ID: 100, Op: ssa.OpHelperCall, Type: retType, Args: args}
		plan := &funcPlan{
			offsets: map[ssa.ValueID]int{},
			regHome: map[ssa.ValueID]string{},
		}
		var b strings.Builder
		done, err := emitInlineHelper(&b, v, plan, argFrame{}, name)
		if err != nil {
			t.Errorf("helper %q: dry-run emit error: %v", name, err)
			continue
		}
		if got := inlineHelperNamesAMD64[name]; got != done {
			t.Errorf("helper %q: inlineHelperNamesAMD64=%v but emitInlineHelper handled-inline=%v — keep the set in sync with the switch",
				name, got, done)
		}
	}
	// The inline set must not name helpers that don't exist in the
	// registry (typo guard).
	for name := range inlineHelperNamesAMD64 {
		if _, ok := helperSigs[name]; !ok {
			t.Errorf("inlineHelperNamesAMD64 names unknown helper %q", name)
		}
	}
}
