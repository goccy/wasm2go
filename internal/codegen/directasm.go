package codegen

import (
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// Direct-asm retention (see Options.DirectAsmFuncs). The translator
// keeps the finalized SSA of opted-in functions so the asm bundle can
// emit their bodies straight from SSA via internal/asmgen instead of
// transforming the gc-captured listing. Retention is bookkeeping only
// — the pure-Go body is still emitted for every function, and the
// bundle decides per function (and falls back to the listing
// transform) at build time.

// retainDirectAsm records ssaFn under its name when the name was
// opted in. sig is the function's signature in wasm value types — for
// FnN functions the module's own type, for outlined functions the
// synthetic boundary signature.
func (t *translator) retainDirectAsm(ssaFn *ssa.Func, sig wasm.FuncType) {
	t.retainDirectAsmFn(ssaFn.Name, DirectAsmFn{Fn: ssaFn, Sig: sig})
}

// retainDirectAsmPacked is the packed-boundary variant: the wasm sig
// is results-only (the caller passes just m) and the parameter types
// ride along for the pack prologue. A boundary type outside the
// scalar/v128 set is not retainable.
func (t *translator) retainDirectAsmPacked(ssaFn *ssa.Func) {
	if !t.directAsmSet[ssaFn.Name] {
		return
	}
	var ft wasm.FuncType
	for _, r := range ssaFn.Sig.Results {
		vt, ok := ssaValType(r)
		if !ok || vt == wasm.ValV128 {
			return
		}
		ft.Results = append(ft.Results, vt)
	}
	for _, p := range ssaFn.Sig.Params {
		switch p {
		case ssa.TypeI32, ssa.TypeI64, ssa.TypeF32, ssa.TypeF64, ssa.TypeV128:
		default:
			return
		}
	}
	t.retainDirectAsmFn(ssaFn.Name, DirectAsmFn{
		Fn:           ssaFn,
		Sig:          ft,
		Packed:       true,
		PackedParams: append([]ssa.Type(nil), ssaFn.Sig.Params...),
	})
}

func (t *translator) retainDirectAsmFn(name string, df DirectAsmFn) {
	if !t.directAsmSet[name] {
		return
	}
	if t.directAsmSSA == nil {
		t.directAsmSSA = map[string]DirectAsmFn{}
	}
	t.directAsmSSA[name] = df
}

// outlinedWasmSig converts an outlined function's SSA signature into
// wasm value types. Returns false when a boundary type has no scalar
// wasm equivalent the asm frame layout can carry (v128 boundaries ride
// the packed pointer form instead, which direct-asm does not emit).
func outlinedWasmSig(sig ssa.FuncSig) (wasm.FuncType, bool) {
	var ft wasm.FuncType
	for _, p := range sig.Params {
		vt, ok := ssaValType(p)
		if !ok || vt == wasm.ValV128 {
			return wasm.FuncType{}, false
		}
		ft.Params = append(ft.Params, vt)
	}
	for _, r := range sig.Results {
		vt, ok := ssaValType(r)
		if !ok || vt == wasm.ValV128 {
			return wasm.FuncType{}, false
		}
		ft.Results = append(ft.Results, vt)
	}
	return ft, true
}
