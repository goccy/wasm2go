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
	if !t.directAsmSet[ssaFn.Name] {
		return
	}
	if t.directAsmSSA == nil {
		t.directAsmSSA = map[string]DirectAsmFn{}
	}
	t.directAsmSSA[ssaFn.Name] = DirectAsmFn{Fn: ssaFn, Sig: sig}
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
