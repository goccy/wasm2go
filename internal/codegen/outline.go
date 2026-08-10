package codegen

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/wasm"
)

// OutlinedSig is an extracted function's signature in wasm value
// types, for the asm bundle to transform its body like a regular
// translated function.
type OutlinedSig struct {
	Params []wasm.ValType
	Result *wasm.ValType // nil when the function returns nothing
	// Packed: the boundary exceeds the register ABI, so the caller
	// passes one pointer to a [len(Params)]uint64 slot array instead
	// of individual scalar arguments.
	Packed bool
}

// ssaValType maps the scalar SSA types an outline boundary may carry.
func ssaValType(t ssa.Type) (wasm.ValType, bool) {
	switch t {
	case ssa.TypeI32:
		return wasm.ValI32, true
	case ssa.TypeI64:
		return wasm.ValI64, true
	case ssa.TypeF32:
		return wasm.ValF32, true
	case ssa.TypeF64:
		return wasm.ValF64, true
	case ssa.TypeV128:
		return wasm.ValV128, true
	}
	return 0, false
}

// Loop-outlining integration (see internal/ssa/outline.go for the
// extraction itself). Gated by Options.OutlineMinValues: 0 disables;
// otherwise the minimum loop body size in SSA values.

// maybeOutline extracts eligible loops of ssaFn, queueing the new
// functions for emission next to their parent.
func (t *translator) maybeOutline(ssaFn *ssa.Func) error {
	min := t.opts.OutlineMinValues
	if min <= 0 {
		return nil
	}
	outs, err := ssa.OutlineLoops(ssaFn, func(h ssa.BlockID) string {
		return fmt.Sprintf("%sl%d", ssaFn.Name, h)
	}, min, t.mod.Memory64())
	if err != nil {
		return err
	}
	t.pendingOutlined = append(t.pendingOutlined, outs...)
	for _, of := range outs {
		g := of.Fn
		if t.outlinedByChunk == nil {
			t.outlinedByChunk = map[string][]string{}
		}
		rel := ""
		if t.multiPackage && t.plan != nil {
			if c, ok := t.plan.FuncToChunk[t.curOutlineFunc]; ok {
				rel = fmt.Sprintf("p%d", c)
			}
		}
		t.outlinedByChunk[rel] = append(t.outlinedByChunk[rel], g.Name)
		sig := OutlinedSig{}
		for _, p := range g.Sig.Params {
			vt, ok := ssaValType(p)
			if !ok {
				return fmt.Errorf("outlined %s: non-scalar param type %v", g.Name, p)
			}
			sig.Params = append(sig.Params, vt)
		}
		if len(g.Sig.Results) == 1 {
			vt, ok := ssaValType(g.Sig.Results[0])
			if !ok {
				return fmt.Errorf("outlined %s: non-scalar result type %v", g.Name, g.Sig.Results[0])
			}
			sig.Result = &vt
		}
		sig.Packed = of.Packed
		if t.outlinedSigs == nil {
			t.outlinedSigs = map[string]OutlinedSig{}
		}
		t.outlinedSigs[g.Name] = sig
	}
	return nil
}

// emitOutlinedDecls lowers every queued extracted function into a Go
// func decl. Called by emitOneDefinedFunction right after the parent,
// so the definitions land in the same chunk.
func (t *translator) emitOutlinedDecls() ([]ast.Decl, error) {
	if len(t.pendingOutlined) == 0 {
		return nil, nil
	}
	var out []ast.Decl
	for _, of := range t.pendingOutlined {
		g := of.Fn
		// Direct-asm retention. Unpacked scalar boundaries carry the
		// synthetic signature; packed boundaries retain results-only
		// plus the parameter types for the pack prologue.
		if of.Packed {
			t.retainDirectAsmPacked(g)
		} else if ft, ok := outlinedWasmSig(g.Sig); ok {
			t.retainDirectAsm(g, ft)
		}
		em := newSSAEmitter(t)
		if of.Packed {
			// Prologue goes through the emitter pre-scalarize so v128
			// params become pair variables the splices recognize.
			var pro []ast.Stmt
			slot := 0
			for i, p := range g.Sig.Params {
				if p == ssa.TypeV128 {
					pro = append(pro, &ast.AssignStmt{
						Tok: token.DEFINE,
						Lhs: []ast.Expr{newID(fmt.Sprintf("l%d", i))},
						Rhs: []ast.Expr{&ast.CompositeLit{
							Type: &ast.ArrayType{
								Len: &ast.BasicLit{Kind: token.INT, Value: "2"},
								Elt: newID("uint64"),
							},
							Elts: []ast.Expr{t.packSlot(slot), t.packSlot(slot + 1)},
						}},
					})
					slot += 2
					continue
				}
				pro = append(pro, &ast.AssignStmt{
					Tok: token.DEFINE,
					Lhs: []ast.Expr{newID(fmt.Sprintf("l%d", i))},
					Rhs: []ast.Expr{t.packSlotRead(slot, p)},
				})
				slot++
			}
			em.packedPrologue = pro
		}
		body, err := em.emitFuncBody(g)
		if err != nil {
			return nil, fmt.Errorf("outlined %s: %w", g.Name, err)
		}
		ftype := outlinedFuncSig(t, g.Sig)
		if of.Packed {
			ftype.Params = &ast.FieldList{List: []*ast.Field{
				{Names: []*ast.Ident{newID("m")}, Type: t.moduleType()},
			}}
		}
		out = append(out, &ast.FuncDecl{
			Name: newID(g.Name),
			Type: ftype,
			Body: body,
		})
	}
	t.pendingOutlined = nil
	return out, nil
}

// packSlot is m.<outlinePack>[i], the per-module boundary scratch.
func (t *translator) packSlot(i int) ast.Expr {
	return &ast.IndexExpr{
		X:     &ast.SelectorExpr{X: newID("m"), Sel: newID(t.fieldName("outlinePack"))},
		Index: &ast.BasicLit{Kind: token.INT, Value: strconv.Itoa(i)},
	}
}

// packSlotRead unpacks slot i into the parameter's type. Floats round-
// trip through the wasm reinterpret helpers so no new imports appear in
// chunk files.
func (t *translator) packSlotRead(i int, typ ssa.Type) ast.Expr {
	slot := t.packSlot(i)
	u32 := func(e ast.Expr) ast.Expr {
		return &ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{e}}
	}
	switch typ {
	case ssa.TypeI32:
		return &ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{u32(slot)}}
	case ssa.TypeI64:
		return &ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{slot}}
	case ssa.TypeF32:
		return &ast.CallExpr{Fun: t.helperRef("f32_reinterpret_i32"),
			Args: []ast.Expr{&ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{u32(slot)}}}}
	default: // f64
		return &ast.CallExpr{Fun: t.helperRef("f64_reinterpret_i64"),
			Args: []ast.Expr{&ast.CallExpr{Fun: newID("int64"), Args: []ast.Expr{slot}}}}
	}
}

// packSlotWrite converts a boundary value into its uint64 slot form.
func (t *translator) packSlotWrite(arg ast.Expr, typ ssa.Type) ast.Expr {
	u64 := func(e ast.Expr) ast.Expr {
		return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{e}}
	}
	u32 := func(e ast.Expr) ast.Expr {
		return &ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{e}}
	}
	switch typ {
	case ssa.TypeI32:
		return u64(u32(arg))
	case ssa.TypeI64:
		return u64(arg)
	case ssa.TypeF32:
		return u64(u32(&ast.CallExpr{Fun: t.helperRef("i32_reinterpret_f32"), Args: []ast.Expr{arg}}))
	default: // f64
		return u64(&ast.CallExpr{Fun: t.helperRef("i64_reinterpret_f64"), Args: []ast.Expr{arg}})
	}
}

// outlinedFuncSig builds `func(m *Module, l0 T0, ...) (r0 R)` from an
// SSA signature (parameter names match the OpParam emission).
func outlinedFuncSig(t *translator, sig ssa.FuncSig) *ast.FuncType {
	params := []*ast.Field{{Names: []*ast.Ident{newID("m")}, Type: t.moduleType()}}
	for i, p := range sig.Params {
		params = append(params, &ast.Field{
			Names: []*ast.Ident{newID(fmt.Sprintf("l%d", i))},
			Type:  goTypeForSSAType(p),
		})
	}
	ft := &ast.FuncType{Params: &ast.FieldList{List: params}}
	if len(sig.Results) > 0 {
		ft.Results = &ast.FieldList{List: []*ast.Field{{
			Names: []*ast.Ident{newID("r0")},
			Type:  goTypeForSSAType(sig.Results[0]),
		}}}
	}
	return ft
}
