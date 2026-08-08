package codegen

import (
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/token"
	"os"

	"github.com/goccy/wasm2go/internal/wasm"
)

// ggml pairs matmul rows and columns when a quant type's
// type_traits_cpu entry declares nrows == 2: the generic driver loop
// steps both the row and column indices by two, passes the row/column
// strides through the vec_dot bs/bx/by arguments, and falls back to
// nrows == 1 for odd shapes. The wasm build compiles all of that
// machinery in but pins nrows to 1 (the 2-row kernels are gated on
// __ARM_FEATURE_MATMUL_INT8, absent on wasm).
//
// wasm2go re-enables the pairing for the q8_0 self-dot WITHOUT
// touching the wasm: the emitted data image gets nrows = 2, the
// vec_dot function gets an nrc == 2 prelude, and a companion function
// computes the 2x2 tile as four nrc == 1 calls — bit-exact with the
// unpaired semantics on every backend (the arm64 fast-math bundle
// replaces the companion's body with the SMMLA tile kernel). The
// engine executing the SAME wasm under a wasm VM keeps nrows == 1;
// only this transpiler's output takes the paired path.
//
// Recognition is structural, not nominal: the type_traits_cpu array
// is located as a maximal run of parseable 24-byte rows
//
//	{ u32 from_float, u32 vec_dot, u32 vec_dot_type, u32 pad == 0,
//	  u64 nrows <= 2 }
//
// whose function fields are 0 or valid indirect-table indices, and
// the q8_0 entry is the run's index GGML_TYPE_Q8_0 == 8 (a stable
// public ggml ABI value), self-typed (vec_dot_type == 8), unpaired
// (nrows == 1), with a defined vec_dot of the ggml_vec_dot_t shape
// (eight i32 parameters, no results). Any mismatch leaves the module
// untouched. WASM2GO_NO_NRC2 is the kill switch.

const (
	nrc2TraitsRowSize = 24
	nrc2TraitsMinRun  = 16
	nrc2Q8Entry       = 8 // GGML_TYPE_Q8_0
)

// nrc2Info records a verified q8_0 traits entry.
type nrc2Info struct {
	funcIdx  uint32 // the q8_0 vec_dot (module function index)
	segIdx   int    // data segment holding the traits array
	nrowsOff int    // byte offset of the entry's nrows field in the segment
}

// nrc2TableSet returns the set of valid indirect-table element
// indices mapped to their function indices.
func nrc2TableSet(m *wasm.Module) map[uint32]uint32 {
	tab := map[uint32]uint32{}
	for _, es := range m.Elements {
		off, err := evalConstExprI64(es.Offset, m)
		if err != nil {
			continue
		}
		for i, f := range es.FuncIdxs {
			tab[uint32(off)+uint32(i)] = f
		}
	}
	return tab
}

// nrc2RowOK reports whether the 24 bytes at b parse as a traits row.
func nrc2RowOK(b []byte, tab map[uint32]uint32) bool {
	ff := binary.LittleEndian.Uint32(b)
	vd := binary.LittleEndian.Uint32(b[4:])
	vdt := binary.LittleEndian.Uint32(b[8:])
	pad := binary.LittleEndian.Uint32(b[12:])
	nrows := binary.LittleEndian.Uint64(b[16:])
	if pad != 0 || nrows > 2 || vdt >= 64 {
		return false
	}
	if ff != 0 {
		if _, ok := tab[ff]; !ok {
			return false
		}
	}
	if vd != 0 {
		if _, ok := tab[vd]; !ok {
			return false
		}
	}
	return true
}

// scanGgmlNrc2 locates the traits array and verifies the q8_0 entry.
// The scan anchors on candidate ENTRIES (a self-typed q8 row) rather
// than on the array base — zero padding parses as a valid row, so run
// starts are ambiguous — and then verifies the enum neighborhood:
// entries 0..15 around the candidate must all parse and entry 0 (F32)
// must be self-typed 0. Exactly one candidate may survive; ambiguity
// leaves the feature off. On success t.nrc2 is set.
func (t *translator) scanGgmlNrc2() {
	if os.Getenv("WASM2GO_NO_NRC2") != "" {
		return
	}
	debug := os.Getenv("WASM2GO_NRC2_DEBUG") != ""
	tab := nrc2TableSet(t.mod)
	if len(tab) == 0 {
		return
	}
	var found *nrc2Info
	for segIdx, ds := range t.mod.Datas {
		if ds.Passive || len(ds.Bytes) < nrc2TraitsRowSize {
			continue
		}
		segOff, err := evalConstExprI64(ds.Offset, t.mod)
		if err != nil {
			continue
		}
		b := ds.Bytes
		for entry := 0; entry+nrc2TraitsRowSize <= len(b); entry += 4 {
			row := b[entry:]
			vd := binary.LittleEndian.Uint32(row[4:])
			vdt := binary.LittleEndian.Uint32(row[8:])
			pad := binary.LittleEndian.Uint32(row[12:])
			nrows := binary.LittleEndian.Uint64(row[16:])
			if vd == 0 || vdt != nrc2Q8Entry || pad != 0 || nrows != 1 {
				continue
			}
			funcIdx, ok := tab[vd]
			if !ok || funcIdx < t.mod.NumImportedFuncs {
				continue
			}
			// Enum neighborhood: entries 0..15 of the array around the
			// candidate must all parse and the F32 entry (index 0) is
			// self-typed 0. The array commonly SPANS segments (zero
			// rows become segment gaps), so assemble the neighborhood
			// from the initial memory image; uncovered bytes default
			// to zero, which parses as an empty row — exactly the
			// removed-type rows ggml leaves zeroed.
			addr := segOff + int64(entry)
			base := addr - nrc2Q8Entry*nrc2TraitsRowSize
			if base < 0 {
				continue
			}
			img := t.nrc2ImageAt(base, nrc2TraitsMinRun*nrc2TraitsRowSize)
			okRun := true
			for k := 0; k < nrc2TraitsMinRun; k++ {
				if !nrc2RowOK(img[k*nrc2TraitsRowSize:], tab) {
					okRun = false
					break
				}
			}
			if !okRun {
				if debug {
					fmt.Fprintf(os.Stderr, "wasm2go: nrc2 candidate at seg %d +%d: neighborhood parse failed\n", segIdx, entry)
				}
				continue
			}
			// Entry 0 must be the REAL F32 row — self-typed 0 with a
			// populated from_float/vec_dot pair. Requiring nonzero
			// function fields rejects the zero padding that often
			// precedes the array, which would otherwise let any
			// vdt==8 row (q4_0, q5_0, ...) pose as the q8_0 entry.
			f32ff := binary.LittleEndian.Uint32(img)
			f32vd := binary.LittleEndian.Uint32(img[4:])
			f32vdt := binary.LittleEndian.Uint32(img[8:])
			if f32vdt != 0 || f32ff == 0 || f32vd == 0 {
				if debug {
					fmt.Fprintf(os.Stderr, "wasm2go: nrc2 candidate at seg %d +%d: entry0 not the F32 row (ff=%d vd=%d vdt=%d)\n",
						segIdx, entry, f32ff, f32vd, f32vdt)
				}
				continue
			}
			fn := t.mod.Functions[funcIdx-t.mod.NumImportedFuncs]
			ft := t.mod.Types[fn.TypeIdx]
			sigOK := len(ft.Params) == 8 && len(ft.Results) == 0
			for _, p := range ft.Params {
				sigOK = sigOK && p == wasm.ValI32
			}
			if !sigOK {
				if debug {
					fmt.Fprintf(os.Stderr, "wasm2go: nrc2 candidate at seg %d +%d: vec_dot signature mismatch\n", segIdx, entry)
				}
				continue
			}
			if t.reachable != nil && !t.reachable[funcIdx-t.mod.NumImportedFuncs] {
				if debug {
					fmt.Fprintf(os.Stderr, "wasm2go: nrc2 candidate at seg %d +%d: vec_dot unreachable\n", segIdx, entry)
				}
				continue
			}
			if found != nil {
				fmt.Fprintf(os.Stderr, "wasm2go: ggml q8_0 traits row ambiguous; row/column pairing disabled\n")
				return
			}
			found = &nrc2Info{funcIdx: funcIdx, segIdx: segIdx, nrowsOff: entry + 16}
		}
	}
	if found == nil {
		if debug {
			fmt.Fprintf(os.Stderr, "wasm2go: no ggml q8_0 traits row found\n")
		}
		return
	}
	t.nrc2 = found
	fmt.Fprintf(os.Stderr, "wasm2go: ggml q8_0 vec_dot row/column pairing enabled (%s, traits nrows -> 2)\n",
		t.funcName(found.funcIdx))
}

// nrc2ImageAt assembles n bytes of the initial memory image starting
// at addr from the active data segments; uncovered bytes are zero.
func (t *translator) nrc2ImageAt(addr int64, n int) []byte {
	img := make([]byte, n)
	for _, ds := range t.mod.Datas {
		if ds.Passive {
			continue
		}
		off, err := evalConstExprI64(ds.Offset, t.mod)
		if err != nil {
			continue
		}
		segEnd := off + int64(len(ds.Bytes))
		lo, hi := addr, addr+int64(n)
		if segEnd <= lo || off >= hi {
			continue
		}
		s, e := max64(off, lo), min64(segEnd, hi)
		copy(img[s-lo:e-lo], ds.Bytes[s-off:e-off])
	}
	return img
}

// nrc2SegBytes returns the segment's bytes with the traits patch
// applied when segIdx is the recognized traits segment; the input is
// never mutated.
func (t *translator) nrc2SegBytes(segIdx int, b []byte) []byte {
	if t.nrc2 == nil || t.nrc2.segIdx != segIdx {
		return b
	}
	out := make([]byte, len(b))
	copy(out, b)
	binary.LittleEndian.PutUint64(out[t.nrc2.nrowsOff:], 2)
	return out
}

// nrc2CompanionName is the companion function's Go identifier.
func (t *translator) nrc2CompanionName() string {
	return t.funcName(t.nrc2.funcIdx) + "nrc2"
}

// nrc2Prelude is the statement prepended to the vec_dot body:
//
//	if l7 == 2 { fnNnrc2(m, l0, l1, l2, l3, l4, l5, l6); return }
func (t *translator) nrc2Prelude() ast.Stmt {
	args := []ast.Expr{newID("m")}
	for i := 0; i < 7; i++ {
		args = append(args, newID(fmt.Sprintf("l%d", i)))
	}
	return &ast.IfStmt{
		Cond: &ast.BinaryExpr{X: newID("l7"), Op: token.EQL, Y: intLit(2)},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: &ast.CallExpr{Fun: newID(t.nrc2CompanionName()), Args: args}},
			&ast.ReturnStmt{},
		}},
	}
}

// nrc2Companion emits the paired-tile companion:
//
//	func fnNnrc2(m *Module, l0, l1, l2, l3, l4, l5, l6 int32) {
//	    fnN(m, l0, l1+4*(j*l2+i), 0, l3+i*l4, 0, l5+j*l6, 0, 1) ...
//	}
//
// Four nrc == 1 calls covering rows i and columns j of the 2x2 tile —
// arithmetic identical to the unpaired path, so every backend is
// correct; the arm64 fast-math bundle swaps this body for the SMMLA
// tile kernel.
func (t *translator) nrc2Companion() *ast.FuncDecl {
	params := &ast.FieldList{List: []*ast.Field{{Names: []*ast.Ident{newID("m")}, Type: t.moduleType()}}}
	for i := 0; i < 7; i++ {
		params.List = append(params.List, &ast.Field{
			Names: []*ast.Ident{newID(fmt.Sprintf("l%d", i))},
			Type:  newID("int32"),
		})
	}
	add := func(x ast.Expr, y ast.Expr) ast.Expr {
		return &ast.BinaryExpr{X: x, Op: token.ADD, Y: y}
	}
	mul := func(x ast.Expr, y ast.Expr) ast.Expr {
		return &ast.BinaryExpr{X: x, Op: token.MUL, Y: y}
	}
	var body []ast.Stmt
	for j := 0; j < 2; j++ { // column
		for i := 0; i < 2; i++ { // row
			s := ast.Expr(newID("l1"))
			// s' = s + 4*(j*bs + i) — bs is in floats, s in bytes.
			if j == 1 {
				s = add(s, mul(intLit(4), add(newID("l2"), intLit(int64(i)))))
			} else if i == 1 {
				s = add(s, intLit(4))
			}
			x := ast.Expr(newID("l3"))
			if i == 1 {
				x = add(x, newID("l4"))
			}
			y := ast.Expr(newID("l5"))
			if j == 1 {
				y = add(y, newID("l6"))
			}
			body = append(body, &ast.ExprStmt{X: &ast.CallExpr{
				Fun: newID(t.funcName(t.nrc2.funcIdx)),
				Args: []ast.Expr{
					newID("m"), newID("l0"), s, intLit(0), x, intLit(0), y, intLit(0), intLit(1),
				},
			}})
		}
	}
	return &ast.FuncDecl{
		Name: newID(t.nrc2CompanionName()),
		Type: &ast.FuncType{Params: params},
		Body: &ast.BlockStmt{List: body},
	}
}
