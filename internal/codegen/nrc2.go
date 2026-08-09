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
// untouched.

const (
	nrc2TraitsMinRun = 16
	nrc2Q8Entry      = 8 // GGML_TYPE_Q8_0
)

// nrc2Layout is the type_traits_cpu row layout at the module's
// pointer width. ILP32 packs {u32 from_float, u32 vec_dot,
// u32 vec_dot_type, u32 pad, u64 nrows} into 24 bytes; LP64 widens
// the two function pointers to u64 (table indices zero-extended),
// giving {u64, u64, u32, u32 pad, u64} = 32 bytes.
type nrc2Layout struct {
	row      int // row stride in bytes
	vdOff    int // vec_dot field offset
	vdtOff   int // vec_dot_type field offset
	padOff   int // alignment padding field offset (must be 0)
	nrowsOff int // nrows field offset
	ptr      int // function-pointer field width in bytes
}

func nrc2LayoutFor(wide bool) nrc2Layout {
	if wide {
		return nrc2Layout{row: 32, vdOff: 8, vdtOff: 16, padOff: 20, nrowsOff: 24, ptr: 8}
	}
	return nrc2Layout{row: 24, vdOff: 4, vdtOff: 8, padOff: 12, nrowsOff: 16, ptr: 4}
}

// nrc2Ptr reads a function-pointer field: the stored value is a table
// index, so an LP64 value with nonzero high bits can never be one.
func nrc2Ptr(b []byte, l nrc2Layout) (uint32, bool) {
	if l.ptr == 8 {
		v := binary.LittleEndian.Uint64(b)
		return uint32(v), v <= 0xFFFFFFFF
	}
	return binary.LittleEndian.Uint32(b), true
}

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

// nrc2RowOK reports whether the bytes at b parse as a traits row of
// the given layout.
func nrc2RowOK(b []byte, tab map[uint32]uint32, l nrc2Layout) bool {
	ff, ffOK := nrc2Ptr(b, l)
	vd, vdOK := nrc2Ptr(b[l.vdOff:], l)
	vdt := binary.LittleEndian.Uint32(b[l.vdtOff:])
	pad := binary.LittleEndian.Uint32(b[l.padOff:])
	nrows := binary.LittleEndian.Uint64(b[l.nrowsOff:])
	if !ffOK || !vdOK || pad != 0 || nrows > 2 || vdt >= 64 {
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
	tab := nrc2TableSet(t.mod)
	if len(tab) == 0 {
		return
	}
	lay := nrc2LayoutFor(t.mod.Memory64())
	var found *nrc2Info
	for segIdx, ds := range t.mod.Datas {
		if ds.Passive || len(ds.Bytes) < lay.row {
			continue
		}
		segOff, err := evalConstExprI64(ds.Offset, t.mod)
		if err != nil {
			continue
		}
		b := ds.Bytes
		for entry := 0; entry+lay.row <= len(b); entry += 4 {
			row := b[entry:]
			vd, vdOK := nrc2Ptr(row[lay.vdOff:], lay)
			vdt := binary.LittleEndian.Uint32(row[lay.vdtOff:])
			pad := binary.LittleEndian.Uint32(row[lay.padOff:])
			nrows := binary.LittleEndian.Uint64(row[lay.nrowsOff:])
			if !vdOK || vd == 0 || vdt != nrc2Q8Entry || pad != 0 || nrows != 1 {
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
			base := addr - int64(nrc2Q8Entry*lay.row)
			if base < 0 {
				continue
			}
			img := t.nrc2ImageAt(base, nrc2TraitsMinRun*lay.row)
			okRun := true
			for k := 0; k < nrc2TraitsMinRun; k++ {
				if !nrc2RowOK(img[k*lay.row:], tab, lay) {
					okRun = false
					break
				}
			}
			if !okRun {
				continue
			}
			// Entry 0 must be the REAL F32 row — self-typed 0 with a
			// populated from_float/vec_dot pair. Requiring nonzero
			// function fields rejects the zero padding that often
			// precedes the array, which would otherwise let any
			// vdt==8 row (q4_0, q5_0, ...) pose as the q8_0 entry.
			f32ff, _ := nrc2Ptr(img, lay)
			f32vd, _ := nrc2Ptr(img[lay.vdOff:], lay)
			f32vdt := binary.LittleEndian.Uint32(img[lay.vdtOff:])
			if f32vdt != 0 || f32ff == 0 || f32vd == 0 {
				continue
			}
			fn := t.mod.Functions[funcIdx-t.mod.NumImportedFuncs]
			ft := t.mod.Types[fn.TypeIdx]
			// ggml_vec_dot_t: (n i32, s *f32, bs size_t, x *void,
			// bx size_t, y *void, by size_t, nrc i32) — pointers and
			// size_t widen to i64 on a memory64 module.
			want := []wasm.ValType{wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32}
			if t.mod.Memory64() {
				want = []wasm.ValType{wasm.ValI32, wasm.ValI64, wasm.ValI64, wasm.ValI64, wasm.ValI64, wasm.ValI64, wasm.ValI64, wasm.ValI32}
			}
			sigOK := len(ft.Params) == len(want) && len(ft.Results) == 0
			for pi, p := range ft.Params {
				sigOK = sigOK && p == want[pi]
			}
			if !sigOK {
				continue
			}
			if t.reachable != nil && !t.reachable[funcIdx-t.mod.NumImportedFuncs] {
				continue
			}
			if found != nil {
				fmt.Fprintf(os.Stderr, "wasm2go: ggml q8_0 traits row ambiguous; row/column pairing disabled\n")
				return
			}
			found = &nrc2Info{funcIdx: funcIdx, segIdx: segIdx, nrowsOff: entry + lay.nrowsOff}
		}
	}
	if found == nil {
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
		// l0 is the i32 element count; the pointer and size_t
		// parameters (l1..l6) widen to int64 on a memory64 module,
		// matching the vec_dot's own signature.
		typ := "int32"
		if t.mod.Memory64() && i >= 1 {
			typ = "int64"
		}
		params.List = append(params.List, &ast.Field{
			Names: []*ast.Ident{newID(fmt.Sprintf("l%d", i))},
			Type:  newID(typ),
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
