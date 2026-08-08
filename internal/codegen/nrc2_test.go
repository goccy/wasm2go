package codegen

import (
	"bytes"
	"encoding/binary"
	"go/printer"
	"go/token"
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// nrc2TestModule builds a module holding a plausible ggml
// type_traits_cpu array: 16 rows, the q8_0 entry (index 8) self-typed
// with a defined vec_dot of the ggml_vec_dot_t shape.
func nrc2TestModule(t *testing.T, mutate func(rows []byte)) *wasm.Module {
	t.Helper()
	rows := make([]byte, 16*nrc2TraitsRowSize)
	putRow := func(idx int, ff, vd, vdt uint32, nrows uint64) {
		off := idx * nrc2TraitsRowSize
		binary.LittleEndian.PutUint32(rows[off:], ff)
		binary.LittleEndian.PutUint32(rows[off+4:], vd)
		binary.LittleEndian.PutUint32(rows[off+8:], vdt)
		binary.LittleEndian.PutUint64(rows[off+16:], nrows)
	}
	// F32 (self-typed 0), a few quant rows, q8_0 at index 8.
	putRow(0, 10, 11, 0, 1)
	putRow(2, 12, 13, 8, 1)
	putRow(6, 14, 15, 8, 1)
	putRow(8, 16, 17, 8, 1)
	putRow(9, 18, 19, 9, 1)
	if mutate != nil {
		mutate(rows)
	}
	vecDotType := wasm.FuncType{Params: []wasm.ValType{
		wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32,
		wasm.ValI32, wasm.ValI32, wasm.ValI32, wasm.ValI32,
	}}
	m := &wasm.Module{
		Types:     []wasm.FuncType{vecDotType},
		Functions: make([]wasm.Function, 30),
		Datas: []wasm.DataSegment{
			{Offset: i32ConstExpr(4096), Bytes: rows},
		},
		Elements: []wasm.ElementSegment{
			{Offset: i32ConstExpr(0), FuncIdxs: func() []uint32 {
				idxs := make([]uint32, 30)
				for i := range idxs {
					idxs[i] = uint32(i)
				}
				return idxs
			}()},
		},
	}
	return m
}

func TestScanGgmlNrc2Accepts(t *testing.T) {
	m := nrc2TestModule(t, nil)
	tr := &translator{mod: m}
	tr.scanGgmlNrc2()
	if tr.nrc2 == nil {
		t.Fatal("traits array not recognized")
	}
	if tr.nrc2.funcIdx != 17 {
		t.Fatalf("vec_dot func = %d, want 17", tr.nrc2.funcIdx)
	}
	if tr.nrc2.nrowsOff != 8*nrc2TraitsRowSize+16 {
		t.Fatalf("nrows offset = %d", tr.nrc2.nrowsOff)
	}
	// The patch flows only into the recognized segment, as a copy.
	orig := m.Datas[0].Bytes
	patched := tr.nrc2SegBytes(0, orig)
	if binary.LittleEndian.Uint64(patched[tr.nrc2.nrowsOff:]) != 2 {
		t.Fatal("nrows not patched")
	}
	if binary.LittleEndian.Uint64(orig[tr.nrc2.nrowsOff:]) != 1 {
		t.Fatal("original bytes mutated")
	}
	if got := tr.nrc2SegBytes(1, orig); &got[0] != &orig[0] {
		t.Fatal("unrelated segment copied")
	}
}

func TestScanGgmlNrc2Rejections(t *testing.T) {
	cases := map[string]func(rows []byte){
		"nrows already 2": func(rows []byte) {
			binary.LittleEndian.PutUint64(rows[8*nrc2TraitsRowSize+16:], 2)
		},
		"entry0 not F32-typed": func(rows []byte) {
			binary.LittleEndian.PutUint32(rows[8:], 3)
		},
		"vec_dot table index invalid": func(rows []byte) {
			binary.LittleEndian.PutUint32(rows[8*nrc2TraitsRowSize+4:], 999)
		},
		"pad nonzero": func(rows []byte) {
			binary.LittleEndian.PutUint32(rows[8*nrc2TraitsRowSize+12:], 7)
		},
	}
	for name, mutate := range cases {
		tr := &translator{mod: nrc2TestModule(t, mutate)}
		tr.scanGgmlNrc2()
		if tr.nrc2 != nil {
			t.Errorf("%s: unexpectedly recognized", name)
		}
	}
}

func TestScanGgmlNrc2KillSwitch(t *testing.T) {
	t.Setenv("WASM2GO_NO_NRC2", "1")
	tr := &translator{mod: nrc2TestModule(t, nil)}
	tr.scanGgmlNrc2()
	if tr.nrc2 != nil {
		t.Fatal("kill switch ignored")
	}
}

func TestScanGgmlNrc2WrongSignature(t *testing.T) {
	m := nrc2TestModule(t, nil)
	m.Types = append(m.Types, wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}})
	m.Functions[17].TypeIdx = 1
	tr := &translator{mod: m}
	tr.scanGgmlNrc2()
	if tr.nrc2 != nil {
		t.Fatal("wrong-signature vec_dot accepted")
	}
}

func TestNrc2CompanionShape(t *testing.T) {
	tr := &translator{mod: nrc2TestModule(t, nil)}
	tr.scanGgmlNrc2()
	if tr.nrc2 == nil {
		t.Fatal("not recognized")
	}
	var b bytes.Buffer
	if err := printer.Fprint(&b, token.NewFileSet(), tr.nrc2Companion()); err != nil {
		t.Fatal(err)
	}
	src := b.String()
	name := tr.funcName(tr.nrc2.funcIdx)
	// Four tile calls with nrc pinned to 1 and the documented
	// destination/pointer offsets.
	for _, want := range []string{
		name + "(m, l0, l1, 0, l3, 0, l5, 0, 1)",
		name + "(m, l0, l1+4, 0, l3+l4, 0, l5, 0, 1)",
		name + "(m, l0, l1+4*(l2+0), 0, l3, 0, l5+l6, 0, 1)",
		name + "(m, l0, l1+4*(l2+1), 0, l3+l4, 0, l5+l6, 0, 1)",
	} {
		if !bytes.Contains([]byte(src), []byte(want)) {
			t.Errorf("companion missing call %q:\n%s", want, src)
		}
	}
	var pb bytes.Buffer
	if err := printer.Fprint(&pb, token.NewFileSet(), tr.nrc2Prelude()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pb.Bytes(), []byte("if l7 == 2 {")) {
		t.Errorf("prelude shape:\n%s", pb.String())
	}
}
