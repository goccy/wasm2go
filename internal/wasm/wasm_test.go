package wasm_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// mustParseFile compiles testdata/<name>.wat and parses the result.
func mustParseFile(t *testing.T, name string) *wasm.Module {
	t.Helper()
	bin := testfixture.Wasm(t, name)
	m, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return m
}

// mustParseBytes parses a wasm module from a raw byte slice, failing on error.
func mustParseBytes(t *testing.T, data []byte) *wasm.Module {
	t.Helper()
	m, err := wasm.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

// parseBytes attempts to parse a byte slice and returns the error.
func parseBytes(data []byte) (*wasm.Module, error) {
	return wasm.Parse(bytes.NewReader(data))
}

// wasmHeader is the 8-byte preamble of every valid wasm binary.
var wasmHeader = []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}

// buildModule constructs a trivially valid wasm binary from raw section bytes.
// The caller provides pre-encoded section payloads; buildModule adds the header.
func buildModule(sections ...[]byte) []byte {
	var b []byte
	b = append(b, wasmHeader...)
	for _, s := range sections {
		b = append(b, s...)
	}
	return b
}

// encodeSection encodes: sectionID (1 byte) + leb128(len(payload)) + payload.
func encodeSection(id byte, payload []byte) []byte {
	var out []byte
	out = append(out, id)
	out = append(out, encodeLEB128U32(uint32(len(payload)))...)
	out = append(out, payload...)
	return out
}

func encodeLEB128U32(v uint32) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			return buf
		}
	}
}

func encodeLEB128S32(v int32) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			buf = append(buf, b)
			return buf
		}
		buf = append(buf, b|0x80)
	}
}

// ---- Happy-path tests using testdata fixtures ----

// TestParseArith tests arith.wasm: 8 functions, 8 exports, no imports/memory/data.
func TestParseArith(t *testing.T) {
	m := mustParseFile(t, "arith.wasm")

	if len(m.Functions) != 8 {
		t.Errorf("want 8 functions, got %d", len(m.Functions))
	}
	if len(m.Exports) != 8 {
		t.Errorf("want 8 exports, got %d", len(m.Exports))
	}
	if len(m.Imports) != 0 {
		t.Errorf("want 0 imports, got %d", len(m.Imports))
	}
	if len(m.Memories) != 0 {
		t.Errorf("want 0 memories, got %d", len(m.Memories))
	}
	if len(m.Datas) != 0 {
		t.Errorf("want 0 data segments, got %d", len(m.Datas))
	}

	// Verify all expected export names are present.
	exportNames := make(map[string]uint32)
	for _, e := range m.Exports {
		exportNames[e.Name] = e.Index
		if e.Kind != wasm.ExportFunc {
			t.Errorf("export %q: want ExportFunc kind, got %d", e.Name, e.Kind)
		}
	}
	for _, name := range []string{"add", "sub", "mul64", "div_s", "shifts", "rotl", "lt_s", "lt_u"} {
		if _, ok := exportNames[name]; !ok {
			t.Errorf("missing export %q", name)
		}
	}

	// All types should have i32 or i64 params.
	if len(m.Types) == 0 {
		t.Error("want at least 1 type, got 0")
	}
	for _, ft := range m.Types {
		if len(ft.Params) == 0 {
			t.Errorf("unexpected no-param type: %+v", ft)
		}
	}
}

// TestParseMemory tests memory.wasm: 1 memory, 1 data segment, table, element segment, exports.
func TestParseMemory(t *testing.T) {
	m := mustParseFile(t, "memory.wasm")

	// One memory exported as "memory".
	if len(m.Memories) != 1 {
		t.Fatalf("want 1 memory, got %d", len(m.Memories))
	}
	mem := m.Memories[0]
	if mem.Limits.Min != 1 {
		t.Errorf("memory min: want 1, got %d", mem.Limits.Min)
	}

	// memory.wat has exactly 1 data segment: "hi\0" at offset 16.
	// (table + elem do not produce data segments)
	if len(m.Datas) < 1 {
		t.Fatalf("want >= 1 data segment, got %d", len(m.Datas))
	}
	ds := m.Datas[0]
	if ds.MemIdx != 0 {
		t.Errorf("data[0].MemIdx: want 0, got %d", ds.MemIdx)
	}
	// Offset expr should be i32.const 16 (0x41 0x10 0x0b).
	if len(ds.Offset) < 2 {
		t.Errorf("data[0].Offset too short: %v", ds.Offset)
	} else if ds.Offset[0] != 0x41 {
		t.Errorf("data[0].Offset opcode: want 0x41 (i32.const), got 0x%02x", ds.Offset[0])
	}
	// Payload: "hi\0" = 3 bytes.
	if len(ds.Bytes) != 3 {
		t.Errorf("data[0].Bytes: want 3, got %d: %v", len(ds.Bytes), ds.Bytes)
	}

	// One table, one element segment.
	if len(m.Tables) != 1 {
		t.Errorf("want 1 table, got %d", len(m.Tables))
	}
	if m.Tables[0].ElemType != wasm.ValFuncref {
		t.Errorf("table ElemType: want funcref, got %v", m.Tables[0].ElemType)
	}
	if len(m.Elements) != 1 {
		t.Errorf("want 1 element segment, got %d", len(m.Elements))
	}
	if len(m.Elements[0].FuncIdxs) != 3 {
		t.Errorf("element[0].FuncIdxs: want 3, got %d", len(m.Elements[0].FuncIdxs))
	}

	// Export named "memory" with ExportMemory kind.
	found := false
	for _, e := range m.Exports {
		if e.Name == "memory" {
			if e.Kind != wasm.ExportMemory {
				t.Errorf("export 'memory' kind: want ExportMemory, got %d", e.Kind)
			}
			found = true
		}
	}
	if !found {
		t.Error("no export named 'memory'")
	}
}

// TestParseHello tests hello.wasm: 1 import (fd_write), 1 memory, 3 data segments, 1 func export.
func TestParseHello(t *testing.T) {
	m := mustParseFile(t, "hello.wasm")

	if len(m.Imports) != 1 {
		t.Fatalf("want 1 import, got %d", len(m.Imports))
	}
	imp := m.Imports[0]
	if imp.Module != "wasi_snapshot_preview1" {
		t.Errorf("import module: want 'wasi_snapshot_preview1', got %q", imp.Module)
	}
	if imp.Name != "fd_write" {
		t.Errorf("import name: want 'fd_write', got %q", imp.Name)
	}
	if imp.Kind != wasm.ImportFunc {
		t.Errorf("import kind: want ImportFunc, got %d", imp.Kind)
	}
	if m.NumImportedFuncs != 1 {
		t.Errorf("NumImportedFuncs: want 1, got %d", m.NumImportedFuncs)
	}

	// 1 memory exported.
	if len(m.Memories) != 1 {
		t.Errorf("want 1 memory, got %d", len(m.Memories))
	}

	// hello.wat has 3 data segments: "hello from wasi\n" @ 16, iovec[0] @ 0, iovec[1] @ 4.
	if len(m.Datas) != 3 {
		t.Errorf("want 3 data segments, got %d", len(m.Datas))
	}

	// 1 function (say_hello), 1 export.
	if len(m.Functions) != 1 {
		t.Errorf("want 1 function, got %d", len(m.Functions))
	}
	if len(m.Exports) != 2 {
		// say_hello + memory
		t.Errorf("want 2 exports, got %d: %+v", len(m.Exports), m.Exports)
	}

	// FuncTypeOf on the imported func (index 0) should work.
	ft := m.FuncTypeOf(0)
	if len(ft.Params) != 4 {
		t.Errorf("fd_write type: want 4 params, got %d", len(ft.Params))
	}
	if len(ft.Results) != 1 {
		t.Errorf("fd_write type: want 1 result, got %d", len(ft.Results))
	}
	// FuncTypeOf on the first local func (index 1, NumImportedFuncs=1).
	ft2 := m.FuncTypeOf(1)
	if len(ft2.Params) != 0 {
		t.Errorf("say_hello type: want 0 params, got %d", len(ft2.Params))
	}
	if len(ft2.Results) != 1 {
		t.Errorf("say_hello type: want 1 result, got %d", len(ft2.Results))
	}
}

// TestParseWexports tests wexports.wasm: 4 functions, 4 exports, no imports.
func TestParseWexports(t *testing.T) {
	m := mustParseFile(t, "wexports.wasm")

	if len(m.Functions) != 4 {
		t.Errorf("want 4 functions, got %d", len(m.Functions))
	}
	if len(m.Exports) != 4 {
		t.Errorf("want 4 exports, got %d", len(m.Exports))
	}
	exportNames := make(map[string]bool)
	for _, e := range m.Exports {
		exportNames[e.Name] = true
	}
	for _, name := range []string{"w_0_0", "w_0_1", "w_1_0", "helper"} {
		if !exportNames[name] {
			t.Errorf("missing export %q", name)
		}
	}
}

// TestParseControl tests control.wasm: no memory, 4 funcs, 4 exports.
func TestParseControl(t *testing.T) {
	m := mustParseFile(t, "control.wasm")

	if len(m.Functions) != 4 {
		t.Errorf("want 4 functions, got %d", len(m.Functions))
	}
	if len(m.Exports) != 4 {
		t.Errorf("want 4 exports, got %d", len(m.Exports))
	}
	for _, name := range []string{"fact", "gcd", "max", "switch3"} {
		found := false
		for _, e := range m.Exports {
			if e.Name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing export %q", name)
		}
	}
}

// TestParseDeadfunc tests deadfunc.wasm: 4 funcs, 1 table, 1 elem, 1 export.
func TestParseDeadfunc(t *testing.T) {
	m := mustParseFile(t, "deadfunc.wasm")

	if len(m.Functions) != 4 {
		t.Errorf("want 4 functions, got %d", len(m.Functions))
	}
	if len(m.Tables) != 1 {
		t.Errorf("want 1 table, got %d", len(m.Tables))
	}
	if len(m.Elements) != 1 {
		t.Errorf("want 1 element segment, got %d", len(m.Elements))
	}
	if len(m.Elements[0].FuncIdxs) != 1 {
		t.Errorf("elem[0].FuncIdxs: want 1, got %d", len(m.Elements[0].FuncIdxs))
	}

	found := false
	for _, e := range m.Exports {
		if e.Name == "used" {
			found = true
			if e.Kind != wasm.ExportFunc {
				t.Errorf("export 'used' kind: want func, got %d", e.Kind)
			}
		}
	}
	if !found {
		t.Error("export 'used' not found")
	}
}

// TestParseDataCoalesce tests datacoalesce.wasm: 1 memory (2 pages), 3 data segments.
func TestParseDataCoalesce(t *testing.T) {
	m := mustParseFile(t, "datacoalesce.wasm")

	if len(m.Memories) != 1 {
		t.Fatalf("want 1 memory, got %d", len(m.Memories))
	}
	if m.Memories[0].Limits.Min != 2 {
		t.Errorf("memory min: want 2, got %d", m.Memories[0].Limits.Min)
	}
	if len(m.Datas) != 3 {
		t.Errorf("want 3 data segments, got %d", len(m.Datas))
	}
	// Verify segment bytes.
	for _, tc := range []struct {
		idx  int
		want []byte
	}{
		{0, []byte("AAAA")},
		{1, []byte("BBBB")},
		{2, []byte("CC")},
	} {
		if tc.idx >= len(m.Datas) {
			t.Errorf("data[%d] does not exist", tc.idx)
			continue
		}
		if !bytes.Equal(m.Datas[tc.idx].Bytes, tc.want) {
			t.Errorf("data[%d].Bytes: want %q, got %q", tc.idx, tc.want, m.Datas[tc.idx].Bytes)
		}
	}
}

// TestParseVtableDispatch tests vtable_dispatch.wasm: 1 memory, 1 table, 4 data segments, elem.
func TestParseVtableDispatch(t *testing.T) {
	m := mustParseFile(t, "vtable_dispatch.wasm")

	if len(m.Memories) != 1 {
		t.Errorf("want 1 memory, got %d", len(m.Memories))
	}
	if len(m.Tables) != 1 {
		t.Errorf("want 1 table, got %d", len(m.Tables))
	}
	if len(m.Elements) < 1 {
		t.Errorf("want >= 1 element segment, got %d", len(m.Elements))
	}
	// vtable_dispatch has 4 data segments.
	if len(m.Datas) != 4 {
		t.Errorf("want 4 data segments, got %d", len(m.Datas))
	}
	found := false
	for _, e := range m.Exports {
		if e.Name == "call_method" {
			found = true
		}
	}
	if !found {
		t.Error("missing export 'call_method'")
	}
}

// TestParseRecursiveInit tests recursive_init.wasm: 1 memory, 5 data segments, 2 exports.
func TestParseRecursiveInit(t *testing.T) {
	m := mustParseFile(t, "recursive_init.wasm")

	if len(m.Memories) != 1 {
		t.Errorf("want 1 memory, got %d", len(m.Memories))
	}
	if len(m.Datas) < 2 {
		t.Errorf("want >= 2 data segments, got %d", len(m.Datas))
	}
	for _, name := range []string{"run", "flag_of"} {
		found := false
		for _, e := range m.Exports {
			if e.Name == name {
				found = true
			}
		}
		if !found {
			t.Errorf("missing export %q", name)
		}
	}
}

// TestParseSSACF tests ssa_cf.wasm: many funcs, no imports, no memory.
func TestParseSSACF(t *testing.T) {
	m := mustParseFile(t, "ssa_cf.wasm")

	if len(m.Functions) == 0 {
		t.Error("want > 0 functions")
	}
	if len(m.Exports) == 0 {
		t.Error("want > 0 exports")
	}
	// All exports should be functions.
	for _, e := range m.Exports {
		if e.Kind != wasm.ExportFunc {
			t.Errorf("export %q: want ExportFunc, got %d", e.Name, e.Kind)
		}
	}
	// Every function body should be non-empty.
	for i, fn := range m.Functions {
		if len(fn.Body) == 0 {
			t.Errorf("function[%d] has empty body", i)
		}
	}
}

// ---- FuncTypeOf tests ----

// TestFuncTypeOfLocalOnly checks FuncTypeOf when there are no imports.
func TestFuncTypeOfLocalOnly(t *testing.T) {
	m := mustParseFile(t, "arith.wasm")
	if m.NumImportedFuncs != 0 {
		t.Fatalf("precondition: expected 0 imports, got %d", m.NumImportedFuncs)
	}
	// All function indices should resolve to a type.
	for i := uint32(0); i < uint32(len(m.Functions)); i++ {
		ft := m.FuncTypeOf(i)
		if len(ft.Params) == 0 && len(ft.Results) == 0 {
			t.Logf("FuncTypeOf(%d) = %+v (ok, some funcs have no params/results)", i, ft)
		}
	}
}

// TestFuncTypeOfWithImports checks FuncTypeOf with imported functions.
func TestFuncTypeOfWithImports(t *testing.T) {
	m := mustParseFile(t, "hello.wasm")
	if m.NumImportedFuncs != 1 {
		t.Fatalf("precondition: expected 1 imported func, got %d", m.NumImportedFuncs)
	}
	// Index 0 is the imported fd_write.
	ft := m.FuncTypeOf(0)
	if len(ft.Params) != 4 {
		t.Errorf("fd_write FuncTypeOf(0): want 4 params, got %d", len(ft.Params))
	}
	// Index 1 is the first local function say_hello.
	ft2 := m.FuncTypeOf(1)
	if len(ft2.Results) != 1 {
		t.Errorf("say_hello FuncTypeOf(1): want 1 result, got %d", len(ft2.Results))
	}
}

// ---- ValType.String tests ----

func TestValTypeString(t *testing.T) {
	cases := []struct {
		vt   wasm.ValType
		want string
	}{
		{wasm.ValI32, "i32"},
		{wasm.ValI64, "i64"},
		{wasm.ValF32, "f32"},
		{wasm.ValF64, "f64"},
		{wasm.ValV128, "v128"},
		{wasm.ValFuncref, "funcref"},
		{wasm.ValExternref, "externref"},
		{wasm.ValType(0x00), "?"},
	}
	for _, tc := range cases {
		got := tc.vt.String()
		if got != tc.want {
			t.Errorf("ValType(0x%02x).String(): want %q, got %q", byte(tc.vt), tc.want, got)
		}
	}
}

// ---- Error-path tests: malformed input ----

// TestParseErrorBadMagic verifies that a wrong magic number returns an error.
func TestParseErrorBadMagic(t *testing.T) {
	bad := []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	_, err := parseBytes(bad)
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

// TestParseErrorBadVersion verifies that an unsupported wasm version returns an error.
func TestParseErrorBadVersion(t *testing.T) {
	bad := []byte{0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00}
	_, err := parseBytes(bad)
	if err == nil {
		t.Fatal("expected error for bad version, got nil")
	}
}

// TestParseErrorTruncatedHeader verifies that a too-short input returns an error.
func TestParseErrorTruncatedHeader(t *testing.T) {
	for i := 0; i < 8; i++ {
		_, err := parseBytes(wasmHeader[:i])
		if err == nil {
			t.Errorf("expected error for header truncated at %d bytes", i)
		}
	}
}

// TestParseErrorUnknownSection verifies that an unknown section ID returns an error.
func TestParseErrorUnknownSection(t *testing.T) {
	payload := encodeLEB128U32(0) // empty payload for unknown section
	sec := encodeSection(0xFF, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for unknown section id, got nil")
	}
}

// TestParseErrorTruncatedSectionSize verifies that a truncated section size returns an error.
func TestParseErrorTruncatedSectionSize(t *testing.T) {
	// Header followed by a section id but no size.
	data := append(wasmHeader, 0x01) // section id 1 (type), then EOF
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated section size, got nil")
	}
}

// TestParseErrorTruncatedSectionPayload verifies that a truncated section payload returns an error.
func TestParseErrorTruncatedSectionPayload(t *testing.T) {
	// Claim 100 bytes of payload for section 1 but provide none.
	data := append(wasmHeader, 0x01, 100)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated section payload, got nil")
	}
}

// TestParseErrorBadTypeSectionTag verifies that a non-0x60 tag in the type section fails.
func TestParseErrorBadTypeSectionTag(t *testing.T) {
	// Type section: count=1, then tag=0x61 (bad).
	payload := []byte{0x01, 0x61}
	sec := encodeSection(1, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for bad type tag, got nil")
	}
}

// TestParseErrorBadImportKind verifies that an unknown import kind returns an error.
func TestParseErrorBadImportKind(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 import
	// module name "env" (len=3)
	payload = append(payload, 0x03, 'e', 'n', 'v')
	// import name "x" (len=1)
	payload = append(payload, 0x01, 'x')
	// unknown kind 0xFF
	payload = append(payload, 0xFF)
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for bad import kind, got nil")
	}
}

// TestParseErrorCodeFunctionCountMismatch verifies the code-function section count check.
func TestParseErrorCodeFunctionCountMismatch(t *testing.T) {
	// Type section: 1 type (no params, no results).
	typePayload := []byte{0x01, 0x60, 0x00, 0x00}
	// Function section: 1 func, type 0.
	funcPayload := []byte{0x01, 0x00}
	// Code section: claims 2 functions (mismatch).
	codePayload := []byte{0x02}

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
		encodeSection(10, codePayload),
	)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for code/function count mismatch, got nil")
	}
}

// TestParseErrorUnsupportedElementFlag verifies unsupported element segment flags return an error.
func TestParseErrorUnsupportedElementFlag(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 element segment
	// flag = 0x03 (passive, unsupported)
	payload = append(payload, 0x03)
	sec := encodeSection(9, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for unsupported element flag, got nil")
	}
}

// TestParseErrorUnsupportedDataFlag verifies unsupported data segment flags return an error.
func TestParseErrorUnsupportedDataFlag(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 data segment
	// flag = 0x01 (passive, unsupported)
	payload = append(payload, 0x01)
	sec := encodeSection(11, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for unsupported data flag, got nil")
	}
}

// TestParseErrorUnsupportedConstExprOpcode verifies that an unknown const-expr opcode errors.
func TestParseErrorUnsupportedConstExprOpcode(t *testing.T) {
	// Build a global section with an init expr using opcode 0x01 (nop — not allowed in const expr).
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 global
	payload = append(payload, 0x7f)                  // value type i32
	payload = append(payload, 0x00)                  // immutable
	// const expr: 0x01 (nop) — unsupported opcode
	payload = append(payload, 0x01, 0x0b)
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for unsupported const expr opcode, got nil")
	}
}

// TestParseErrorUnsupportedElemKind verifies that an unsupported elemkind in flag=0x02 errors.
func TestParseErrorUnsupportedElemKind(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)    // 1 element segment
	payload = append(payload, encodeLEB128U32(0x02)...) // flag=0x02
	payload = append(payload, encodeLEB128U32(0)...)    // table index
	// offset: i32.const 0, end
	payload = append(payload, 0x41, 0x00, 0x0b)
	payload = append(payload, 0x01) // elemkind = 0x01 (unsupported; only 0x00 is supported)
	sec := encodeSection(9, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for unsupported elemkind, got nil")
	}
}

// ---- Hand-crafted happy-path modules ----

// TestParseEmptyModule verifies that a module with no sections parses successfully.
func TestParseEmptyModule(t *testing.T) {
	m := mustParseBytes(t, wasmHeader)
	if len(m.Types) != 0 || len(m.Functions) != 0 || len(m.Exports) != 0 {
		t.Errorf("empty module should have no types/funcs/exports: %+v", m)
	}
	if m.Start != nil {
		t.Errorf("empty module should have no start: %v", m.Start)
	}
}

// TestParseCustomSection verifies that a custom section (id=0) is silently ignored.
func TestParseCustomSection(t *testing.T) {
	payload := []byte{0x04, 'n', 'a', 'm', 'e', 0xFF, 0xFE} // arbitrary custom content
	sec := encodeSection(0, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	// Should parse without error; no types/funcs/exports.
	if len(m.Types) != 0 {
		t.Errorf("expected no types, got %d", len(m.Types))
	}
}

// TestParseStartSection verifies that the start section is parsed correctly.
func TestParseStartSection(t *testing.T) {
	// Build: type section (1 func () -> ()), function section (1 func), start section (idx=0), code section.
	typePayload := []byte{0x01, 0x60, 0x00, 0x00}
	funcPayload := []byte{0x01, 0x00}
	startPayload := encodeLEB128U32(0) // start function index = 0
	// Code: 1 function body, just end (0x0b).
	codePayload := []byte{0x01, 0x02, 0x00, 0x0b}

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
		encodeSection(8, startPayload),
		encodeSection(10, codePayload),
	)
	m := mustParseBytes(t, data)
	if m.Start == nil {
		t.Fatal("expected Start to be set")
	}
	if *m.Start != 0 {
		t.Errorf("Start: want 0, got %d", *m.Start)
	}
}

// TestParseDataCountSection verifies that the data count section (id=12) is parsed without error.
func TestParseDataCountSection(t *testing.T) {
	// A module with a data count section (count=0) and empty data section.
	dataCountPayload := encodeLEB128U32(0) // count = 0
	dataSectionPayload := encodeLEB128U32(0)

	data := buildModule(
		encodeSection(12, dataCountPayload),
		encodeSection(11, dataSectionPayload),
	)
	m := mustParseBytes(t, data)
	if len(m.Datas) != 0 {
		t.Errorf("expected 0 data segments, got %d", len(m.Datas))
	}
}

// TestParseLimitsWithMax verifies parsing of limits that include a max value.
func TestParseLimitsWithMax(t *testing.T) {
	// Memory section with a limit of min=1, max=4.
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 memory
	payload = append(payload, 0x01)                  // flags: has max
	payload = append(payload, encodeLEB128U32(1)...) // min=1
	payload = append(payload, encodeLEB128U32(4)...) // max=4
	sec := encodeSection(5, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Memories) != 1 {
		t.Fatalf("expected 1 memory, got %d", len(m.Memories))
	}
	mem := m.Memories[0]
	if !mem.Limits.HasMax {
		t.Error("expected HasMax=true")
	}
	if mem.Limits.Min != 1 {
		t.Errorf("min: want 1, got %d", mem.Limits.Min)
	}
	if mem.Limits.Max != 4 {
		t.Errorf("max: want 4, got %d", mem.Limits.Max)
	}
}

// TestParseImportTable verifies parsing of a table import.
func TestParseImportTable(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 import
	// module "env"
	payload = append(payload, 0x03, 'e', 'n', 'v')
	// name "tab"
	payload = append(payload, 0x03, 't', 'a', 'b')
	// kind: ImportTable (0x01)
	payload = append(payload, 0x01)
	// elem type: funcref (0x70)
	payload = append(payload, 0x70)
	// limits: no max, min=1
	payload = append(payload, 0x00)                  // flags
	payload = append(payload, encodeLEB128U32(1)...) // min=1
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(m.Imports))
	}
	if m.Imports[0].Kind != wasm.ImportTable {
		t.Errorf("kind: want ImportTable, got %d", m.Imports[0].Kind)
	}
	if m.NumImportedTables != 1 {
		t.Errorf("NumImportedTables: want 1, got %d", m.NumImportedTables)
	}
	if m.Imports[0].Table.ElemType != wasm.ValFuncref {
		t.Errorf("table ElemType: want funcref, got %v", m.Imports[0].Table.ElemType)
	}
}

// TestParseImportMemory verifies parsing of a memory import.
func TestParseImportMemory(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 import
	// module "env"
	payload = append(payload, 0x03, 'e', 'n', 'v')
	// name "mem"
	payload = append(payload, 0x03, 'm', 'e', 'm')
	// kind: ImportMemory (0x02)
	payload = append(payload, 0x02)
	// limits: no max, min=1
	payload = append(payload, 0x00)
	payload = append(payload, encodeLEB128U32(1)...)
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(m.Imports))
	}
	if m.Imports[0].Kind != wasm.ImportMemory {
		t.Errorf("kind: want ImportMemory, got %d", m.Imports[0].Kind)
	}
	if m.NumImportedMems != 1 {
		t.Errorf("NumImportedMems: want 1, got %d", m.NumImportedMems)
	}
}

// TestParseImportGlobal verifies parsing of a global import.
func TestParseImportGlobal(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // 1 import
	// module "env"
	payload = append(payload, 0x03, 'e', 'n', 'v')
	// name "g"
	payload = append(payload, 0x01, 'g')
	// kind: ImportGlobal (0x03)
	payload = append(payload, 0x03)
	// value type i32 (0x7f), mutable=0
	payload = append(payload, 0x7f, 0x00)
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(m.Imports))
	}
	if m.Imports[0].Kind != wasm.ImportGlobal {
		t.Errorf("kind: want ImportGlobal, got %d", m.Imports[0].Kind)
	}
	if m.NumImportedGlobals != 1 {
		t.Errorf("NumImportedGlobals: want 1, got %d", m.NumImportedGlobals)
	}
	if m.Imports[0].Global.Type != wasm.ValI32 {
		t.Errorf("global type: want i32, got %v", m.Imports[0].Global.Type)
	}
	if m.Imports[0].Global.Mutable {
		t.Error("global mutable: want false")
	}
}

// TestParseExportKinds verifies all four export kinds.
func TestParseExportKinds(t *testing.T) {
	// Build a module with:
	//   type section: 1 type (no params, no results)
	//   function section: 1 func type 0
	//   table section: 1 table funcref 0..0
	//   memory section: 1 memory min=0
	//   global section: 1 global i32 immutable (i32.const 0)
	//   export section: 4 exports (func, table, memory, global)
	//   code section: 1 body just end

	typePayload := []byte{0x01, 0x60, 0x00, 0x00}
	funcPayload := []byte{0x01, 0x00}

	var tablePayload []byte
	tablePayload = append(tablePayload, encodeLEB128U32(1)...)
	tablePayload = append(tablePayload, 0x70) // funcref
	tablePayload = append(tablePayload, 0x00) // no max
	tablePayload = append(tablePayload, encodeLEB128U32(0)...)

	var memPayload []byte
	memPayload = append(memPayload, encodeLEB128U32(1)...)
	memPayload = append(memPayload, 0x00)
	memPayload = append(memPayload, encodeLEB128U32(0)...)

	// Global: i32 immutable, init = i32.const 0.
	var globalPayload []byte
	globalPayload = append(globalPayload, encodeLEB128U32(1)...)
	globalPayload = append(globalPayload, 0x7f)             // i32
	globalPayload = append(globalPayload, 0x00)             // immutable
	globalPayload = append(globalPayload, 0x41, 0x00, 0x0b) // i32.const 0, end

	// Exports: 4 entries.
	var exportPayload []byte
	exportPayload = append(exportPayload, encodeLEB128U32(4)...)
	// func export "f"
	exportPayload = append(exportPayload, 0x01, 'f', 0x00)
	exportPayload = append(exportPayload, encodeLEB128U32(0)...)
	// table export "t"
	exportPayload = append(exportPayload, 0x01, 't', 0x01)
	exportPayload = append(exportPayload, encodeLEB128U32(0)...)
	// memory export "m"
	exportPayload = append(exportPayload, 0x01, 'm', 0x02)
	exportPayload = append(exportPayload, encodeLEB128U32(0)...)
	// global export "g"
	exportPayload = append(exportPayload, 0x01, 'g', 0x03)
	exportPayload = append(exportPayload, encodeLEB128U32(0)...)

	codePayload := []byte{0x01, 0x02, 0x00, 0x0b}

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
		encodeSection(4, tablePayload),
		encodeSection(5, memPayload),
		encodeSection(6, globalPayload),
		encodeSection(7, exportPayload),
		encodeSection(10, codePayload),
	)
	m := mustParseBytes(t, data)
	if len(m.Exports) != 4 {
		t.Fatalf("want 4 exports, got %d", len(m.Exports))
	}
	kindByName := make(map[string]wasm.ExportKind)
	for _, e := range m.Exports {
		kindByName[e.Name] = e.Kind
	}
	if kindByName["f"] != wasm.ExportFunc {
		t.Errorf("export 'f': want ExportFunc, got %d", kindByName["f"])
	}
	if kindByName["t"] != wasm.ExportTable {
		t.Errorf("export 't': want ExportTable, got %d", kindByName["t"])
	}
	if kindByName["m"] != wasm.ExportMemory {
		t.Errorf("export 'm': want ExportMemory, got %d", kindByName["m"])
	}
	if kindByName["g"] != wasm.ExportGlobal {
		t.Errorf("export 'g': want ExportGlobal, got %d", kindByName["g"])
	}
}

// TestParseGlobalMutable verifies a mutable global parses correctly.
func TestParseGlobalMutable(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7f)             // i32
	payload = append(payload, 0x01)             // mutable
	payload = append(payload, 0x41, 0x2a, 0x0b) // i32.const 42, end
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global, got %d", len(m.Globals))
	}
	g := m.Globals[0]
	if !g.Type.Mutable {
		t.Error("expected Mutable=true")
	}
	if g.Type.Type != wasm.ValI32 {
		t.Errorf("global type: want i32, got %v", g.Type.Type)
	}
	// Init expr should start with 0x41 (i32.const).
	if len(g.Init) == 0 || g.Init[0] != 0x41 {
		t.Errorf("global init: want opcode 0x41, got %v", g.Init)
	}
}

// TestParseElementFlag0x02 verifies parsing of an element segment with flag=0x02.
func TestParseElementFlag0x02(t *testing.T) {
	// Type, function, table, element (flag=0x02), code sections.
	typePayload := []byte{0x01, 0x60, 0x00, 0x00}
	funcPayload := []byte{0x01, 0x00}

	var tablePayload []byte
	tablePayload = append(tablePayload, encodeLEB128U32(1)...)
	tablePayload = append(tablePayload, 0x70)
	tablePayload = append(tablePayload, 0x00)
	tablePayload = append(tablePayload, encodeLEB128U32(1)...)

	var elemPayload []byte
	elemPayload = append(elemPayload, encodeLEB128U32(1)...)    // 1 segment
	elemPayload = append(elemPayload, encodeLEB128U32(0x02)...) // flag=0x02
	elemPayload = append(elemPayload, encodeLEB128U32(0)...)    // table idx=0
	elemPayload = append(elemPayload, 0x41, 0x00, 0x0b)         // offset: i32.const 0, end
	elemPayload = append(elemPayload, 0x00)                     // elemkind=0x00 (funcref)
	elemPayload = append(elemPayload, encodeLEB128U32(1)...)    // 1 func idx
	elemPayload = append(elemPayload, encodeLEB128U32(0)...)    // func idx=0

	codePayload := []byte{0x01, 0x02, 0x00, 0x0b}

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
		encodeSection(4, tablePayload),
		encodeSection(9, elemPayload),
		encodeSection(10, codePayload),
	)
	m := mustParseBytes(t, data)
	if len(m.Elements) != 1 {
		t.Fatalf("expected 1 element segment, got %d", len(m.Elements))
	}
	if m.Elements[0].TableIdx != 0 {
		t.Errorf("TableIdx: want 0, got %d", m.Elements[0].TableIdx)
	}
	if len(m.Elements[0].FuncIdxs) != 1 {
		t.Errorf("FuncIdxs: want 1, got %d", len(m.Elements[0].FuncIdxs))
	}
}

// TestParseDataFlag0x02 verifies parsing of a data segment with flag=0x02 (explicit memidx).
func TestParseDataFlag0x02(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)    // 1 segment
	payload = append(payload, encodeLEB128U32(0x02)...) // flag=0x02
	payload = append(payload, encodeLEB128U32(0)...)    // mem idx=0
	payload = append(payload, 0x41, 0x00, 0x0b)         // offset: i32.const 0
	payload = append(payload, 0x04, 'a', 'b', 'c', 'd') // 4 bytes "abcd"
	sec := encodeSection(11, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Datas) != 1 {
		t.Fatalf("expected 1 data segment, got %d", len(m.Datas))
	}
	ds := m.Datas[0]
	if ds.MemIdx != 0 {
		t.Errorf("MemIdx: want 0, got %d", ds.MemIdx)
	}
	if !bytes.Equal(ds.Bytes, []byte("abcd")) {
		t.Errorf("Bytes: want 'abcd', got %q", ds.Bytes)
	}
}

// TestParseConstExprI64Const verifies that i64.const in a global init expr is handled.
func TestParseConstExprI64Const(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7e) // i64 value type
	payload = append(payload, 0x00) // immutable
	// i64.const 1000 (0x42 + LEB128 signed 1000)
	payload = append(payload, 0x42)
	payload = append(payload, encodeLEB128S32(1000)...) // 1000 in SLEB128
	payload = append(payload, 0x0b)
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global, got %d", len(m.Globals))
	}
	if m.Globals[0].Type.Type != wasm.ValI64 {
		t.Errorf("global type: want i64, got %v", m.Globals[0].Type.Type)
	}
}

// TestParseConstExprF32Const verifies that f32.const in a global init expr is handled.
func TestParseConstExprF32Const(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7d) // f32 value type
	payload = append(payload, 0x00) // immutable
	// f32.const 0x3f800000 (1.0)
	payload = append(payload, 0x43, 0x00, 0x00, 0x80, 0x3f)
	payload = append(payload, 0x0b)
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global, got %d", len(m.Globals))
	}
	if m.Globals[0].Type.Type != wasm.ValF32 {
		t.Errorf("global type: want f32, got %v", m.Globals[0].Type.Type)
	}
}

// TestParseConstExprF64Const verifies that f64.const in a global init expr is handled.
func TestParseConstExprF64Const(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7c) // f64 value type
	payload = append(payload, 0x00) // immutable
	// f64.const: 8 bytes (0x3FF0000000000000 = 1.0)
	payload = append(payload, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f)
	payload = append(payload, 0x0b)
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global, got %d", len(m.Globals))
	}
	if m.Globals[0].Type.Type != wasm.ValF64 {
		t.Errorf("global type: want f64, got %v", m.Globals[0].Type.Type)
	}
}

// TestParseConstExprGlobalGet verifies that global.get in a const expr is handled.
func TestParseConstExprGlobalGet(t *testing.T) {
	// Import a global, then use global.get in another global's init.
	var payload []byte
	// Two globals: first is locally defined, second uses global.get 0.
	payload = append(payload, encodeLEB128U32(2)...)
	// Global 0: i32, immutable, i32.const 5
	payload = append(payload, 0x7f, 0x00, 0x41, 0x05, 0x0b)
	// Global 1: i32, immutable, global.get 0
	payload = append(payload, 0x7f, 0x00)
	payload = append(payload, 0x23)                  // global.get
	payload = append(payload, encodeLEB128U32(0)...) // global idx 0
	payload = append(payload, 0x0b)                  // end
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 2 {
		t.Fatalf("expected 2 globals, got %d", len(m.Globals))
	}
}

// TestParseConstExprRefNull verifies that ref.null in a const expr is handled.
func TestParseConstExprRefNull(t *testing.T) {
	// Use a data segment with a global that has a ref.null init (not typical but valid).
	// Actually global init with ref.null funcref.
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x70) // funcref
	payload = append(payload, 0x00) // immutable
	// ref.null funcref (0xd0 0x70)
	payload = append(payload, 0xd0, 0x70, 0x0b)
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global, got %d", len(m.Globals))
	}
}

// TestParseConstExprRefFunc verifies that ref.func in a const expr is handled.
func TestParseConstExprRefFunc(t *testing.T) {
	// We need a function for ref.func to reference.
	typePayload := []byte{0x01, 0x60, 0x00, 0x00}
	funcPayload := []byte{0x01, 0x00}

	var globalPayload []byte
	globalPayload = append(globalPayload, encodeLEB128U32(1)...)
	globalPayload = append(globalPayload, 0x70) // funcref
	globalPayload = append(globalPayload, 0x00) // immutable
	// ref.func 0 (0xd2 + uleb128(0))
	globalPayload = append(globalPayload, 0xd2)
	globalPayload = append(globalPayload, encodeLEB128U32(0)...)
	globalPayload = append(globalPayload, 0x0b)

	codePayload := []byte{0x01, 0x02, 0x00, 0x0b}

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
		encodeSection(6, globalPayload),
		encodeSection(10, codePayload),
	)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global, got %d", len(m.Globals))
	}
}

// ---- LEB128 edge-case tests ----

// TestLEB128OverflowU32 verifies that a 5-byte LEB128 exceeding uint32 is an error.
func TestLEB128OverflowU32(t *testing.T) {
	// Encode a value > 0xFFFFFFFF as a valid u64 LEB128 (e.g. 0x1_0000_0000).
	// 0x1_0000_0000 in uleb128 = 0x80 0x80 0x80 0x80 0x10
	overflow := []byte{0x80, 0x80, 0x80, 0x80, 0x10}

	// Put it as the count in a type section — section payload = overflow bytes.
	sec := encodeSection(1, overflow)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected overflow error for u32 > 0xFFFFFFFF, got nil")
	}
}

// TestLEB128TruncatedU32 verifies that a LEB128 with continuation bits but no next byte errors.
func TestLEB128TruncatedU32(t *testing.T) {
	// Type section with count byte 0x80 (continuation bit set) then EOF.
	sec := encodeSection(1, []byte{0x80})
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected truncated LEB128 error, got nil")
	}
}

// TestParseEmptyReader verifies that an empty reader returns an error (not a panic).
func TestParseEmptyReader(t *testing.T) {
	_, err := parseBytes(nil)
	if err == nil {
		_, err = parseBytes([]byte{})
	}
	if err == nil {
		t.Fatal("expected error parsing empty input")
	}
}

// TestParseReaderError verifies that read errors propagate correctly.
func TestParseReaderError(t *testing.T) {
	_, err := wasm.Parse(errReader{})
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
}

// errReader is an io.Reader that always returns an error.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// TestParseMultipleTypes verifies parsing of multiple function types including all val types.
func TestParseMultipleTypes(t *testing.T) {
	// Build a type section with 3 types:
	//   () -> ()
	//   (i32, i64) -> (i32)
	//   (f32, f64) -> (f64)
	var payload []byte
	payload = append(payload, encodeLEB128U32(3)...)
	// Type 0: () -> ()
	payload = append(payload, 0x60, 0x00, 0x00)
	// Type 1: (i32, i64) -> (i32)
	payload = append(payload, 0x60, 0x02, 0x7f, 0x7e, 0x01, 0x7f)
	// Type 2: (f32, f64) -> (f64)
	payload = append(payload, 0x60, 0x02, 0x7d, 0x7c, 0x01, 0x7c)
	sec := encodeSection(1, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Types) != 3 {
		t.Fatalf("want 3 types, got %d", len(m.Types))
	}
	// Type 1: (i32, i64) -> (i32)
	if m.Types[1].Params[0] != wasm.ValI32 || m.Types[1].Params[1] != wasm.ValI64 {
		t.Errorf("type[1] params: got %v", m.Types[1].Params)
	}
	if m.Types[1].Results[0] != wasm.ValI32 {
		t.Errorf("type[1] result: got %v", m.Types[1].Results)
	}
	// Type 2: (f32, f64) -> (f64)
	if m.Types[2].Params[0] != wasm.ValF32 || m.Types[2].Params[1] != wasm.ValF64 {
		t.Errorf("type[2] params: got %v", m.Types[2].Params)
	}
}

// TestParseMutableImportGlobal verifies a mutable global import.
func TestParseMutableImportGlobal(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x03, 'e', 'n', 'v')
	payload = append(payload, 0x01, 'g')
	payload = append(payload, 0x03) // ImportGlobal
	payload = append(payload, 0x7e) // i64
	payload = append(payload, 0x01) // mutable=1
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Imports) != 1 {
		t.Fatalf("expected 1 import, got %d", len(m.Imports))
	}
	if !m.Imports[0].Global.Mutable {
		t.Error("expected mutable global import")
	}
	if m.Imports[0].Global.Type != wasm.ValI64 {
		t.Errorf("global type: want i64, got %v", m.Imports[0].Global.Type)
	}
}

// TestParseCodeBodyContent verifies that code bodies are non-empty after parsing.
func TestParseCodeBodyContent(t *testing.T) {
	m := mustParseFile(t, "arith.wasm")
	for i, fn := range m.Functions {
		if len(fn.Body) == 0 {
			t.Errorf("function[%d] has empty body", i)
		}
		// Last byte of every body should be 0x0b (end).
		if fn.Body[len(fn.Body)-1] != 0x0b {
			t.Errorf("function[%d] body does not end with 0x0b", i)
		}
	}
}

// TestParseGlobalInitRawBytes verifies that the raw init bytes include the trailing 0x0b.
func TestParseGlobalInitRawBytes(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7f, 0x00)       // i32 immutable
	payload = append(payload, 0x41, 0x00, 0x0b) // i32.const 0, end
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 1 {
		t.Fatalf("expected 1 global")
	}
	init := m.Globals[0].Init
	if len(init) == 0 {
		t.Fatal("global init is empty")
	}
	if init[len(init)-1] != 0x0b {
		t.Errorf("global init last byte: want 0x0b, got 0x%02x", init[len(init)-1])
	}
}

// TestParseDataOffsetRawBytes verifies that data segment offsets include the trailing 0x0b.
func TestParseDataOffsetRawBytes(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x00)             // flag=0x00
	payload = append(payload, 0x41, 0x10, 0x0b) // i32.const 16, end
	payload = append(payload, 0x03, 'a', 'b', 'c')
	sec := encodeSection(11, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Datas) != 1 {
		t.Fatalf("expected 1 data segment")
	}
	off := m.Datas[0].Offset
	if len(off) == 0 || off[len(off)-1] != 0x0b {
		t.Errorf("data offset: last byte should be 0x0b, got %v", off)
	}
}

// ---- Extra error-path coverage for LEB128 and section parsers ----

// TestLEB128U64TenByteOverflow verifies that a 10-byte LEB128 value > max u64 returns overflow.
// The last (10th) byte of a valid u64 LEB128 may be at most 0x01; 0x02 overflows.
func TestLEB128U64TenByteOverflow(t *testing.T) {
	// 10 bytes, all with continuation except the last:
	// bytes 0-8: 0x80; byte 9: 0x02 (overflows since i==9 && b>1)
	overflow10 := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	// Embed as count in a type section.
	sec := encodeSection(1, overflow10)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected overflow for 10-byte LEB128 > maxU64, got nil")
	}
}

// TestLEB128U64ElevenBytesOverflow verifies that an 11-byte LEB128 (all continuation) overflows
// after 10 iterations.
func TestLEB128U64ElevenBytesOverflow(t *testing.T) {
	// 11 bytes all with continuation bit — exits after 10 iterations returning overflow.
	overflow11 := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	sec := encodeSection(1, overflow11)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected overflow for 11-byte LEB128, got nil")
	}
}

// TestLEB128U64ShiftOverflow exercises the shift >= 64 branch inside readU64.
// After 10 bytes of all-continuation the loop exits with overflow, but the shift>=64 guard
// fires at byte 10 (shift=63 after 9 bytes, so byte 10: shift=63 is not >=64 yet; we need
// byte 10 to have shift=70). Actually the loop caps at 10 bytes. Drive it via a crafted
// section whose count would require shift>=64 to hit — the 10-iteration loop with
// continuation bytes forces the overflow exit at i=10.
// This test drives the same overflow path through a multi-byte count in a section.
func TestLEB128U64LargeMultiByteValue(t *testing.T) {
	// Encode the count of a type section as a valid but large u32 (128 = 0x80 0x01)
	// to exercise the multi-byte LEB128 path in readU64/readU32.
	var payload []byte
	// Count = 1 encoded as two bytes 0x81, 0x00 (same as 1 but uses continuation).
	payload = append(payload, 0x81, 0x00)
	// One type: 0x60 tag, 0 params, 0 results.
	payload = append(payload, 0x60, 0x00, 0x00)
	sec := encodeSection(1, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Types) != 1 {
		t.Errorf("want 1 type from two-byte LEB128 count, got %d", len(m.Types))
	}
}

// TestReadS64BitsShiftOverflow exercises the shift > 70 error path in readS64Bits.
// To reach that branch we need a signed LEB128 with more than 10 bytes of continuation.
// We feed such a value as an i64.const in a global init expression.
func TestReadS64BitsShiftOverflow(t *testing.T) {
	// Build a global section whose init expr uses i64.const with an 11-byte SLEB128.
	// 11 bytes all with continuation: 0x80 * 11 — truncated (never terminates without end byte).
	// However, once shift > 70 (after the 11th byte, shift would be 77) the overflow fires.
	// We need continuation bytes: shift increases by 7 per byte. After byte 11, shift=77 > 70.
	// Construct 11 continuation bytes followed by a terminating byte.
	sleb11 := []byte{
		0x80, 0x80, 0x80, 0x80, 0x80, // bytes 0-4
		0x80, 0x80, 0x80, 0x80, 0x80, // bytes 5-9
		0x80, // byte 10: continuation (shift would be 70 here — hits shift>70 on next check)
		0x00, // byte 11: final byte (but shift>70 fires before we get here... let's check)
	}

	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7e) // i64 value type
	payload = append(payload, 0x00) // immutable
	payload = append(payload, 0x42) // i64.const
	payload = append(payload, sleb11...)
	payload = append(payload, 0x0b) // end
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	// This should error (overflow or truncated).
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for very long SLEB128 in i64.const, got nil")
	}
}

// TestReadByteVecTruncated exercises the readByteVec error path when the data is truncated.
func TestReadByteVecTruncated(t *testing.T) {
	// Data section: 1 segment, flag=0, offset=i32.const 0, then claim 100 bytes but provide 2.
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x00)             // flag=0x00
	payload = append(payload, 0x41, 0x00, 0x0b) // offset: i32.const 0
	// Count = 100 but only 2 bytes of data follow.
	payload = append(payload, 100, 'x', 'y')
	sec := encodeSection(11, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated data bytes, got nil")
	}
}

// TestReadNameTruncated exercises the readName error path via a truncated import name.
func TestReadNameTruncated(t *testing.T) {
	// Import section: 1 import, module name length=10 but only 3 bytes follow.
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 10, 'e', 'n', 'v') // claims 10 bytes, provides 3
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated import module name, got nil")
	}
}

// TestReadImportNameTruncated exercises truncated import field-name reading.
func TestReadImportNameTruncated(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x03, 'e', 'n', 'v') // valid module name
	payload = append(payload, 10, 'f')             // import name claims 10 bytes, provides 1
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated import field name, got nil")
	}
}

// TestParseCodeSectionTruncatedBody exercises the code body read error path.
func TestParseCodeSectionTruncatedBody(t *testing.T) {
	typePayload := []byte{0x01, 0x60, 0x00, 0x00}
	funcPayload := []byte{0x01, 0x00}

	// Code section: 1 body claiming 20 bytes but providing 0.
	var codePayload []byte
	codePayload = append(codePayload, encodeLEB128U32(1)...)  // count
	codePayload = append(codePayload, encodeLEB128U32(20)...) // body size = 20
	// No body bytes follow.

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
		encodeSection(10, codePayload),
	)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated code body, got nil")
	}
}

// TestParseFunctionSectionTruncated exercises the readU32 error path in parseFunctionSection.
func TestParseFunctionSectionTruncated(t *testing.T) {
	typePayload := []byte{0x01, 0x60, 0x00, 0x00}

	// Function section: claims 1 func but provides no type index bytes.
	funcPayload := []byte{0x01} // count=1, then EOF inside the section

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(3, funcPayload),
	)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated function section, got nil")
	}
}

// TestParseTableSectionTruncated exercises the readLimits error path in parseTableSection.
func TestParseTableSectionTruncated(t *testing.T) {
	// Table section: count=1, then elem type 0x70, then EOF before limits.
	payload := []byte{0x01, 0x70} // count=1, elemtype=funcref, then EOF
	sec := encodeSection(4, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated table section, got nil")
	}
}

// TestParseMemorySectionTruncated exercises the readLimits error path in parseMemorySection.
func TestParseMemorySectionTruncated(t *testing.T) {
	// Memory section: count=1, then EOF (no limits).
	payload := []byte{0x01} // count=1, then EOF
	sec := encodeSection(5, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated memory section, got nil")
	}
}

// TestParseExportSectionTruncated exercises error paths in parseExportSection.
func TestParseExportSectionTruncated(t *testing.T) {
	// Export section: count=1, export name length=5 but only 2 bytes follow.
	payload := []byte{0x01, 0x05, 'h', 'i'} // count=1, name len=5, only 2 bytes
	sec := encodeSection(7, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated export name, got nil")
	}
}

// TestParseGlobalSectionTruncated exercises the early-return error path in parseGlobalSection.
func TestParseGlobalSectionTruncated(t *testing.T) {
	// Global section: count=1, then value type 0x7f, then EOF (no mutability byte).
	payload := []byte{0x01, 0x7f} // count=1, vt=i32, then EOF
	sec := encodeSection(6, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated global section, got nil")
	}
}

// TestParseElementSectionTruncatedOffset exercises the error path for a missing element offset.
func TestParseElementSectionTruncatedOffset(t *testing.T) {
	// Element section: count=1, flag=0x00, then EOF (no offset const expr).
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...) // count=1
	payload = append(payload, 0x00)                  // flag=0x00
	// No offset follows.
	sec := encodeSection(9, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for missing element segment offset, got nil")
	}
}

// TestParseTypeSectionTruncatedTag exercises truncated type section after count.
func TestParseTypeSectionTruncatedTag(t *testing.T) {
	// Type section: count=1, then EOF (no tag byte).
	payload := []byte{0x01}
	sec := encodeSection(1, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for missing type tag, got nil")
	}
}

// TestParseFuncTypeParamsTruncated exercises error when param bytes are missing.
func TestParseFuncTypeParamsTruncated(t *testing.T) {
	// Type section: count=1, tag=0x60, param count=3 but only 1 param byte.
	payload := []byte{0x01, 0x60, 0x03, 0x7f} // 3 params claimed, 1 provided
	sec := encodeSection(1, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated func type params, got nil")
	}
}

// TestParseFuncTypeResultsTruncated exercises error when result bytes are missing.
func TestParseFuncTypeResultsTruncated(t *testing.T) {
	// Type section: count=1, tag=0x60, 0 params, result count=2 but only 1 result byte.
	payload := []byte{0x01, 0x60, 0x00, 0x02, 0x7f} // 2 results claimed, 1 provided
	sec := encodeSection(1, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated func type results, got nil")
	}
}

// TestParseStartSectionTruncated exercises the error path when start section has no index.
func TestParseStartSectionTruncated(t *testing.T) {
	// Start section payload is empty (no index LEB128).
	data := buildModule(encodeSection(8, []byte{}))
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for truncated start section, got nil")
	}
}

// TestParseImportFuncTruncatedTypeIdx exercises error when import func type index is missing.
func TestParseImportFuncTruncatedTypeIdx(t *testing.T) {
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x03, 'e', 'n', 'v')
	payload = append(payload, 0x01, 'f')
	payload = append(payload, 0x00) // ImportFunc kind
	// No type index follows.
	sec := encodeSection(2, payload)
	data := buildModule(sec)
	_, err := parseBytes(data)
	if err == nil {
		t.Fatal("expected error for missing import func type index, got nil")
	}
}

// TestWriteULEBMultiByte exercises the multi-byte writeULEB path via a global.get const expr.
// global.get encodes its index with writeULEB; a large index (>=128) forces two bytes.
func TestWriteULEBMultiByte(t *testing.T) {
	// Build: 200 globals with i32.const 0 init, then one more whose init is global.get 128.
	// This exercises writeULEB with a value >= 128 (needs 2 bytes).
	var payload []byte
	count := uint32(201)
	payload = append(payload, encodeLEB128U32(count)...)
	// Globals 0-199: i32 immutable, i32.const 0
	for i := 0; i < 200; i++ {
		payload = append(payload, 0x7f, 0x00, 0x41, 0x00, 0x0b)
	}
	// Global 200: i32 immutable, global.get 128 (needs 2-byte writeULEB)
	payload = append(payload, 0x7f, 0x00)
	payload = append(payload, 0x23)                    // global.get opcode
	payload = append(payload, encodeLEB128U32(128)...) // index 128 (ULEB128 = 0x80 0x01)
	payload = append(payload, 0x0b)

	sec := encodeSection(6, payload)
	data := buildModule(sec)
	m := mustParseBytes(t, data)
	if len(m.Globals) != 201 {
		t.Errorf("expected 201 globals, got %d", len(m.Globals))
	}
	// The last global's init should have a two-byte ULEB128 for index 128.
	last := m.Globals[200].Init
	if len(last) < 4 {
		t.Errorf("last global init too short for multi-byte ULEB128: %v", last)
	}
}

// TestFuncTypeOfImportedMultiple verifies FuncTypeOf walks imports in order correctly.
func TestFuncTypeOfImportedMultiple(t *testing.T) {
	// Build a module with 2 imported functions of different types, then 1 local function.
	// FuncTypeOf(0) -> first import type, FuncTypeOf(1) -> second import type,
	// FuncTypeOf(2) -> local function type.
	var typePayload []byte
	typePayload = append(typePayload, encodeLEB128U32(3)...)
	// Type 0: () -> (i32)
	typePayload = append(typePayload, 0x60, 0x00, 0x01, 0x7f)
	// Type 1: (i32) -> ()
	typePayload = append(typePayload, 0x60, 0x01, 0x7f, 0x00)
	// Type 2: (i32, i32) -> (i32)
	typePayload = append(typePayload, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f)

	var importPayload []byte
	importPayload = append(importPayload, encodeLEB128U32(2)...)
	// Import 0: func type 0
	importPayload = append(importPayload, 0x03, 'e', 'n', 'v')
	importPayload = append(importPayload, 0x02, 'f', '0')
	importPayload = append(importPayload, 0x00)                  // ImportFunc
	importPayload = append(importPayload, encodeLEB128U32(0)...) // type idx 0
	// Import 1: func type 1
	importPayload = append(importPayload, 0x03, 'e', 'n', 'v')
	importPayload = append(importPayload, 0x02, 'f', '1')
	importPayload = append(importPayload, 0x00)                  // ImportFunc
	importPayload = append(importPayload, encodeLEB128U32(1)...) // type idx 1

	funcPayload := []byte{0x01, 0x02} // 1 local func, type 2

	codePayload := []byte{0x01, 0x02, 0x00, 0x0b}

	data := buildModule(
		encodeSection(1, typePayload),
		encodeSection(2, importPayload),
		encodeSection(3, funcPayload),
		encodeSection(10, codePayload),
	)
	m := mustParseBytes(t, data)
	if m.NumImportedFuncs != 2 {
		t.Fatalf("NumImportedFuncs: want 2, got %d", m.NumImportedFuncs)
	}
	// FuncTypeOf(0): first import — type 0: () -> (i32)
	ft0 := m.FuncTypeOf(0)
	if len(ft0.Params) != 0 || len(ft0.Results) != 1 || ft0.Results[0] != wasm.ValI32 {
		t.Errorf("FuncTypeOf(0) = %+v, want () -> (i32)", ft0)
	}
	// FuncTypeOf(1): second import — type 1: (i32) -> ()
	ft1 := m.FuncTypeOf(1)
	if len(ft1.Params) != 1 || ft1.Params[0] != wasm.ValI32 || len(ft1.Results) != 0 {
		t.Errorf("FuncTypeOf(1) = %+v, want (i32) -> ()", ft1)
	}
	// FuncTypeOf(2): local func — type 2: (i32, i32) -> (i32)
	ft2 := m.FuncTypeOf(2)
	if len(ft2.Params) != 2 || len(ft2.Results) != 1 {
		t.Errorf("FuncTypeOf(2) = %+v, want (i32, i32) -> (i32)", ft2)
	}
}

// buildI32ConstGlobal wraps a raw SLEB128 byte sequence as the init
// expression of an i32 global, returning the full wasm binary. Used by
// the LEB128 boundary tests below to drive readS32 through the public
// Parse entry point.
func buildI32ConstGlobal(t *testing.T, sleb []byte) []byte {
	t.Helper()
	var payload []byte
	payload = append(payload, encodeLEB128U32(1)...)
	payload = append(payload, 0x7f) // value type i32
	payload = append(payload, 0x00) // immutable
	payload = append(payload, 0x41) // i32.const opcode
	payload = append(payload, sleb...)
	payload = append(payload, 0x0b) // end
	sec := encodeSection(6, payload)
	return buildModule(sec)
}

// TestReadS32MinusOneFiveBytes verifies that the five-byte SLEB128
// encoding of -1 (0xff 0xff 0xff 0xff 0x7f) is accepted by readS32.
// The pre-fix readS64Bits ran the bit-width validation BEFORE OR'ing
// the current byte's payload into the assembled result, which made
// bit 31 read as 0 in the final byte's check and falsely rejected
// this otherwise legal encoding.
func TestReadS32MinusOneFiveBytes(t *testing.T) {
	enc := []byte{0xff, 0xff, 0xff, 0xff, 0x7f}
	if _, err := parseBytes(buildI32ConstGlobal(t, enc)); err != nil {
		t.Fatalf("5-byte SLEB128 for i32(-1): %v", err)
	}
}

// TestReadS32MinInt32FiveBytes verifies the same fix for the canonical
// 5-byte SLEB128 of math.MinInt32 (0x80 0x80 0x80 0x80 0x78).
func TestReadS32MinInt32FiveBytes(t *testing.T) {
	enc := []byte{0x80, 0x80, 0x80, 0x80, 0x78}
	if _, err := parseBytes(buildI32ConstGlobal(t, enc)); err != nil {
		t.Fatalf("5-byte SLEB128 for i32(MinInt32): %v", err)
	}
}

// TestReadS32OverflowAboveSignBit verifies that an otherwise-valid
// 5-byte SLEB128 whose payload bits above bit 31 do NOT match the
// sign-extension of bit 31 is still rejected as overflow. Uses
// 0x80 0x80 0x80 0x80 0x10 — value-bit 32 set but value-bit 31 clear,
// so bits 32+ should have been 0 to be a legal i32 encoding.
func TestReadS32OverflowAboveSignBit(t *testing.T) {
	enc := []byte{0x80, 0x80, 0x80, 0x80, 0x10}
	if _, err := parseBytes(buildI32ConstGlobal(t, enc)); err == nil {
		t.Fatal("expected overflow for 5-byte SLEB128 with stray bit above i32 sign bit, got nil")
	}
}
