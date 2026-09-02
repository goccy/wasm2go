package codegen

import (
	"bytes"
	"go/ast"
	"go/token"
	"math"
	"testing"

	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestNameClassifiers exercises the local-identifier-name classifier.
func TestNameClassifiers(t *testing.T) {
	if !isLocalName("l0") || !isLocalName("l42") {
		t.Error("isLocalName should accept l0/l42")
	}
	if isLocalName("t0") || isLocalName("l") || isLocalName("lx") || isLocalName("") {
		t.Error("isLocalName accepted a non-local name")
	}
}

// TestBasicLitInt covers integer-literal extraction including the unary-minus
// and hex-literal paths.
func TestBasicLitInt(t *testing.T) {
	mk := func(v string) *ast.BasicLit { return &ast.BasicLit{Kind: token.INT, Value: v} }
	if v, ok := basicLitInt(mk("42")); !ok || v != 42 {
		t.Errorf("basicLitInt(42)=(%d,%v)", v, ok)
	}
	if v, ok := basicLitInt(mk("0x1f")); !ok || v != 31 {
		t.Errorf("basicLitInt(0x1f)=(%d,%v)", v, ok)
	}
	neg := &ast.UnaryExpr{Op: token.SUB, X: mk("7")}
	if v, ok := basicLitInt(neg); !ok || v != -7 {
		t.Errorf("basicLitInt(-7)=(%d,%v)", v, ok)
	}
	if _, ok := basicLitInt(&ast.BasicLit{Kind: token.FLOAT, Value: "1.5"}); ok {
		t.Error("basicLitInt accepted a float literal")
	}
	if _, ok := basicLitInt(newID("x")); ok {
		t.Error("basicLitInt accepted an identifier")
	}
}

// TestParseFnDeclName covers the `Fn<N>` / `fn<N>` function-name parser used
// by the multi-package partitioner.
func TestParseFnDeclName(t *testing.T) {
	for _, in := range []string{"Fn0", "fn123", "Fn4294967295"} {
		if _, ok := parseFnDeclName(in); !ok {
			t.Errorf("parseFnDeclName(%q) should succeed", in)
		}
	}
	if v, ok := parseFnDeclName("Fn42"); !ok || v != 42 {
		t.Errorf("parseFnDeclName(Fn42)=(%d,%v)", v, ok)
	}
	for _, in := range []string{"", "Fn", "Xn5", "FnAB", "Fn"} {
		if _, ok := parseFnDeclName(in); ok {
			t.Errorf("parseFnDeclName(%q) should fail", in)
		}
	}
}

// TestIsChunkPkgName covers the `pN` chunk-package-name predicate.
func TestIsChunkPkgName(t *testing.T) {
	for _, in := range []string{"p0", "p12", "p999"} {
		if !isChunkPkgName(in) {
			t.Errorf("isChunkPkgName(%q) should be true", in)
		}
	}
	for _, in := range []string{"p", "px", "base", "0p", "", "P3"} {
		if isChunkPkgName(in) {
			t.Errorf("isChunkPkgName(%q) should be false", in)
		}
	}
}

// TestCapitalize covers the first-rune-uppercasing helper.
func TestCapitalize(t *testing.T) {
	cases := map[string]string{
		"hello": "Hello",
		"World": "World",
		"":      "",
	}
	for in, want := range cases {
		if got := capitalize(in); got != want {
			t.Errorf("capitalize(%q)=%q want %q", in, got, want)
		}
	}
}

// TestMangleModuleHelpers verifies the import-module name manglers.
func TestMangleModuleHelpers(t *testing.T) {
	if got := MangleModuleType("env"); got != "envImports" {
		t.Errorf("MangleModuleType(env)=%q want envImports", got)
	}
	if got := MangleModuleField("wasi_snapshot_preview1"); got == "" {
		t.Errorf("MangleModuleField returned empty")
	}
}

// TestScanStdlibRefs verifies the stdlib-import scanner used by the
// multi-package serializer to compute per-file import blocks.
func TestScanStdlibRefs(t *testing.T) {
	// Build a tiny decl that references math/bits and encoding/binary.
	mkSel := func(pkg, sym string) ast.Expr {
		return &ast.CallExpr{Fun: &ast.SelectorExpr{X: newID(pkg), Sel: newID(sym)}}
	}
	fn := &ast.FuncDecl{
		Name: newID("f"),
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: mkSel("bits", "TrailingZeros32")},
			&ast.ExprStmt{X: mkSel("binary", "LittleEndian")},
		}},
	}
	got := scanStdlibRefs([]ast.Decl{fn})
	want := map[string]bool{"math/bits": true, "encoding/binary": true}
	if len(got) != len(want) {
		t.Fatalf("scanStdlibRefs=%v want keys %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("scanStdlibRefs returned unexpected %q", p)
		}
	}
}

// TestChunkUsedDeps verifies the prior-chunk dependency scanner.
func TestChunkUsedDeps(t *testing.T) {
	mkSel := func(pkg string) ast.Expr {
		return &ast.CallExpr{Fun: &ast.SelectorExpr{X: newID(pkg), Sel: newID("Fn1")}}
	}
	fn := &ast.FuncDecl{
		Name: newID("f"),
		Type: &ast.FuncType{Params: &ast.FieldList{}},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ExprStmt{X: mkSel("p3")},
			&ast.ExprStmt{X: mkSel("p0")},
			&ast.ExprStmt{X: mkSel("base")}, // not a chunk pkg — ignored
		}},
	}
	got := chunkUsedDeps([]ast.Decl{fn})
	if len(got) != 2 || got[0] != 0 || got[1] != 3 {
		t.Errorf("chunkUsedDeps=%v want [0 3]", got)
	}
}

// TestImportShortName covers the import-alias resolution used to decide
// which base-package imports are actually referenced.
func TestImportShortName(t *testing.T) {
	cases := []struct {
		path, alias, want string
	}{
		{"math/bits", "", "bits"},
		{"encoding/binary", "", "binary"},
		{"math", "", "math"},
		{"some/pkg", "alias", "alias"},
		{"some/pkg", "_", "pkg"},
	}
	for _, c := range cases {
		if got := importShortName(c.path, c.alias); got != c.want {
			t.Errorf("importShortName(%q,%q)=%q want %q", c.path, c.alias, got, c.want)
		}
	}
}

// TestEvalConstExprFloat covers the f32/f64 const-expr decoder used for
// float global initializers.
func TestEvalConstExprFloat(t *testing.T) {
	// f32.const 1.5 — opcode 0x43, then 4 LE bytes of float32 bits.
	f32Bits := []byte{0x43, 0x00, 0x00, 0xc0, 0x3f, 0x0b} // 1.5
	if v, err := evalConstExprFloat(f32Bits); err != nil || v != 1.5 {
		t.Errorf("evalConstExprFloat(f32 1.5)=(%v,%v)", v, err)
	}
	// f64.const 2.5 — opcode 0x44, then 8 LE bytes.
	f64Bits := []byte{0x44, 0, 0, 0, 0, 0, 0, 0x04, 0x40, 0x0b} // 2.5
	if v, err := evalConstExprFloat(f64Bits); err != nil || v != 2.5 {
		t.Errorf("evalConstExprFloat(f64 2.5)=(%v,%v)", v, err)
	}
	if _, err := evalConstExprFloat(nil); err == nil {
		t.Error("evalConstExprFloat(nil) should error")
	}
	if _, err := evalConstExprFloat([]byte{0x41, 0x00}); err == nil {
		t.Error("evalConstExprFloat should reject an i32.const opcode")
	}
	if _, err := evalConstExprFloat([]byte{0x43, 0x00}); err == nil {
		t.Error("evalConstExprFloat should reject a truncated f32.const")
	}
}

// TestGoTypeOf covers the wasm-valtype → Go-type AST mapping.
func TestGoTypeOf(t *testing.T) {
	cases := []struct {
		in   wasm.ValType
		want string
	}{
		{wasm.ValI32, "int32"},
		{wasm.ValI64, "int64"},
		{wasm.ValF32, "float32"},
		{wasm.ValF64, "float64"},
		{wasm.ValFuncref, "any"},
		{wasm.ValExternref, "any"},
	}
	for _, c := range cases {
		id, ok := goTypeOf(c.in).(*ast.Ident)
		if !ok || id.Name != c.want {
			t.Errorf("goTypeOf(%v)=%v want %q", c.in, goTypeOf(c.in), c.want)
		}
	}
}

// TestFieldList covers the typed-field-list builder, including the named,
// anonymous, and empty cases.
func TestFieldList(t *testing.T) {
	if fieldList() != nil {
		t.Error("fieldList() with no pairs should be nil")
	}
	fl := fieldList(
		field{name: "x", typ: newID("int32")},
		field{name: "", typ: newID("int64")},
	)
	if fl == nil || len(fl.List) != 2 {
		t.Fatalf("fieldList returned %v", fl)
	}
	if len(fl.List[0].Names) != 1 || fl.List[0].Names[0].Name != "x" {
		t.Errorf("first field should be named x")
	}
	if len(fl.List[1].Names) != 0 {
		t.Errorf("second field should be anonymous")
	}
}

// TestLitHelpers covers the literal-construction helpers.
func TestLitHelpers(t *testing.T) {
	if got := intLit(-42).Value; got != "-42" {
		t.Errorf("intLit(-42)=%q", got)
	}
	if got := uintLit(42).Value; got != "42" {
		t.Errorf("uintLit(42)=%q", got)
	}
	if got := stringLit("hi").Value; got != `"hi"` {
		t.Errorf("stringLit(hi)=%q", got)
	}
}

// TestMangleID covers the identifier mangler: empty, leading-digit,
// special-character, and Go-keyword-collision cases.
func TestMangleID(t *testing.T) {
	cases := map[string]string{
		"":         "_",
		"hello":    "hello",
		"with_us":  "with_us",
		"9lives":   "_9lives", // leading digit → underscore prefix
		"a-b":      "a_x2db",  // '-' → _x<hex>
		"func":     "func_",   // Go keyword → trailing underscore
		"type":     "type_",   // Go keyword
		"normalID": "normalID",
	}
	for in, want := range cases {
		if got := MangleID(in); got != want {
			t.Errorf("MangleID(%q)=%q want %q", in, got, want)
		}
	}
}

// TestExportMethodName covers the wasm-export → Go-method-name mapping,
// including the numeric-segment-preserving rule for bulk exports.
func TestExportMethodName(t *testing.T) {
	cases := map[string]string{
		"add":        "Add",
		"wasm_alloc": "WasmAlloc",
		"w_56_10":    "W_56_10",
		"w_561_0":    "W_561_0",
	}
	seen := map[string]string{}
	for in, want := range cases {
		got := ExportMethodName(in)
		if got != want {
			t.Errorf("ExportMethodName(%q)=%q want %q", in, got, want)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("ExportMethodName collision: %q and %q both → %q", prev, in, got)
		}
		seen[got] = in
	}
	// Every result must start uppercase so the method is exported.
	for in := range cases {
		got := ExportMethodName(in)
		if got == "" || got[0] < 'A' || got[0] > 'Z' {
			t.Errorf("ExportMethodName(%q)=%q is not exported", in, got)
		}
	}
}

// TestEvalConstExprI64 covers the integer const-expr evaluator: i32.const,
// i64.const, the unsupported global.get path, and a bad opcode.
func TestEvalConstExprI64(t *testing.T) {
	// i32.const 100 → 0x41 then signed-LEB128 100 (0xe4 0x00) then 0x0b.
	if v, err := evalConstExprI64([]byte{0x41, 0xe4, 0x00, 0x0b}, nil); err != nil || v != 100 {
		t.Errorf("evalConstExprI64(i32.const 100)=(%d,%v)", v, err)
	}
	// i64.const -1 → 0x42 0x7f 0x0b
	if v, err := evalConstExprI64([]byte{0x42, 0x7f, 0x0b}, nil); err != nil || v != -1 {
		t.Errorf("evalConstExprI64(i64.const -1)=(%d,%v)", v, err)
	}
	// global.get (0x23) is not supported in a const expr.
	if _, err := evalConstExprI64([]byte{0x23, 0x00, 0x0b}, nil); err == nil {
		t.Error("evalConstExprI64 should reject global.get")
	}
	// empty expr.
	if _, err := evalConstExprI64(nil, nil); err == nil {
		t.Error("evalConstExprI64(nil) should error")
	}
	// f32.const opcode is not an integer const-expr.
	if _, err := evalConstExprI64([]byte{0x43, 0, 0, 0, 0, 0x0b}, nil); err == nil {
		t.Error("evalConstExprI64 should reject a float const-expr")
	}
}

// TestFloatInitExpr covers the float-global-initializer expression builder
// for finite and special (NaN/Inf) values, f32 and f64.
func TestFloatInitExpr(t *testing.T) {
	// Finite f32 → float32(<lit>).
	e := floatInitExpr(1.5, true)
	call, ok := e.(*ast.CallExpr)
	if !ok {
		t.Fatalf("floatInitExpr(1.5,f32) returned %T", e)
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "float32" {
		t.Errorf("finite f32 init should cast via float32(), got %v", call.Fun)
	}
	// Finite f64 → float64(<lit>).
	e2 := floatInitExpr(2.5, false)
	if id, ok := e2.(*ast.CallExpr).Fun.(*ast.Ident); !ok || id.Name != "float64" {
		t.Errorf("finite f64 init should cast via float64()")
	}
	// +Inf f32 → math.Float32frombits(...).
	einf := floatInitExpr(math.Inf(1), true)
	if sel, ok := einf.(*ast.CallExpr).Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Float32frombits" {
		t.Errorf("Inf f32 init should route through math.Float32frombits")
	}
	// NaN f64 → math.Float64frombits(...).
	enan := floatInitExpr(math.NaN(), false)
	if sel, ok := enan.(*ast.CallExpr).Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Float64frombits" {
		t.Errorf("NaN f64 init should route through math.Float64frombits")
	}
}

// TestPlanLinknamePackagesPublic exercises the package-public chunk
// planner against an arbitrary parsed module. The behavioural
// guarantees we assert are minimal and stable across any future
// re-balancing of the bin-packing algorithm:
//
//   - The plan returns at least one chunk for a non-empty module.
//   - Every defined function (with a non-empty body) appears in
//     exactly one chunk's func list.
//   - chunkBytes <= 0 falls back to a sane default and still
//     produces a non-empty plan.
//
// No internal field of MultiPackagePlan is inspected beyond what's
// publicly documented — purposefully so a refactor of the planner
// keeps the test green.
func TestPlanLinknamePackagesPublic(t *testing.T) {
	// Use cg_manyfuncs (many small functions) so the planner has
	// to actually distribute across chunks rather than handing the
	// single function back as one chunk.
	bin := testfixture.Wasm(t, "cg_manyfuncs")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("wasm.Parse: %v", err)
	}

	plan, err := PlanLinknamePackages(mod, 1024, nil)
	if err != nil {
		t.Fatalf("PlanLinknamePackages: %v", err)
	}
	if plan == nil || len(plan.Chunks) == 0 {
		t.Fatalf("PlanLinknamePackages returned empty plan")
	}

	// Every defined function with a body must land in exactly one
	// chunk. (The planner may drop dead SCCs when `reachable` is
	// non-nil; we passed nil so the body-count must match.)
	seen := map[uint32]int{}
	for _, ch := range plan.Chunks {
		for _, fidx := range ch.FuncIdxs {
			seen[fidx]++
		}
	}
	for i := range mod.Functions {
		global := mod.NumImportedFuncs + uint32(i)
		if seen[global] != 1 {
			t.Errorf("function %d appears %d times in plan, want 1", global, seen[global])
		}
	}

	// chunkBytes <= 0 is documented to mean "use default". We
	// don't assert what the default IS, just that the plan is
	// still non-empty under it.
	planDefault, err := PlanLinknamePackages(mod, 0, nil)
	if err != nil || planDefault == nil || len(planDefault.Chunks) == 0 {
		t.Errorf("PlanLinknamePackages(chunkBytes=0): err=%v plan=%v", err, planDefault)
	}

	// `reachable` non-nil exercises the dead-SCC drop path. Mark a
	// single function as reachable; the planner must include it
	// (and any SCC it pulls in) but skip the rest.
	if len(mod.Functions) > 0 {
		reach := map[uint32]bool{mod.NumImportedFuncs: true}
		planReach, err := PlanLinknamePackages(mod, 1024, reach)
		if err != nil {
			t.Fatalf("PlanLinknamePackages(reachable=…): %v", err)
		}
		if planReach == nil {
			t.Fatal("PlanLinknamePackages(reachable=…) returned nil plan")
		}
		// We don't assert exactly which functions land — the SCC
		// algorithm decides that. The contract we assert is: the
		// plan stays consistent (every listed function has a
		// non-empty body and exists in the module).
		for _, ch := range planReach.Chunks {
			for _, fidx := range ch.FuncIdxs {
				if fidx < mod.NumImportedFuncs {
					t.Errorf("plan included import-index %d (NumImported=%d)", fidx, mod.NumImportedFuncs)
				}
				local := fidx - mod.NumImportedFuncs
				if int(local) >= len(mod.Functions) {
					t.Errorf("plan referenced local-index %d, max %d", local, len(mod.Functions)-1)
				}
			}
		}
	}
}
