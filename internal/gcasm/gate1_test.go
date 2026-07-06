package gcasm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// goKindOf maps a Go source type to its ABI kind; ok=false for types
// the marshaller cannot pass (bools, strings, structs, multi-word).
func goKindOf(typ string) (ArgKind, bool) {
	typ = strings.TrimSpace(typ)
	if strings.HasPrefix(typ, "*") || typ == "unsafe.Pointer" || typ == "uintptr" {
		return ArgPtr, true
	}
	switch typ {
	case "int32", "uint32":
		return ArgI32, true
	case "int64", "uint64", "int", "uint":
		return ArgI64, true
	case "float32":
		return ArgF32, true
	case "float64":
		return ArgF64, true
	}
	return 0, false
}

type goSig struct {
	params []ArgKind
	hasRes bool
	res    ArgKind
	ok     bool // every type representable
}

var fnDeclRe = regexp.MustCompile(`(?m)^func ([a-zA-Z_]\w*)\(([^)]*)\)\s*([^{\n]*)\{`)

// parseSigs extracts top-level function signatures from Go sources —
// the transform must marshal EVERY in-package call boundary (ABI0
// stack convention), so the callee table has to cover helpers too,
// not just fnN.
func parseSigs(srcs map[string][]byte) map[string]goSig {
	sigs := map[string]goSig{}
	for name, data := range srcs {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		for _, m := range fnDeclRe.FindAllStringSubmatch(string(data), -1) {
			name, params, results := m[1], m[2], strings.TrimSpace(m[3])
			sig := goSig{ok: true}
			if strings.TrimSpace(params) != "" {
				groups := strings.Split(params, ",")
				// Shared-type parameter groups: `x, y int32` splits
				// into a type-less "x" and "y int32" — a group with
				// only a name inherits the type of the next group
				// that carries one.
				types := make([]string, len(groups))
				for i := len(groups) - 1; i >= 0; i-- {
					fields := strings.Fields(strings.TrimSpace(groups[i]))
					switch {
					case len(fields) >= 2:
						types[i] = fields[len(fields)-1]
					case i+1 < len(groups) && types[i+1] != "" && !strings.ContainsAny(fields[0], ".*"):
						// Bare identifier: a name sharing the next
						// group's type (bare TYPES like `int32` or
						// `*Module` only occur in all-unnamed lists,
						// which generated helpers never use).
						if _, isType := map[string]bool{"int32": true, "uint32": true, "int64": true, "uint64": true, "float32": true, "float64": true}[fields[0]]; isType {
							types[i] = fields[0]
						} else {
							types[i] = types[i+1]
						}
					default:
						types[i] = fields[0]
					}
				}
				for _, typ := range types {
					k, ok := goKindOf(typ)
					if !ok {
						sig.ok = false
						break
					}
					sig.params = append(sig.params, k)
				}
			}
			if sig.ok && results != "" {
				results = strings.TrimPrefix(results, "(")
				results = strings.TrimSuffix(strings.TrimSpace(results), ")")
				parts := strings.Split(results, ",")
				if len(parts) > 1 {
					sig.ok = false
				} else if strings.TrimSpace(parts[0]) != "" {
					fields := strings.Fields(strings.TrimSpace(parts[0]))
					k, ok := goKindOf(fields[len(fields)-1])
					if !ok {
						sig.ok = false
					} else {
						sig.hasRes, sig.res = true, k
					}
				}
			}
			sigs[name] = sig
		}
	}
	return sigs
}

func kindOfVal(v wasm.ValType) ArgKind {
	switch v {
	case wasm.ValI64:
		return ArgI64
	case wasm.ValF32:
		return ArgF32
	case wasm.ValF64:
		return ArgF64
	default:
		return ArgI32
	}
}

func goTypeOfKind(k ArgKind) string {
	switch k {
	case ArgI64:
		return "int64"
	case ArgF32:
		return "float32"
	case ArgF64:
		return "float64"
	}
	return "int32"
}

// fixtureGate pushes one wasm fixture through the whole gc-capture
// path: translate to pure Go, compile the PURE bodies with gc (the
// emitted asm bundle is filtered out — without that the capture only
// sees gc's ABI bridge wrappers around the existing hand-rolled asm),
// transform every fnN into ABI0 .s, then run transformed and pure
// functions side by side over a broad input sweep (values AND panic
// outcomes must agree). Determinism is asserted by capturing the same
// tree from two different directories.
func fixtureGate(t *testing.T, fixture string) {
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatal(err)
	}

	// Pure-capture tree: asm bundle dropped, pure guards stripped.
	pureFiles := map[string][]byte{"gen.go": buf.Bytes()}
	for name, data := range res.Sidecars {
		pureFiles[name] = data
	}
	for name, data := range res.Files {
		pureFiles[name] = data
	}
	pureFiles = PureFilter(pureFiles)

	writeTree := func(dir string, files map[string][]byte) {
		t.Helper()
		for name, data := range files {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	newPureDir := func() string {
		dir := t.TempDir()
		files := map[string][]byte{"go.mod": []byte("module gentest\n\ngo 1.25.0\n")}
		for name, data := range pureFiles {
			files["pkg/"+name] = data
		}
		writeTree(dir, files)
		return dir
	}

	sigs := parseSigs(pureFiles)

	fnIdxRe := regexp.MustCompile(`^gentest/pkg\.fn(\d+)$`)
	localName := func(sym string) (string, bool) {
		if !strings.HasPrefix(sym, "gentest/pkg.") {
			return "", false
		}
		name := strings.TrimPrefix(sym, "gentest/pkg.")
		if strings.ContainsAny(name, ".()*") {
			return "", false // methods, closures — not plain funcs
		}
		return name, true
	}
	// Non-inlinable stdlib callees reached from inlined helper bodies
	// (f64_ceil → math.Ceil, i32_popcnt's non-POPCNT fallback →
	// bits.OnesCount32, ...). Asm can only reference ABI0 symbols and
	// the toolchain materialises ABI0 wrappers from asm references in
	// the SAME package only — so each stdlib callee gets a local Go
	// wrapper function and the marshalled CALL targets that.
	f64unary := goSig{params: []ArgKind{ArgF64}, hasRes: true, res: ArgF64, ok: true}
	cnt32 := goSig{params: []ArgKind{ArgI32}, hasRes: true, res: ArgI64, ok: true}
	cnt64 := goSig{params: []ArgKind{ArgI64}, hasRes: true, res: ArgI64, ok: true}
	stdlibSigs := map[string]struct {
		sig  goSig
		wrap string // local wrapper name
	}{
		"math.Ceil":                 {f64unary, "gcasmMathCeil"},
		"math.Floor":                {f64unary, "gcasmMathFloor"},
		"math.Trunc":                {f64unary, "gcasmMathTrunc"},
		"math.RoundToEven":          {f64unary, "gcasmMathRoundToEven"},
		"math.Sqrt":                 {f64unary, "gcasmMathSqrt"},
		"math/bits.OnesCount32":     {cnt32, "gcasmBitsOnesCount32"},
		"math/bits.OnesCount64":     {cnt64, "gcasmBitsOnesCount64"},
		"math/bits.LeadingZeros32":  {cnt32, "gcasmBitsLeadingZeros32"},
		"math/bits.LeadingZeros64":  {cnt64, "gcasmBitsLeadingZeros64"},
		"math/bits.TrailingZeros32": {cnt32, "gcasmBitsTrailingZeros32"},
		"math/bits.TrailingZeros64": {cnt64, "gcasmBitsTrailingZeros64"},
	}
	const stdlibWrappers = `
import (
	"math"
	"math/bits"
	"unsafe"
)

var _ = unsafe.Pointer(nil)

func gcasmMathCeil(x float64) float64        { return math.Ceil(x) }
func gcasmMathFloor(x float64) float64       { return math.Floor(x) }
func gcasmMathTrunc(x float64) float64       { return math.Trunc(x) }
func gcasmMathRoundToEven(x float64) float64 { return math.RoundToEven(x) }
func gcasmMathSqrt(x float64) float64        { return math.Sqrt(x) }
func gcasmBitsOnesCount32(x uint32) int      { return bits.OnesCount32(x) }
func gcasmBitsOnesCount64(x uint64) int      { return bits.OnesCount64(x) }
func gcasmBitsLeadingZeros32(x uint32) int   { return bits.LeadingZeros32(x) }
func gcasmBitsLeadingZeros64(x uint64) int   { return bits.LeadingZeros64(x) }
func gcasmBitsTrailingZeros32(x uint32) int  { return bits.TrailingZeros32(x) }
func gcasmBitsTrailingZeros64(x uint64) int  { return bits.TrailingZeros64(x) }
`
	var unresolved []string
	calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if std, ok := stdlibSigs[sym]; ok {
			return std.sig.params, std.sig.hasRes, std.sig.res, "·" + std.wrap, true
		}
		name, ok := localName(sym)
		if !ok {
			if strings.HasPrefix(sym, "gentest/") {
				unresolved = append(unresolved, sym)
			}
			return nil, false, 0, "", false
		}
		sig, found := sigs[name]
		if !found || !sig.ok {
			unresolved = append(unresolved, sym)
			return nil, false, 0, "", false
		}
		return sig.params, sig.hasRes, sig.res, "·" + name, true
	}

	// A fnN is transformable when its wasm signature is single- or
	// zero-result (the ABI0 transform handles at most one result).
	transformable := func(idx int) bool {
		ft := mod.FuncTypeOf(uint32(idx) + mod.NumImportedFuncs)
		return len(ft.Results) <= 1
	}

	transformAll := func(dir string) (asm string, decls string, fnIdxs []int) {
		t.Helper()
		fns, datas, err := Capture(dir, "gentest/pkg")
		if err != nil {
			t.Fatal(err)
		}
		dm := map[string]*DataSym{}
		for _, d := range datas {
			dm[d.Name] = d
		}
		var asmB, declB strings.Builder
		asmB.WriteString("#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
		declB.WriteString("//go:build amd64\n\npackage pkg\n")
		declB.WriteString(stdlibWrappers)
		declB.WriteString("\n")
		pool := &ConstPool{}
		types := &TypeTable{}
		for _, f := range fns {
			m := fnIdxRe.FindStringSubmatch(f.Name)
			if m == nil {
				continue
			}
			idx, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatal(err)
			}
			if !transformable(idx) {
				continue
			}
			ft := mod.FuncTypeOf(uint32(idx) + mod.NumImportedFuncs)
			params := []ArgKind{ArgPtr}
			names := []string{"m"}
			var declArgs strings.Builder
			declArgs.WriteString("m *Module")
			for i, p := range ft.Params {
				params = append(params, kindOfVal(p))
				names = append(names, fmt.Sprintf("l%d", i))
				fmt.Fprintf(&declArgs, ", l%d %s", i, goTypeOfKind(kindOfVal(p)))
			}
			hasRes := len(ft.Results) == 1
			var resKind ArgKind
			resDecl := ""
			if hasRes {
				resKind = kindOfVal(ft.Results[0])
				resDecl = fmt.Sprintf(" (r0 %s)", goTypeOfKind(resKind))
			}
			body, err := Transform(f, TransformOptions{
				SymName:   fmt.Sprintf("fn%d", idx),
				CalleeSig: calleeSig,
				Params:    params,
				HasResult: hasRes,
				Result:    resKind,
				ArgNames:  names,
				Datas:     dm,
				Consts:    pool,
				Types:     types,
			})
			if err != nil {
				t.Fatalf("transform %s: %v", f.Name, err)
			}
			asmB.WriteString(body)
			asmB.WriteString("\n")
			fmt.Fprintf(&declB, "func fn%d(%s)%s\n", idx, declArgs.String(), resDecl)
			fnIdxs = append(fnIdxs, idx)
		}
		if len(fnIdxs) == 0 {
			t.Fatal("no fnN captured")
		}
		if len(unresolved) > 0 {
			sort.Strings(unresolved)
			t.Fatalf("unresolved in-module callees (silent ABI mismatch): %v", unresolved)
		}
		asmB.WriteString(pool.Emit())
		// Type descriptor vars: initialise each from an eface's type
		// word — the same descriptor `LEAQ type:F(SB)` would produce.
		// The captured spelling qualifies identifiers with the import
		// path; strip it for the in-package source spelling.
		if len(types.Names) > 0 {
			declB.WriteString("\nfunc gcasmTypePtr(v any) uintptr {\n\treturn *(*uintptr)(unsafe.Pointer(&v))\n}\n\n")
			for i, typ := range types.Names {
				local := strings.ReplaceAll(typ, "gentest/pkg.", "")
				fmt.Fprintf(&declB, "var gcasmType%d = gcasmTypePtr((%s)(nil))\n", i, local)
			}
		}
		// Never-returning trap targets for reachable runtime panics
		// whose register arguments the transform drops.
		declB.WriteString(`
//go:noinline
func gcasmTrapBounds() { panic("wasm: out of bounds access") }

//go:noinline
func gcasmTrapIndirectSig() { panic("wasm: indirect call type mismatch") }

//go:noinline
func gcasmTrapDivZero() { panic("wasm: integer divide by zero") }

//go:noinline
func gcasmTrapOverflow() { panic("wasm: integer overflow") }

//go:noinline
func gcasmTrapUnreachable() { panic("wasm: unreachable") }

var (
	_ = gcasmTrapBounds
	_ = gcasmTrapIndirectSig
	_ = gcasmTrapDivZero
	_ = gcasmTrapOverflow
	_ = gcasmTrapUnreachable
)
`)
		return asmB.String(), declB.String(), fnIdxs
	}

	asm1, decls, fnIdxs := transformAll(newPureDir())
	asm2, _, _ := transformAll(newPureDir())
	if asm1 != asm2 {
		t.Fatalf("transform not deterministic across capture dirs:\n--- run1\n%s\n--- run2\n%s", asm1, asm2)
	}
	t.Logf("captured+transformed %d functions (%v)", len(fnIdxs), fnIdxs)

	// Run transformed asm against the pure bodies. The pure
	// definitions are renamed fnN → fnN_pure (which also rewrites
	// their internal call graph AND any table/funcval references,
	// keeping the pure closure self-consistent); the asm closure
	// takes over the fnN names. Only transformed indices are renamed
	// — untransformed fns keep their single pure definition.
	runDir := t.TempDir()
	transformed := map[string]bool{}
	for _, idx := range fnIdxs {
		transformed[strconv.Itoa(idx)] = true
	}
	renRe := regexp.MustCompile(`\bfn(\d+)\b`)
	runFiles := map[string][]byte{"go.mod": []byte("module gentest\n\ngo 1.25.0\n")}
	for name, data := range pureFiles {
		if strings.HasSuffix(name, ".go") {
			data = renRe.ReplaceAllFunc(data, func(m []byte) []byte {
				idx := renRe.FindSubmatch(m)
				if transformed[string(idx[1])] {
					// Fresh slice: append onto m would scribble into
					// the source buffer it aliases.
					return []byte(string(m) + "_pure")
				}
				return m
			})
		}
		runFiles["pkg/"+name] = data
	}
	runFiles["pkg/gcasm_amd64.s"] = []byte(asm1)
	runFiles["pkg/gcasm_decls.go"] = []byte(decls)

	var driver strings.Builder
	driver.WriteString(`package pkg

import (
	"math"
	"testing"
)

var _ = math.Float32bits

type outcome struct {
	val      int64
	panicked bool
}

func run(f func() int64) (o outcome) {
	defer func() {
		if recover() != nil {
			o.panicked = true
		}
	}()
	o.val = f()
	return o
}

func TestFixtureGate(t *testing.T) {
`)
	// Non-negative only: generated memory ops deref unsafe pointers
	// WITHOUT bounds checks (by design — see PR #4), so a negative
	// value fed into an address parameter hard-faults identically in
	// BOTH the pure and transformed bodies, killing the process before
	// the comparison. Valid-range inputs still walk every code path
	// the transform could have broken.
	argSet := []string{"0", "1", "2", "3", "5", "42", "255", "1000"}
	wrapRes := func(k ArgKind, call string) string {
		switch k {
		case ArgI64:
			return call
		case ArgF32:
			return fmt.Sprintf("int64(math.Float32bits(%s))", call)
		case ArgF64:
			return fmt.Sprintf("int64(math.Float64bits(%s))", call)
		}
		return fmt.Sprintf("int64(%s)", call)
	}
	cases := 0
	for _, idx := range fnIdxs {
		ft := mod.FuncTypeOf(uint32(idx) + mod.NumImportedFuncs)
		if len(ft.Results) != 1 {
			continue
		}
		resKind := kindOfVal(ft.Results[0])
		var tuples [][]string
		switch len(ft.Params) {
		case 0:
			tuples = [][]string{{}}
		case 1:
			for _, a := range argSet {
				tuples = append(tuples, []string{a})
			}
		default:
			for _, a := range argSet {
				for _, b := range []string{"0", "1", "3", "7"} {
					tup := []string{a, b}
					for len(tup) < len(ft.Params) {
						tup = append(tup, "1")
					}
					tuples = append(tuples, tup)
				}
			}
		}
		for _, tup := range tuples {
			args := ""
			for i, a := range tup {
				args += fmt.Sprintf(", %s(%s)", goTypeOfKind(kindOfVal(ft.Params[i])), a)
			}
			asmCall := wrapRes(resKind, fmt.Sprintf("fn%d(m%s)", idx, args))
			pureCall := wrapRes(resKind, fmt.Sprintf("fn%d_pure(m%s)", idx, args))
			fmt.Fprintf(&driver, `	{
		got := run(func() int64 { m := New(); return %s })
		want := run(func() int64 { m := New(); return %s })
		if got != want {
			t.Errorf("fn%d(%s): asm=%%+v pure=%%+v", got, want)
		}
	}
`, asmCall, pureCall, idx, strings.Join(tup, ","))
			cases++
		}
	}
	driver.WriteString("}\n")
	if cases == 0 {
		t.Skip("no single-result fn to drive")
	}
	runFiles["pkg/fixturegate_test.go"] = []byte(driver.String())
	writeTree(runDir, runFiles)

	// -unreachable=false: the generated pure bodies trip the
	// unreachable-code analyzer by design (goto-heavy control flow);
	// the check that matters here is asmdecl over gcasm_amd64.s.
	cmd := exec.Command("go", "vet", "-unreachable=false", "./pkg/")
	cmd.Dir = runDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("vet failed: %v\n%s", err, out)
	}
	cmd = exec.Command("go", "test", "-run", "TestFixtureGate", "./pkg/")
	cmd.Dir = runDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture gate run failed: %v\n%s\n--- asm ---\n%s", err, out, asm1)
	}
	t.Logf("gate: %d comparison cases, asm matches pure", cases)
}

// TestGate1ControlFixture is the original whole-fixture gate.
func TestGate1ControlFixture(t *testing.T) {
	fixtureGate(t, "control")
}

// TestGate2Fixtures sweeps the transform across the wider codegen
// fixture corpus: floats, i64, memory ops, globals, traps, indirect
// calls, dense dispatch.
func TestGate2Fixtures(t *testing.T) {
	for _, fixture := range []string{
		"cg_brtable64",
		"cg_bittest",
		"cg_numerics",
		"cg_allops",
		"cg_memops",
		"cg_globals",
		"cg_frame",
		"cg_nestedloop",
		"cg_sharedexit",
		"cg_dispatchif",
		"cg_traps",
		"cg_indirect",
		"cg_deadend",
		"cg_specialfp",
		"cg_largeoff",
		"cg_misc",
		"cg_unreachable",
		"cg_bigdispatch",
		"arith",
		"ssa_cf",
		"vtable_dispatch",
	} {
		t.Run(fixture, func(t *testing.T) {
			fixtureGate(t, fixture)
		})
	}
}
