package gcasm

import (
	"bytes"
	"fmt"
	"os"
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

// a64FixtureGate mirrors fixtureGate for arm64: translate a wasm
// fixture to pure Go, compile the PURE bodies with gc for arm64,
// transform every fnN into ABI0 arm64 .s (TransformARM64), and run
// transformed vs pure over an input sweep on GOARCH=arm64 (native on
// Apple Silicon).
func a64FixtureGate(t *testing.T, fixture string) {
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
	capDir := t.TempDir()
	{
		files := map[string][]byte{"go.mod": []byte("module gentest\n\ngo 1.25.0\n")}
		for name, data := range pureFiles {
			files["pkg/"+name] = data
		}
		writeTree(capDir, files)
	}

	sigs := parseSigs(pureFiles)
	fnIdxRe := regexp.MustCompile(`^gentest/pkg\.fn(\d+)$`)
	var unresolved []string
	stdSig := gate3StdlibSigs
	calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if std, ok := stdSig[sym]; ok {
			return std.params, std.hasRes, std.res, "·" + std.wrap, true
		}
		if !strings.HasPrefix(sym, "gentest/pkg.") {
			return nil, false, 0, "", false
		}
		name := strings.TrimPrefix(sym, "gentest/pkg.")
		if strings.ContainsAny(name, ".()*") {
			unresolved = append(unresolved, sym)
			return nil, false, 0, "", false
		}
		sig, found := sigs[name]
		if !found || !sig.ok {
			unresolved = append(unresolved, sym)
			return nil, false, 0, "", false
		}
		return sig.params, sig.hasRes, sig.res, "·" + name, true
	}
	transformable := func(idx int) bool {
		ft := mod.FuncTypeOf(uint32(idx) + mod.NumImportedFuncs)
		return len(ft.Results) <= 1
	}

	fns, datas, err := captureArch(capDir, "gentest/pkg", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	dm := map[string]*DataSym{}
	for _, d := range datas {
		dm[d.Name] = d
	}
	pool := &ConstPool{}
	types := &TypeTable{}
	jt := &JTTable{}
	var asmB, declB strings.Builder
	asmB.WriteString("//go:build arm64\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
	declB.WriteString("//go:build arm64\n\npackage pkg\n")
	declB.WriteString(stdlibWrappersArm)
	declB.WriteString("\n")
	var fnIdxs []int
	for _, f := range fns {
		m := fnIdxRe.FindStringSubmatch(f.Name)
		if m == nil {
			continue
		}
		idx, aerr := strconv.Atoi(m[1])
		if aerr != nil {
			t.Fatal(aerr)
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
		body, err := TransformARM64(f, TransformOptions{
			SymName:   fmt.Sprintf("fn%d", idx),
			CalleeSig: calleeSig,
			Params:    params,
			HasResult: hasRes,
			Result:    resKind,
			ArgNames:  names,
			Datas:     dm,
			Consts:    pool,
			Types:     types,
			JT:        jt,
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
		t.Skip("no transformable fnN")
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		t.Fatalf("unresolved callees: %v", unresolved)
	}
	asmB.WriteString(pool.Emit())
	asmB.WriteString(jt.EmitAsm("arm64"))
	declB.WriteString("\n")
	declB.WriteString(jt.EmitGo("arm64"))
	if len(types.Names) > 0 {
		t.Skipf("type refs present (%d) — arm64 type-desc wiring TODO", len(types.Names))
	}

	// Run vs pure: rename pure fnN → fnN_pure, install asm as fnN.
	runDir := t.TempDir()
	transformed := map[string]bool{}
	for _, idx := range fnIdxs {
		transformed[strconv.Itoa(idx)] = true
	}
	renRe := regexp.MustCompile(`\bfn(\d+)\b`)
	runFiles := map[string][]byte{"go.mod": []byte("module gentest\n\ngo 1.25.0\n")}
	for name, data := range pureFiles {
		if strings.HasSuffix(name, ".go") {
			data = renRe.ReplaceAllFunc(data, func(mm []byte) []byte {
				idx := renRe.FindSubmatch(mm)
				if transformed[string(idx[1])] {
					return []byte(string(mm) + "_pure")
				}
				return mm
			})
		}
		runFiles["pkg/"+name] = data
	}
	runFiles["pkg/arm64.s"] = []byte(asmB.String())
	runFiles["pkg/decls_arm64.go"] = []byte(declB.String())

	var driver strings.Builder
	driver.WriteString("package pkg\n\nimport (\n\t\"math\"\n\t\"testing\"\n)\n\nvar _ = math.Float32bits\n\ntype outcome struct{ val int64; panicked bool }\n\nfunc run(f func() int64) (o outcome) {\n\tdefer func() { if recover() != nil { o.panicked = true } }()\n\to.val = f()\n\treturn\n}\n\nfunc TestA64FG(t *testing.T) {\n")
	argSet := []string{"0", "1", "2", "3", "5", "42", "255", "1000"}
	cases := 0
	for _, idx := range fnIdxs {
		ft := mod.FuncTypeOf(uint32(idx) + mod.NumImportedFuncs)
		if len(ft.Results) != 1 {
			continue
		}
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
				for _, bb := range []string{"0", "1", "7"} {
					tup := []string{a, bb}
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
			fmt.Fprintf(&driver, "\t{ g := run(func() int64 { m := New(); return int64(fn%d(m%s)) }); w := run(func() int64 { m := New(); return int64(fn%d_pure(m%s)) }); if g != w { t.Errorf(\"fn%d(%s): asm=%%+v pure=%%+v\", g, w) } }\n", idx, args, idx, args, idx, strings.Join(tup, ","))
			cases++
		}
	}
	driver.WriteString("}\n")
	runFiles["pkg/a64fg_test.go"] = []byte(driver.String())
	writeTree(runDir, runFiles)

	runArm64Gate(t, runDir, "./pkg/", "TestA64FG", asmB.String())
	t.Logf("a64 %s: %d cases, asm matches pure", fixture, cases)
}

var stdlibWrappersArm = `
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

//go:noinline
func gcasmTrapDivZero()      { panic("wasm: integer divide by zero") }
//go:noinline
func gcasmTrapOverflow()     { panic("wasm: integer overflow") }
//go:noinline
func gcasmTrapUnreachable()  { panic("wasm: unreachable") }
//go:noinline
func gcasmTrapBounds()       { panic("wasm: out of bounds access") }
//go:noinline
func gcasmTrapIndirectSig()  { panic("wasm: indirect call type mismatch") }

var (
	_ = gcasmTrapDivZero
	_ = gcasmTrapOverflow
	_ = gcasmTrapUnreachable
	_ = gcasmTrapBounds
	_ = gcasmTrapIndirectSig
)
`

// TestA64Fixtures sweeps the arm64 transform over the codegen corpus.
func TestA64Fixtures(t *testing.T) {
	for _, fx := range []string{
		"control", "cg_brtable64", "cg_bittest", "cg_numerics", "cg_memops",
		"cg_globals", "cg_frame", "cg_nestedloop", "cg_dispatchif", "cg_traps",
		"cg_deadend", "cg_largeoff", "cg_misc", "cg_unreachable", "arith", "ssa_cf",
	} {
		t.Run(fx, func(t *testing.T) { a64FixtureGate(t, fx) })
	}
}
