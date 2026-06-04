package asmgen

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/lower"
	"github.com/goccy/wasm2go/internal/ssa"
	"github.com/goccy/wasm2go/internal/testfixture"
	"github.com/goccy/wasm2go/internal/wasm"
)

// assembleARM64 cross-compiles every defined function from the
// given fixture through EmitFuncARM64 and asserts that the Go
// toolchain accepts the resulting plan9 asm. Used as the cheapest
// possible cross-arch validation on an amd64 host: it confirms
// every emitted line is a known instruction with valid operands
// without needing an arm64 runner. Functions that exercise an op
// the prototype doesn't yet support get stubbed (matching the
// amd64 test driver's behavior).
func assembleARM64(t *testing.T, fixture string, moduleSrc string) {
	t.Helper()
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	exportNames := map[uint32]string{}
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc {
			exportNames[e.Index] = e.Name
		}
	}
	funcSymbol := func(idx uint32) string {
		if n, ok := exportNames[idx]; ok {
			return n
		}
		return fmt.Sprintf("Fn%d", idx)
	}
	var asmBuf, declBuf, stubBuf strings.Builder
	for i := range mod.Functions {
		idx := mod.NumImportedFuncs + uint32(i)
		name := funcSymbol(idx)
		fn, err := lower.LowerFunction(mod, idx, name)
		if err != nil {
			t.Fatalf("lower %s: %v", name, err)
		}
		sig := mod.FuncTypeOf(idx)
		asm, decl, err := EmitFuncARM64(name, sig, fn, FuncOptions{
			ModulePkgRef: "*Module",
			Module:       mod,
			FuncSymbol:   funcSymbol,
		})
		if err != nil {
			fmt.Fprintf(&stubBuf, "func %s%s { panic(%q) }\n",
				name, goSignature(sig, "*Module"), "asm stub: "+name)
			continue
		}
		asmBuf.WriteString(asm)
		declBuf.WriteString(decl)
	}

	dir := t.TempDir()
	mustWrite(t, dir, "go.mod", "module asmgentest\n\ngo 1.25\n")
	mustWrite(t, dir, "module.go", moduleSrc)
	mustWrite(t, dir, "decls_arm64.go", "//go:build arm64\n\npackage main\n\n"+declBuf.String())
	mustWrite(t, dir, "asm_arm64.s", "//go:build arm64\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n"+asmBuf.String())
	if stubBuf.Len() > 0 {
		mustWrite(t, dir, "stubs_arm64.go", "//go:build arm64\n\npackage main\n\n"+stubBuf.String())
	}
	mustWrite(t, dir, "main.go", "//go:build arm64\n\npackage main\n\nfunc main() {}\n")
	cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "out"), ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s GOARCH=arm64 build failed: %v\n%s\n\n--- asm ---\n%s", fixture, err, out, asmBuf.String())
	}
}

// TestBuildPackageFilesARM64Assembles cross-builds the
// BuildPackageFiles output for both a wrapper-free fixture (arith)
// and a wrapper-heavy one (cg_globals) to verify the per-arch
// `<arch>.s` + `decls_<arch>.go` + `wrappers.go` triple emits
// internally-consistent symbols on arm64 as well as amd64.
func TestBuildPackageFilesARM64Assembles(t *testing.T) {
	for _, fixture := range []string{"arith", "cg_globals", "cg_indirect"} {
		t.Run(fixture, func(t *testing.T) {
			bin := testfixture.Wasm(t, fixture)
			mod, err := wasm.Parse(bytes.NewReader(bin))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			files, err := BuildPackageFiles(mod, BuildPackageOptions{Package: "main"})
			if err != nil {
				t.Fatalf("BuildPackageFiles: %v", err)
			}
			dir := t.TempDir()
			mustWrite(t, dir, "go.mod", "module asmgentest\n\ngo 1.25\n")
			for path, content := range files {
				mustWrite(t, dir, path, content)
			}
			// Hand-craft the Module + helpers (codegen's full
			// integration would emit these). For arith / cg_globals
			// / cg_indirect the shape that satisfies the asm's
			// references is small enough to inline.
			mustWrite(t, dir, "shared.go", sharedModuleSource(fixture))
			mustWrite(t, dir, "helpers.go", helpersGoSource())
			mustWrite(t, dir, "main.go", "package main\nfunc main() {}\n")
			cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "out"), ".")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("GOARCH=arm64 go build: %v\n%s", err, out)
			}
		})
	}
}

// sharedModuleSource returns the shared (always-on) Go source for a
// given fixture: the Module struct plus any companion declarations
// the asm's CALL-into-Go wrappers need to compile. Naming mirrors
// the single-package codegen translator's conventions (lowercase
// field names, the M field as uppercase).
func sharedModuleSource(fixture string) string {
	switch fixture {
	case "arith":
		return "package main\ntype Module struct{}\n"
	case "cg_globals":
		return `package main
type Module struct {
	g0 int32
	g1 int64
	g2 float32
	g3 float64
	g4 int32
}
`
	case "cg_indirect":
		return `package main
type Module struct {
	t0 []any
	g0 int32
}
`
	}
	return "package main\ntype Module struct{}\n"
}

// TestEmitARM64Assembles cross-builds every fixture through the
// arm64 emitter on an amd64 host. The check is necessarily weaker
// than the amd64 end-to-end tests (the binary never runs), but it
// catches every category of typo go-vet's asm checker can spot:
// unknown mnemonics, mismatched operand shapes, mis-spelled
// condition codes, out-of-range immediates, etc. The fixtures
// exercise every emit path the amd64 tests do.
func TestEmitARM64Assembles(t *testing.T) {
	type fix struct {
		name      string
		moduleSrc string
	}
	for _, f := range []fix{
		{"arith", "package main\ntype Module struct{}\n"},
		{"control", "package main\ntype Module struct{}\n"},
		{"cg_memops", driverWithMemory().moduleSrc},
		{"cg_globals", driverWithGlobals().moduleSrc},
		{"cg_manyfuncs", "package main\ntype Module struct{}\n"},
		{"cg_indirect", driverIndirect().moduleSrc},
		{"asmtest_callimport", driverHostAdd().moduleSrc},
		{"cg_bulkmem", driverBulkMem().moduleSrc},
	} {
		t.Run(f.name, func(t *testing.T) {
			assembleARM64(t, f.name, f.moduleSrc)
		})
	}
}

// TestBuildPackageFilesArith runs the BuildPackageFiles pipeline
// against arith.wat, writes the result into a temporary Go package
// alongside a hand-crafted module + helpers + dispatcher, and
// asserts that the package compiles and produces the same results
// per export as the existing per-function tests.
//
// This is the codegen-integration MVP: instead of the asmgen tests'
// per-test imperative emit loop, the bundle is produced by one call
// to BuildPackageFiles. The integration with codegen.Translate
// itself (auto-splitting the codegen output into shared / fallback /
// asm pieces) is a follow-up — for now the Module struct and helper
// functions are inlined in the test, matching what codegen would
// emit for this fixture (empty Module, two trapping division
// helpers, the rotation helper).
func TestBuildPackageFilesArith(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	files, err := BuildPackageFiles(mod, BuildPackageOptions{Package: "main"})
	if err != nil {
		t.Fatalf("BuildPackageFiles: %v", err)
	}

	// Dispatcher: same shape as the other tests, plus a Module type
	// and the helpers the asm bodies CALL.
	exports := []string{"add", "sub", "mul64", "div_s", "shifts", "rotl", "lt_s", "lt_u"}
	var dispatch strings.Builder
	dispatch.WriteString(`switch os.Args[1] {`)
	for _, name := range exports {
		var sig wasm.FuncType
		for _, e := range mod.Exports {
			if e.Kind == wasm.ExportFunc && e.Name == name {
				sig = mod.FuncTypeOf(e.Index)
			}
		}
		dispatch.WriteString(dispatchCase(name, sig, "nil"))
	}
	dispatch.WriteString(`default: fmt.Fprintln(os.Stderr, "unknown export:", os.Args[1]); os.Exit(2) }`)

	dir := t.TempDir()
	mustWrite(t, dir, "go.mod", "module asmgentest\n\ngo 1.25\n")
	for path, content := range files {
		mustWrite(t, dir, path, content)
	}
	// Always-on shared file: empty Module struct + helpers the asm
	// bodies CALL. The same Module appears in codegen's full Go
	// fallback path; for this MVP we provide it directly so the
	// integration question is "does the asm bundle compose with a
	// drop-in Module / helpers file", which is the load-bearing
	// invariant.
	mustWrite(t, dir, "shared.go", "package main\ntype Module struct{}\n")
	mustWrite(t, dir, "helpers.go", helpersGoSource())
	mustWrite(t, dir, "main.go", `package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: driver <export> args...")
		os.Exit(2)
	}
	`+dispatch.String()+`
}
`)

	exe := filepath.Join(dir, "driver")
	cb := exec.Command("go", "build", "-o", exe, ".")
	cb.Dir = dir
	if out, err := cb.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s\n\n--- files ---\n%v", err, out, fileList(files))
	}
	for _, c := range []driverCase{
		{"add", []string{"2", "3"}, "5"},
		{"sub", []string{"10", "3"}, "7"},
		{"mul64", []string{"6", "7"}, "42"},
		{"div_s", []string{"20", "4"}, "5"},
		{"rotl", []string{"1", "1"}, "2"},
		{"lt_s", []string{"-1", "1"}, "1"},
		{"lt_u", []string{"-1", "1"}, "0"},
	} {
		args := append([]string{c.export}, c.args...)
		out, err := exec.Command(exe, args...).CombinedOutput()
		if err != nil {
			t.Errorf("%s(%v): %v\n%s", c.export, c.args, err, out)
			continue
		}
		if got := strings.TrimSpace(string(out)); got != c.want {
			t.Errorf("%s(%v) = %q, want %q", c.export, c.args, got, c.want)
		}
	}
}

func fileList(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// TestEmitArithAMD64 is the 2.1 milestone: every export of arith.wat
// is lowered to amd64 asm and the asm is exercised through a small
// driver binary. The driver dispatches on the export name so all
// fixtures share one compile cycle — `go build` then a single binary
// invoked per case, instead of paying the toolchain cost per case
// via `go run`. The set of inputs per export covers signed, unsigned,
// and wrap-around edges.
// driverCase is one input/output expectation for the in-driver
// dispatcher. The dispatcher reads its export name and args from
// os.Args, calls into asm, prints the result, and the test compares
// stdout against want.
type driverCase struct {
	export string
	args   []string
	want   string
}

// buildAndRunDriver lowers each export in the given fixture, emits
// amd64 asm, drops everything into a tmp Go module that builds into
// a single dispatcher binary, then runs the binary once per case
// and asserts the output. Used by every fixture-driven test.
//
// driver describes the per-fixture Module type and initialization
// (zero-sized placeholder for the arith / control fixtures; a real
// memory-backed Module for the memops fixture).
func buildAndRunDriver(t *testing.T, fixture string, exports []string, driver driverModule, cases []driverCase) {
	t.Helper()
	bin := testfixture.Wasm(t, fixture)
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// Default funcSymbol: export-name when the wasm function is
	// exported, Fn<funcIdx> otherwise. The fixture's own driverModule
	// can override.
	exportNames := map[uint32]string{}
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc {
			exportNames[e.Index] = e.Name
		}
	}
	funcSymbol := driver.funcSymbol
	if funcSymbol == nil {
		funcSymbol = func(idx uint32) string {
			if n, ok := exportNames[idx]; ok {
				return n
			}
			return fmt.Sprintf("Fn%d", idx)
		}
	}

	// Emit every defined function. Direct callees that aren't
	// exported still need an asm body so cross-function CALLs can
	// resolve; emitting them all also makes the driver layout match
	// the codegen translator's emission semantics.
	//
	// Functions whose ops aren't yet supported by the emitter get a
	// Go-side stub that panics if called. The fixture's test cases
	// pick which exports to exercise, so silently stubbing the un-
	// implemented ones keeps the dispatcher buildable until the
	// emitter catches up.
	var asmBuf, declBuf, stubBuf strings.Builder
	for i := range mod.Functions {
		funcIdx := mod.NumImportedFuncs + uint32(i)
		name := funcSymbol(funcIdx)
		fn, err := lower.LowerFunction(mod, funcIdx, name)
		if err != nil {
			t.Fatalf("lower %s (fn%d): %v", name, funcIdx, err)
		}
		sig := mod.FuncTypeOf(funcIdx)
		asm, decl, err := EmitFuncAMD64(name, sig, fn, FuncOptions{
			ModulePkgRef: "*Module",
			Module:       mod,
			FuncSymbol:   funcSymbol,
		})
		if err != nil {
			t.Logf("emit %s skipped (%v); stubbing", name, err)
			fmt.Fprintf(&stubBuf, "func %s%s { panic(\"asm stub: %s\") }\n",
				name, goSignature(sig, "*Module"), name)
			continue
		}
		asmBuf.WriteString(asm)
		declBuf.WriteString(decl)
	}

	var dispatch strings.Builder
	dispatch.WriteString(`switch os.Args[1] {`)
	for _, name := range exports {
		var sig wasm.FuncType
		found := false
		for idx, ename := range exportNames {
			if ename == name {
				sig = mod.FuncTypeOf(idx)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("export %q missing in %s", name, fixture)
		}
		dispatch.WriteString(dispatchCase(name, sig, driver.modExpr))
	}
	dispatch.WriteString(`default: fmt.Fprintln(os.Stderr, "unknown export:", os.Args[1]); os.Exit(2) }`)

	wrappers := ""
	if driver.importWrappers != nil {
		wrappers = driver.importWrappers(mod)
	}

	dir := t.TempDir()
	writeDriverModule(t, dir, driver, asmBuf.String(), declBuf.String(), stubBuf.String(), wrappers, dispatch.String())

	exe := filepath.Join(dir, "driver")
	cb := exec.Command("go", "build", "-o", exe, ".")
	cb.Dir = dir
	if out, err := cb.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s\n\n--- asm ---\n%s", err, out, asmBuf.String())
	}

	for _, tc := range cases {
		args := append([]string{tc.export}, tc.args...)
		out, err := exec.Command(exe, args...).CombinedOutput()
		if err != nil {
			t.Errorf("%s(%v): %v\n%s", tc.export, tc.args, err, out)
			continue
		}
		got := strings.TrimSpace(string(out))
		if got != tc.want {
			t.Errorf("%s(%v) = %q, want %q", tc.export, tc.args, got, tc.want)
		}
	}
}

// driverModule bundles the per-fixture pieces the driver template
// interpolates: the Module type declaration, the expression each
// dispatchCase substitutes for the m parameter (`nil` or a global
// `modPtr` pointing at an initialised instance), the callee-
// naming callback the asm emitter uses to resolve OpCallDirect
// targets, and the host-import wrapper generator. funcSymbol and
// importWrappers are nil when the fixture has no direct calls or
// no host imports respectively.
type driverModule struct {
	moduleSrc      string
	modExpr        string
	funcSymbol     func(funcIdx uint32) string
	importWrappers func(mod *wasm.Module) string
}

// driverPlaceholder is the Module type for tests whose asm does
// not dereference the receiver pointer (no memory access, no
// globals). Zero size keeps it valid as a non-nil pointer source
// without pulling unsafe into the test code path.
var driverPlaceholder = driverModule{
	moduleSrc: `package main

type Module struct{}
`,
	modExpr: "nil",
}

// driverWithMemory builds a Module containing a real linear-memory
// slice with the cg_memops data segment pre-loaded. The Module's
// layout (Memory []byte; MaxMem uint64; M unsafe.Pointer) matches
// the codegen translator's emission, including the byte offset of
// the M field (32) hard-coded by the emitter as moduleMOffset.
func driverWithMemory() driverModule {
	return driverModule{
		moduleSrc: `package main

import "unsafe"

// Module matches the layout the codegen translator emits in multi-
// package mode: linear-memory slice header, max-pages tracker, and a
// cached data pointer. moduleMOffset in the emitter pins M's offset
// to 32; this struct must keep it stable.
type Module struct {
	Memory []byte
	MaxMem uint64
	M      unsafe.Pointer
}

var modPtr *Module

func init() {
	mem := make([]byte, 2*65536) // 2 wasm pages — matches cg_memops.wat
	copy(mem, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	modPtr = &Module{
		Memory: mem,
		MaxMem: 8 * 65536,
		M:      unsafe.Pointer(&mem[0]),
	}
}

// memorySize / memoryGrow mirror codegen's helpers/helpers.go names
// because asmgen routes OpMemSize / OpMemGrow to those symbols
// (·memorySize(SB) / ·memoryGrow(SB)) — emitting duplicate copies
// in the asmgen wrappers would conflict with codegen's emission.
func memorySize(m *Module) int32 { return int32(len(m.Memory) / 65536) }

func memoryGrow(m *Module, delta int32) int32 {
	if delta < 0 {
		return -1
	}
	cur := int32(len(m.Memory) / 65536)
	want := uint64(cur+delta) * 65536
	if want > m.MaxMem {
		return -1
	}
	grown := make([]byte, want)
	copy(grown, m.Memory)
	m.Memory = grown
	m.M = unsafe.Pointer(&grown[0])
	return cur
}
`,
		modExpr: "modPtr",
	}
}

func TestEmitArithAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{"add", "sub", "mul64", "div_s", "shifts", "rotl", "lt_s", "lt_u"}
	cases := []driverCase{
		{"add", []string{"2", "3"}, "5"},
		{"add", []string{"-5", "-7"}, "-12"},
		{"add", []string{"2147483647", "1"}, "-2147483648"},
		{"sub", []string{"10", "3"}, "7"},
		{"sub", []string{"0", "1"}, "-1"},
		{"sub", []string{"-2147483648", "1"}, "2147483647"},
		{"mul64", []string{"6", "7"}, "42"},
		{"mul64", []string{"-3", "5"}, "-15"},
		{"mul64", []string{"4294967296", "4294967296"}, "0"},
		{"div_s", []string{"20", "4"}, "5"},
		{"div_s", []string{"-20", "4"}, "-5"},
		{"div_s", []string{"-20", "-4"}, "5"},
		{"shifts", []string{"1", "4"}, "1"},
		{"shifts", []string{"7", "1"}, "7"},
		{"rotl", []string{"1", "1"}, "2"},
		{"rotl", []string{"1", "31"}, "-2147483648"},
		{"rotl", []string{"-2147483648", "1"}, "1"},
		{"lt_s", []string{"-1", "1"}, "1"},
		{"lt_s", []string{"1", "-1"}, "0"},
		{"lt_u", []string{"-1", "1"}, "0"},
		{"lt_u", []string{"1", "-1"}, "1"},
	}
	buildAndRunDriver(t, "arith", exports, driverPlaceholder, cases)
}

// TestEmitControlAMD64 is the 2.2 milestone: multi-block CFGs with
// loops (fact, gcd), if/else value-merge (max), and br_table dispatch
// chains (switch3). The asm exercises BlockIf, BlockPlain, BlockRet,
// OpPhi via predecessor-edge copies, and the staged-phi cycle breaker
// on loop back-edges.
func TestEmitControlAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{"max", "fact", "gcd", "switch3"}
	cases := []driverCase{
		// max(a, b) = a > b ? a : b
		{"max", []string{"3", "5"}, "5"},
		{"max", []string{"5", "3"}, "5"},
		{"max", []string{"-1", "1"}, "1"},
		{"max", []string{"42", "42"}, "42"},
		// fact(n) = n! for n >= 0; n*0 ⇒ result 0 because fact's loop
		// uses r := 1 initially but the multiplication keeps using i
		// down to 0, then exits — wait, let me re-derive:
		//   r := 1; i := n
		//   while i != 0: r *= i; i--
		//   return r
		// fact(0)=1, fact(1)=1, fact(5)=120, fact(7)=5040.
		{"fact", []string{"0"}, "1"},
		{"fact", []string{"1"}, "1"},
		{"fact", []string{"5"}, "120"},
		{"fact", []string{"7"}, "5040"},
		// gcd(a, b) by Euclid's mod algorithm.
		{"gcd", []string{"48", "18"}, "6"},
		{"gcd", []string{"54", "24"}, "6"},
		{"gcd", []string{"17", "5"}, "1"},
		{"gcd", []string{"100", "0"}, "100"},
		// switch3 — br_table dispatch chain.
		{"switch3", []string{"0"}, "100"},
		{"switch3", []string{"1"}, "200"},
		{"switch3", []string{"2"}, "300"},
		{"switch3", []string{"3"}, "999"},
		{"switch3", []string{"42"}, "999"},
	}
	buildAndRunDriver(t, "control", exports, driverPlaceholder, cases)
}

// TestEmitLoopPhiBlockIfAMD64 is a regression for a BlockIf-with-phi
// bug in the asm emitter: the predecessor-end phi edge-copies were
// emitted unconditionally before the conditional jump, so the loop's
// back-edge phi target (e.g. `p = mem[p+20]`) clobbered the loop
// variable even on the exit-edge fall-through. Symptoms surfaced in
// the googlesql dlmalloc tree-walk inside Fn39263 (free()): the walk
// exited with p = 0 instead of the last live tree node, downstream
// code observed empty smallbins, and subsequent mallocs returned the
// wrong chunk — eventually loading a ~4 GiB out-of-bounds address
// and SIGSEGVing. Pure-Go didn't hit this because emit_ssa.go places
// phi assigns INSIDE the if/else branches; the asm path is now fixed
// to mirror that structure.
//
// The test constructs the smallest SSA shape that exhibits the bug —
// a single block whose terminator is a BlockIf with one self-loop
// successor and one exit successor, hosting a phi whose back-edge
// value differs from its entry value — then emits the asm body and
// asserts (a) that the back-edge phi copy is routed through a
// per-branch intermediate label (proving conditional emission) and
// (b) that the exit-edge does NOT execute that copy.
//
// We can't trigger the buggy SSA shape from a stock .wat fixture:
// every wat structure we tried either splits the loop body into a
// separate BlockPlain (where unconditional copies are harmless) or
// uses `local.tee` (which SSA-aliases the loop variable with the
// loaded value, so even the bug-free output observes p = 0 at exit).
// Building the SSA directly with FuncBuilder gives a faithful repro
// without depending on the optimizer's blocking decisions.
func TestEmitLoopPhiBlockIfAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	// SSA: f(start i32) i32 {
	//   b0: jmp b1            // entry; gets phi.in = start
	//   b1 (BlockIf, hosts phi p):
	//     p = phi(start from b0, p_next from b1)
	//     p_next = load[p+20]
	//     if p_next != 0 -> b1 (self), else b2
	//   b2 (BlockRet): return p
	// }
	// On the b1->b1 back edge, phi(p) = p_next. On the b1->b2 exit
	// edge, phi values are not relevant (b2 has no phis), so the
	// back-edge copy must NOT fire on exit. The buggy emitter wrote
	// the back-edge copy at b1's terminator unconditionally,
	// clobbering p before the test — surfacing as p = (last load,
	// = 0) at b2 instead of the last live value.
	sig := wasm.FuncType{Params: []wasm.ValType{wasm.ValI32}, Results: []wasm.ValType{wasm.ValI32}}
	b := ssa.NewFuncBuilder("loopphi", ssa.FuncSig{Params: []ssa.Type{ssa.TypeI32}, Results: []ssa.Type{ssa.TypeI32}})

	b0 := b.NewBlock(ssa.BlockPlain)
	b1 := b.NewBlock(ssa.BlockIf)
	b2 := b.NewBlock(ssa.BlockRet)
	b.SetEntry(b0)

	b.SetCurrent(b0)
	start := b.Param(0, ssa.TypeI32)
	ssa.AddEdge(b0, b1)

	b.SetCurrent(b1)
	// Phi p — two preds: b0 (start) and b1 (p_next, filled in after
	// p_next is created). Phi must come first in the block per the
	// SSA verifier's "phis first" rule, so we emit it before any
	// other value and patch Args[1] once the back-edge value exists.
	pPhi := b.NewValue(ssa.OpPhi, ssa.TypeI32, start, nil)
	off20 := b.Const32(20)
	addr := b.NewValue(ssa.OpAdd32, ssa.TypeI32, pPhi, off20)
	pNext := b.NewValueAuxInt(ssa.OpLoad32, ssa.TypeI32, 0, addr)
	pPhi.Args[1] = pNext
	zero := b.Const32(0)
	isNonZero := b.NewValue(ssa.OpNe32, ssa.TypeBool, pNext, zero)
	b.LinkIf(isNonZero, b1, b2) // then: self (back-edge), else: exit

	b.SetCurrent(b2)
	b.FinishRet(pPhi)

	if err := ssa.Verify(b.Func()); err != nil {
		t.Fatalf("SSA verify: %v", err)
	}
	asm, _, err := EmitFuncAMD64("loopphi", sig, b.Func(), FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("EmitFuncAMD64: %v", err)
	}

	// Assertion (a): the emitter inserted the per-branch intermediate
	// label that the fix introduces. Its presence is the load-bearing
	// signal — without it, the back-edge phi copy is emitted at the
	// block end (the buggy pattern).
	if !strings.Contains(asm, "PHI_") || !strings.Contains(asm, "_then:") {
		t.Errorf("expected per-branch PHI_<n>_then intermediate label in emitted asm:\n%s", asm)
	}
	// Assertion (b): the copy that updates the phi slot from pNext's
	// slot lives INSIDE the PHI_<n>_then region, NOT between the
	// block's last value and the conditional jump. We check by
	// confirming the order:
	//   TESTL ... ; JNE PHI_<id>_then ; JMP <else_label> ; PHI_<id>_then:
	// i.e. the JNE precedes the PHI_ label. A regression would put
	// the phi-copy MOVs before the TESTL/JNE pair.
	jneIdx := strings.Index(asm, "JNE PHI_")
	phiLblIdx := strings.Index(asm, "_then:\n")
	if jneIdx < 0 || phiLblIdx < 0 || jneIdx >= phiLblIdx {
		t.Errorf("expected JNE PHI_<id>_then to precede the PHI_<id>_then: label\n%s", asm)
	}
}

// TestEmitMemopsAMD64 is the 2.3 milestone: linear-memory load /
// store ops at every wasm width, exercised through cg_memops.wat.
// The driver instantiates a real Module with two pages of memory and
// the fixture's data segment pre-loaded; the asm dereferences m.M
// (cached unsafe.Pointer) at the offset moduleMOffset to compute
// effective addresses. Float load/store ops are emitted but not
// asserted by name here — the prototype focuses on the integer
// path that the SQL parser actually relies on. mem_size / mem_grow
// are not yet implemented in the emitter and their exports are
// omitted.
func TestEmitMemopsAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{
		"l_i32", "l_i32_8s", "l_i32_8u", "l_i32_16s", "l_i32_16u",
		"l_i64", "l_i64_8s", "l_i64_8u", "l_i64_16s", "l_i64_16u", "l_i64_32s", "l_i64_32u",
		"s_i32", "s_i32_8", "s_i32_16",
		"s_i64", "s_i64_8", "s_i64_16", "s_i64_32",
		"l_offset", "s_offset",
		"mem_size", "mem_grow",
	}
	// Data segment: bytes [1..16] at offset 0. Driver init() repeats
	// the same content.
	cases := []driverCase{
		// --- i32 loads ---
		{"l_i32", []string{"0"}, "67305985"},   // LE [1,2,3,4]   = 0x04030201
		{"l_i32", []string{"4"}, "134678021"},  // LE [5,6,7,8]   = 0x08070605
		{"l_i32_8u", []string{"0"}, "1"},
		{"l_i32_8u", []string{"7"}, "8"},
		{"l_i32_8s", []string{"0"}, "1"},
		{"l_i32_8s", []string{"7"}, "8"},
		{"l_i32_16u", []string{"0"}, "513"},  // 0x0201
		{"l_i32_16s", []string{"0"}, "513"},
		// --- i64 loads ---
		{"l_i64", []string{"0"}, "578437695752307201"}, // 0x0807060504030201
		{"l_i64_8u", []string{"0"}, "1"},
		{"l_i64_8s", []string{"15"}, "16"},
		{"l_i64_16u", []string{"0"}, "513"},
		{"l_i64_16s", []string{"0"}, "513"},
		{"l_i64_32u", []string{"0"}, "67305985"},
		{"l_i64_32s", []string{"0"}, "67305985"},
		// --- i32 store→load round trips ---
		{"s_i32", []string{"100", "305419896"}, "305419896"}, // 0x12345678
		{"s_i32", []string{"104", "-1"}, "-1"},
		{"s_i32_8", []string{"100", "255"}, "255"},
		{"s_i32_16", []string{"100", "65535"}, "65535"},
		// --- i64 store→load round trips ---
		{"s_i64", []string{"200", "1311768467463790320"}, "1311768467463790320"}, // 0x123456789ABCDEF0
		{"s_i64_8", []string{"200", "255"}, "255"},
		{"s_i64_16", []string{"200", "65535"}, "65535"},
		{"s_i64_32", []string{"200", "4294967295"}, "4294967295"},
		// --- offset memarg ---
		{"l_offset", []string{"0"}, "202050057"},     // offset=8: [9..12] = 0x0C0B0A09
		{"s_offset", []string{"300", "42"}, "42"},     // offset=12: writes at 312, reads at 312
		// memory.size / memory.grow — each test binary starts fresh,
		// so the page count begins at 2 (the .wat declares 2 pages).
		{"mem_size", []string{}, "2"},
		{"mem_grow", []string{"3"}, "2"}, // grow by 3 → returns old size = 2
		{"mem_grow", []string{"-1"}, "-1"},
	}
	buildAndRunDriver(t, "cg_memops", exports, driverWithMemory(), cases)
}

// driverHostAdd is the driver for the OpCallImport fixture. The
// Module carries an interface field `host` (hostImports) whose
// implementation adds the integer args (i32 and i64 variants) and
// records the noop calls so the test can assert side-effects.
func driverHostAdd() driverModule {
	return driverModule{
		moduleSrc: `package main

// hostImports is the wasm-side imports interface the asm
// wrappers dispatch through. Method shape: the host always
// receives *Module as its first parameter so it can reach back
// into memory if it needs to.
type hostImports interface {
	Add(m *Module, a, b int32) int32
	Add64(m *Module, a, b int64) int64
	Noop(m *Module, x int32)
}

// Module is the host-side runtime container. The asm reads m
// directly at FP+0 (it doesn't dereference it for this fixture
// because no memory access goes through it), but the import
// wrappers do.
type Module struct {
	host hostImports
}

type hostImpl struct{ noopSeen int32 }

func (h *hostImpl) Add(_ *Module, a, b int32) int32   { return a + b }
func (h *hostImpl) Add64(_ *Module, a, b int64) int64 { return a + b }
func (h *hostImpl) Noop(_ *Module, x int32)           { h.noopSeen = x }

var modPtr *Module

func init() { modPtr = &Module{host: &hostImpl{}} }
`,
		modExpr: "modPtr",
		importWrappers: func(mod *wasm.Module) string {
			// Emit one wrapper per ImportFunc in declaration order.
			// The funcIdx assigned by wasm matches the loop counter
			// because we only walk ImportFunc entries.
			var b strings.Builder
			var fIdx uint32
			for _, imp := range mod.Imports {
				if imp.Kind != wasm.ImportFunc {
					continue
				}
				sig := mod.Types[imp.TypeIdx]
				fmt.Fprintf(&b, "func callImport_%d", fIdx)
				b.WriteString(goSignature(sig, "*Module"))
				b.WriteString(" {\n\t")
				if len(sig.Results) > 0 {
					b.WriteString("return ")
				}
				// host.<MethodName>(m, args...) — MangleID + capitalize.
				method := capitalizeImport(imp.Name)
				fmt.Fprintf(&b, "m.host.%s(m", method)
				for i := range sig.Params {
					fmt.Fprintf(&b, ", l%d", i)
				}
				b.WriteString(")\n}\n")
				fIdx++
			}
			return b.String()
		},
	}
}

// capitalizeImport mirrors codegen's importMethodName for plain
// ASCII names (which is all the fixture uses): capitalise the
// first letter so the method satisfies an interface declared by
// the test driver. Real codegen routes through MangleID for non-
// ASCII / C++-mangled names; we don't need that for the fixture.
func capitalizeImport(s string) string {
	if s == "" {
		return s
	}
	r := []byte(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] = r[0] - 'a' + 'A'
	}
	return string(r)
}

// driverWithGlobals builds a Module that carries the cg_globals
// fixture's five globals. The driver also generates loadGlobal_N /
// storeGlobal_N wrappers per defined global so OpGlobalGet/Set in
// asm can route through them.
func driverWithGlobals() driverModule {
	moduleSrc := `package main

// Module field names mirror the codegen translator's emission:
// g<idx> (lowercase in single-package mode). The asm-side wrappers
// access these fields by name so any layout change is caught at Go
// compile time.
type Module struct {
	g0 int32   // gi32  (mut)
	g1 int64   // gi64  (mut)
	g2 float32 // gf32  (mut)
	g3 float64 // gf64  (mut)
	g4 int32   // cimmu (immut)
}

var modPtr *Module

func init() { modPtr = &Module{g0: 11, g1: 22, g2: 1.5, g3: 2.5, g4: 99} }

// Per-global wrappers (one load + one store per global) — declared
// here rather than emitted by the importWrappers callback because
// the cg_globals fixture has no host imports. A future asmgen
// integration with the codegen translator would unify the two
// wrapper emit paths under one Driver-aware generator.
func loadGlobal_0(m *Module) int32      { return m.g0 }
func storeGlobal_0(m *Module, v int32)  { m.g0 = v }
func loadGlobal_1(m *Module) int64      { return m.g1 }
func storeGlobal_1(m *Module, v int64)  { m.g1 = v }
func loadGlobal_2(m *Module) float32    { return m.g2 }
func storeGlobal_2(m *Module, v float32){ m.g2 = v }
func loadGlobal_3(m *Module) float64    { return m.g3 }
func storeGlobal_3(m *Module, v float64){ m.g3 = v }
func loadGlobal_4(m *Module) int32      { return m.g4 }
`
	return driverModule{moduleSrc: moduleSrc, modExpr: "modPtr"}
}

// driverIndirect builds the Module for cg_indirect.wat. It needs
//   - a `t0 []any` field for the funcref table,
//   - a `g0 int32` field for the $sink global,
//   - one callIndirect_typeN wrapper per wasm type used by an
//     OpCallIndirect (5 types in this fixture),
//   - loadGlobal_0 / storeGlobal_0 wrappers,
//   - an init() that fills t0[0..6] with the asm-emitted function
//     pointers in the order the elem segment specifies.
func driverIndirect() driverModule {
	moduleSrc := `package main

type Module struct {
	t0 []any
	g0 int32 // $sink
}

var modPtr *Module

func init() {
	modPtr = &Module{
		t0: make([]any, 12),
		g0: 0,
	}
	// elem (i32.const 0) $negate $dbl $addp $subp $mul64 $const7 $store
	// — funcIdx 0..6 in this fixture (no imports).
	modPtr.t0[0] = Fn0
	modPtr.t0[1] = Fn1
	modPtr.t0[2] = Fn2
	modPtr.t0[3] = Fn3
	modPtr.t0[4] = Fn4
	modPtr.t0[5] = Fn5
	modPtr.t0[6] = Fn6
}

func loadGlobal_0(m *Module) int32     { return m.g0 }
func storeGlobal_0(m *Module, v int32) { m.g0 = v }

// callIndirect wrappers — one per wasm type used by an
// OpCallIndirect. Each does the type assertion that the asm
// can't easily do by itself, then calls the resulting func ptr.
//   type 0 ($unary):    (param i32) -> i32
//   type 1 ($binary):   (param i32 i32) -> i32
//   type 2 ($i64bin):   (param i64 i64) -> i64
//   type 3 ($noargs):   () -> i32
//   type 4 ($voidproc): (param i32) -> ()
func callIndirect_type0(m *Module, idx int32, p0 int32) int32 {
	return m.t0[idx].(func(*Module, int32) int32)(m, p0)
}
func callIndirect_type1(m *Module, idx int32, p0, p1 int32) int32 {
	return m.t0[idx].(func(*Module, int32, int32) int32)(m, p0, p1)
}
func callIndirect_type2(m *Module, idx int32, p0, p1 int64) int64 {
	return m.t0[idx].(func(*Module, int64, int64) int64)(m, p0, p1)
}
func callIndirect_type3(m *Module, idx int32) int32 {
	return m.t0[idx].(func(*Module) int32)(m)
}
func callIndirect_type4(m *Module, idx int32, p0 int32) {
	m.t0[idx].(func(*Module, int32))(m, p0)
}
`
	return driverModule{moduleSrc: moduleSrc, modExpr: "modPtr"}
}

// TestEmitCallIndirectAMD64 covers OpCallIndirect against
// cg_indirect.wat. Each `call_indirect (type $T)` lowers to a CALL
// of a per-type Go wrapper that performs the runtime
// type-assertion the asm can't easily express by itself. Globals
// (via $sink for the void-returning indirect path) and direct
// calls (direct_chain) flow through the same emitter pipeline.
func TestEmitCallIndirectAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{
		"ind_unary", "ind_binary", "ind_i64", "ind_noargs", "ind_void",
		"direct_chain",
	}
	cases := []driverCase{
		// ind_unary: table[which](x)
		{"ind_unary", []string{"0", "5"}, "-5"},   // negate(5)
		{"ind_unary", []string{"1", "5"}, "10"},   // dbl(5)
		{"ind_unary", []string{"0", "-7"}, "7"},   // negate(-7)
		// ind_binary: table[which](a, b)
		{"ind_binary", []string{"2", "3", "4"}, "7"},   // addp
		{"ind_binary", []string{"3", "10", "3"}, "7"},  // subp
		// ind_i64
		{"ind_i64", []string{"4", "6", "7"}, "42"},     // mul64
		// ind_noargs
		{"ind_noargs", []string{"5"}, "7"},             // const7
		// ind_void: stores its arg to $sink, returns $sink
		{"ind_void", []string{"6", "42"}, "42"},
		// direct_chain(x) = dbl(addp(negate(x), 100)) = 2*(-x+100)
		{"direct_chain", []string{"5"}, "190"},
		{"direct_chain", []string{"-50"}, "300"},
	}
	buildAndRunDriver(t, "cg_indirect", exports, driverIndirect(), cases)
}

// TestEmitGlobalsAMD64 covers OpGlobalGet / OpGlobalSet against
// cg_globals.wat. Each wasm global lives as a field on the host
// Module struct, and the asm reads/writes via loadGlobal_<idx> /
// storeGlobal_<idx> wrappers the driver emits. Float ops that route
// through helper calls (bump_f64) are tested only when those
// helpers are wired up; bump_f64 is left to a future step.
func TestEmitGlobalsAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{
		"get_i32", "set_i32",
		"get_i64", "set_i64",
		"get_f32", "set_f32",
		"get_f64", "set_f64",
		"get_const",
		"bump_i32",
	}
	cases := []driverCase{
		{"get_i32", nil, "11"},
		{"get_i64", nil, "22"},
		{"get_f32", nil, "1.5"},
		{"get_f64", nil, "2.5"},
		{"get_const", nil, "99"},
		// set_X are void — the dispatcher prints "ok" on success.
		{"set_i32", []string{"77"}, "ok"},
		{"set_i64", []string{"77"}, "ok"},
		{"set_f32", []string{"7.25"}, "ok"},
		{"set_f64", []string{"7.25"}, "ok"},
		// bump_i32: round-trip through the global within one call.
		{"bump_i32", []string{"0"}, "11"},
		{"bump_i32", []string{"100"}, "111"},
		{"bump_i32", []string{"-5"}, "6"},
	}
	buildAndRunDriver(t, "cg_globals", exports, driverWithGlobals(), cases)
}

// TestEmitCallImportAMD64 covers OpCallImport — wasm `call` of an
// imported function — by routing each call through a generated Go
// wrapper that dispatches via the Module's hostImports interface.
// The fixture exposes three import shapes: i32 args + i32 result,
// i64 args + i64 result, and a void-returning call. The asm CALLs a
// uniformly-named `callImport_<funcIdx>` symbol; the test driver
// emits one wrapper per import, generated from `mod.Imports`.
func TestEmitCallImportAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{"call_hostadd", "call_hostadd64", "call_hostnoop"}
	cases := []driverCase{
		{"call_hostadd", []string{"3", "4"}, "7"},
		{"call_hostadd", []string{"-100", "100"}, "0"},
		{"call_hostadd", []string{"2147483647", "1"}, "-2147483648"}, // i32 wrap
		{"call_hostadd64", []string{"1000000000000", "1"}, "1000000000001"},
		{"call_hostadd64", []string{"-1", "1"}, "0"},
		// call_hostnoop returns x+1 after a no-op host call.
		{"call_hostnoop", []string{"0"}, "1"},
		{"call_hostnoop", []string{"41"}, "42"},
	}
	buildAndRunDriver(t, "asmtest_callimport", exports, driverHostAdd(), cases)
}

// driverBulkMem builds a Module with linear memory plus
// memoryCopy / memoryFill wrappers for the bulk-memory ops. The
// initial memory contents come from the cg_bulkmem fixture's data
// segment ("abcdefghij" at offset 0).
func driverBulkMem() driverModule {
	return driverModule{
		moduleSrc: `package main

import "unsafe"

type Module struct {
	Memory []byte
	MaxMem uint64
	M      unsafe.Pointer
}

var modPtr *Module

func init() {
	mem := make([]byte, 65536)
	copy(mem, []byte("abcdefghij"))
	modPtr = &Module{
		Memory: mem,
		MaxMem: 65536,
		M:      unsafe.Pointer(&mem[0]),
	}
}

// memoryCopy implements wasm memory.copy: copy n bytes from src to
// dst within the linear memory, with the overlap-correct semantics
// the wasm spec requires (Go's built-in copy handles this).
func memoryCopy(m *Module, dst, src, n int32) {
	if n <= 0 {
		return
	}
	copy(m.Memory[dst:dst+n], m.Memory[src:src+n])
}

// memoryFill writes the low byte of val to n bytes starting at addr.
func memoryFill(m *Module, addr, val, n int32) {
	if n <= 0 {
		return
	}
	b := byte(val)
	for i := int32(0); i < n; i++ {
		m.Memory[addr+i] = b
	}
}
`,
		modExpr: "modPtr",
	}
}

// TestEmitBulkMemAMD64 covers OpMemoryCopy and OpMemoryFill against
// cg_bulkmem.wat. The fixture's saturating-trunc exports use
// f-conversion helpers the prototype doesn't wire up yet; they're
// silently stubbed and not asserted here.
func TestEmitBulkMemAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{"mem_copy", "mem_fill", "load16_s", "store16", "load64"}
	cases := []driverCase{
		// mem_copy(dst=20, src=0, n=4) copies "abcd" into mem[20..],
		// then returns mem[20] as a u8 → 'a' = 97.
		{"mem_copy", []string{"20", "0", "4"}, "97"},
		// mem_fill(addr=100, val=0xAA, n=8) writes 8 copies of 0xAA at
		// mem[100..108]; returning mem[100] u8 → 0xAA = 170.
		{"mem_fill", []string{"100", "170", "8"}, "170"},
		// Sanity-check the surrounding load/store ops are still happy
		// in the same driver.
		{"load16_s", []string{"0"}, "25185"},   // 'a' (0x61) + 'b'<<8 (0x6200) = 0x6261
		{"load64", []string{"0"}, "7523094288207667809"}, // "abcdefgh" little-endian
	}
	buildAndRunDriver(t, "cg_bulkmem", exports, driverBulkMem(), cases)
}

// TestEmitCallDirectAMD64 covers OpCallDirect with cg_manyfuncs.wat:
// `sum_all(x)` invokes thirty `leaf<i>` functions in sequence and
// adds the results. Each leaf computes `x * (i+1) + 3*i`, so
// `sum_all(x) = sum_{i=0..29}[x*(i+1) + 3*i] = 465*x + 1305`. The
// fixture also exposes ops the prototype emitter doesn't support yet
// (call_indirect, global.get / global.set, memory.size); those are
// silently stubbed by the driver and never invoked from the cases
// below.
func TestEmitCallDirectAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	exports := []string{"sum_all"}
	expected := func(x int32) string {
		return fmt.Sprintf("%d", 465*x+1305)
	}
	cases := []driverCase{
		{"sum_all", []string{"0"}, expected(0)},
		{"sum_all", []string{"1"}, expected(1)},
		{"sum_all", []string{"-1"}, expected(-1)},
		{"sum_all", []string{"7"}, expected(7)},
		{"sum_all", []string{"100"}, expected(100)},
		{"sum_all", []string{"-100"}, expected(-100)},
	}
	buildAndRunDriver(t, "cg_manyfuncs", exports, driverPlaceholder, cases)
}

// dispatchCase emits the `case "<name>": ... <call> ...` arm for one
// export. Inputs are parsed from os.Args, the function is called
// with modExpr as the first (m *Module) argument, and the result is
// printed. modExpr is "nil" for tests whose asm never dereferences
// m (the arith / control fixtures) and "modPtr" for tests that need
// a real backing memory (the memops fixture); the driver template
// declares modPtr accordingly.
func dispatchCase(name string, sig wasm.FuncType, modExpr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "case %q:\n", name)
	args := []string{modExpr}
	for i, p := range sig.Params {
		switch p {
		case wasm.ValI32:
			fmt.Fprintf(&b, "\tv%d, err := strconv.ParseInt(os.Args[%d], 10, 32)\n", i, i+2)
			fmt.Fprintf(&b, "\tif err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }\n")
			args = append(args, fmt.Sprintf("int32(v%d)", i))
		case wasm.ValI64:
			fmt.Fprintf(&b, "\tv%d, err := strconv.ParseInt(os.Args[%d], 10, 64)\n", i, i+2)
			fmt.Fprintf(&b, "\tif err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }\n")
			args = append(args, fmt.Sprintf("v%d", i))
		case wasm.ValF32:
			fmt.Fprintf(&b, "\tv%d, err := strconv.ParseFloat(os.Args[%d], 32)\n", i, i+2)
			fmt.Fprintf(&b, "\tif err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }\n")
			args = append(args, fmt.Sprintf("float32(v%d)", i))
		case wasm.ValF64:
			fmt.Fprintf(&b, "\tv%d, err := strconv.ParseFloat(os.Args[%d], 64)\n", i, i+2)
			fmt.Fprintf(&b, "\tif err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(2) }\n")
			args = append(args, fmt.Sprintf("v%d", i))
		}
	}
	if len(sig.Results) == 0 {
		// void-returning export: print a stable token so the
		// dispatcher's exit status alone signals success.
		fmt.Fprintf(&b, "\t%s(%s)\n\tfmt.Println(\"ok\")\n", name, strings.Join(args, ", "))
	} else {
		fmt.Fprintf(&b, "\tfmt.Println(%s(%s))\n", name, strings.Join(args, ", "))
	}
	return b.String()
}

func writeDriverModule(t *testing.T, dir string, driver driverModule, asm, decls, stubs, wrappers, dispatch string) {
	t.Helper()
	mustWrite(t, dir, "go.mod", "module asmgentest\n\ngo 1.25\n")
	mustWrite(t, dir, "module.go", driver.moduleSrc)
	mustWrite(t, dir, "decls_amd64.go", "//go:build amd64\n\npackage main\n\n"+decls)
	mustWrite(t, dir, "asm_amd64.s", "//go:build amd64\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n"+asm)
	mustWrite(t, dir, "helpers_amd64.go", helpersGoSource())
	if stubs != "" {
		mustWrite(t, dir, "stubs_amd64.go", "//go:build amd64\n\npackage main\n\n"+stubs)
	}
	if wrappers != "" {
		mustWrite(t, dir, "wrappers_amd64.go", "//go:build amd64\n\npackage main\n\n"+wrappers)
	}
	mustWrite(t, dir, "main.go", `package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: driver <export> args...")
		os.Exit(2)
	}
	`+dispatch+`
}
`)
}

func mustWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// helpersGoSource returns the test-local Go source containing every
// helper the asm bodies may CALL. The functions mirror the bodies in
// internal/codegen/helpers/helpers.go; copying them here keeps the
// integration test free of an internal-package import. The build
// constraint matches the asm so this file compiles only on amd64
// (other archs would route through the future Go-source fallback).
func helpersGoSource() string {
	return `//go:build amd64

package main

import (
	"math"
	"math/bits"
)

func i32_eqz(x int32) int32 { if x == 0 { return 1 }; return 0 }
func i64_eqz(x int64) int32 { if x == 0 { return 1 }; return 0 }

func i32_clz(x int32) int32    { return int32(bits.LeadingZeros32(uint32(x))) }
func i32_ctz(x int32) int32    { return int32(bits.TrailingZeros32(uint32(x))) }
func i32_popcnt(x int32) int32 { return int32(bits.OnesCount32(uint32(x))) }
func i64_clz(x int64) int64    { return int64(bits.LeadingZeros64(uint64(x))) }
func i64_ctz(x int64) int64    { return int64(bits.TrailingZeros64(uint64(x))) }
func i64_popcnt(x int64) int64 { return int64(bits.OnesCount64(uint64(x))) }

func i32_rotl(x, y int32) int32 { return int32(bits.RotateLeft32(uint32(x), int(y&31))) }
func i32_rotr(x, y int32) int32 { return int32(bits.RotateLeft32(uint32(x), -int(y&31))) }
func i64_rotl(x, y int64) int64 { return int64(bits.RotateLeft64(uint64(x), int(y&63))) }
func i64_rotr(x, y int64) int64 { return int64(bits.RotateLeft64(uint64(x), -int(y&63))) }

func i32_div_s(x, y int32) int32 {
	if y == -1 && x == math.MinInt32 { panic("wasm: integer overflow") }
	if y == 0 { panic("wasm: integer divide by zero") }
	return x / y
}
func i32_div_u(x, y uint32) uint32 {
	if y == 0 { panic("wasm: integer divide by zero") }
	return x / y
}
func i32_div_u_s(x, y int32) int32 { return int32(i32_div_u(uint32(x), uint32(y))) }
func i32_rem_s(x, y int32) int32 {
	if y == 0 { panic("wasm: integer divide by zero") }
	if y == -1 { return 0 }
	return x % y
}
func i32_rem_u(x, y uint32) uint32 {
	if y == 0 { panic("wasm: integer divide by zero") }
	return x % y
}
func i32_rem_u_s(x, y int32) int32 { return int32(i32_rem_u(uint32(x), uint32(y))) }

func i64_div_s(x, y int64) int64 {
	if y == -1 && x == math.MinInt64 { panic("wasm: integer overflow") }
	if y == 0 { panic("wasm: integer divide by zero") }
	return x / y
}
func i64_div_u(x, y uint64) uint64 {
	if y == 0 { panic("wasm: integer divide by zero") }
	return x / y
}
func i64_div_u_s(x, y int64) int64 { return int64(i64_div_u(uint64(x), uint64(y))) }
func i64_rem_s(x, y int64) int64 {
	if y == 0 { panic("wasm: integer divide by zero") }
	if y == -1 { return 0 }
	return x % y
}
func i64_rem_u(x, y uint64) uint64 {
	if y == 0 { panic("wasm: integer divide by zero") }
	return x % y
}
func i64_rem_u_s(x, y int64) int64 { return int64(i64_rem_u(uint64(x), uint64(y))) }

func i32_wrap_i64(x int64) int32     { return int32(x) }
func i64_extend_i32_s(x int32) int64 { return int64(x) }
func i64_extend_i32_u(x int32) int64 { return int64(uint32(x)) }
func i32_extend8_s(x int32) int32  { return int32(int8(x)) }
func i32_extend16_s(x int32) int32 { return int32(int16(x)) }
func i64_extend8_s(x int64) int64  { return int64(int8(x)) }
func i64_extend16_s(x int64) int64 { return int64(int16(x)) }
func i64_extend32_s(x int64) int64 { return int64(int32(x)) }
`
}

// TestEmitAddAMD64 keeps the original one-function add fixture as a
// fast smoke test. It compiles in ~1s and runs in ~10ms, making it
// useful as the first thing to fail when emitter scaffolding breaks.
func TestEmitAddAMD64(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skipf("amd64-only test (GOARCH=%s)", runtime.GOARCH)
	}
	bin := testfixture.Wasm(t, "arith")
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	addIdx := ^uint32(0)
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc && e.Name == "add" {
			addIdx = e.Index
		}
	}
	if addIdx == ^uint32(0) {
		t.Fatal("missing add export")
	}
	fn, err := lower.LowerFunction(mod, addIdx, "add")
	if err != nil {
		t.Fatalf("lower: %v", err)
	}
	sig := mod.FuncTypeOf(addIdx)
	asm, decl, err := EmitFuncAMD64("add", sig, fn, FuncOptions{ModulePkgRef: "*Module"})
	if err != nil {
		t.Fatalf("emit: %v", err)
	}

	dir := t.TempDir()
	mustWrite(t, dir, "go.mod", "module asmgentest\n\ngo 1.25\n")
	mustWrite(t, dir, "module.go", driverPlaceholder.moduleSrc)
	mustWrite(t, dir, "add.go", "//go:build amd64\n\npackage main\n\n"+decl)
	mustWrite(t, dir, "add_amd64.s", "//go:build amd64\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n"+asm)
	mustWrite(t, dir, "main.go", `package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	a, _ := strconv.ParseInt(os.Args[1], 10, 32)
	b, _ := strconv.ParseInt(os.Args[2], 10, 32)
	fmt.Println(add(nil, int32(a), int32(b)))
}
`)
	cmd := exec.Command("go", "run", ".", "2", "3")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "5" {
		t.Errorf("got %q want 5", out)
	}
}
