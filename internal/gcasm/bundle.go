package gcasm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/wasm2go/internal/asmgen"
	"github.com/goccy/wasm2go/internal/simdfuse"
	"github.com/goccy/wasm2go/internal/wasm"
)

// Build orchestrates the gcasm backend over one translated module:
// filter the translated tree to its pure form, compile it with gc,
// capture the listings, transform every eligible FnN into ABI0 .s,
// and emit the amd64 bundle files. Functions whose own signature
// stack-assigns under ABIInternal (and any transform failure) fall
// back to their pure bodies on amd64 too — per-function fallback
// keeps the bundle correct for every shape.
//
// Inputs: the wasm module (exact FnN signatures), the translated main
// source + result files (as produced by codegen.Translate), and the
// OutputImportPath. Output: a file map to MERGE over the translated
// tree — it re-tags each pure file to `//go:build !amd64`, drops the
// own-backend .s/decls files (returning empty content marks deletion:
// callers skip writing empties), and adds amd64.s +
// decls_amd64.go per package.
type BuildStats struct {
	Transformed int
	Fallback    int
	JumpTables  int
	// SimdSpliced / SimdKept count Simd_* helper call sites: spliced
	// inline vs left as marshalled calls (no table entry for the op).
	SimdSpliced int
	SimdKept    int
	// DirectAsm counts functions whose asm body came straight from
	// the retained SSA (internal/asmgen) instead of the listing
	// transform; DirectAsmFallback counts retained functions the
	// direct emitter declined (they took the transform path).
	DirectAsm int
	// AsmOverrides counts functions whose feature bodies came from
	// the project's assembly-override manifest (see asmoverride.go).
	AsmOverrides      int
	DirectAsmFallback int
}

// fnSym matches generated function symbols: fn0 (single-package,
// lowercase) or Fn0 (multi-package, exported for cross-chunk calls).
var fnSymRe = regexp.MustCompile(`^[Ff]n(\d+)$`)

type bundlePkg struct {
	relDir string // "" for the root package
	path   string // import path
}

// Build runs the capture+transform pipeline. mainSrc may be empty
// (multi-package mode leaves the root writer empty). The returned map
// contains ONLY files gcasm adds or replaces; a nil entry value means
// "delete this file from the tree".
// SynthSig is the wasm-typed signature of a synthetic (outlined)
// function, keyed by bare name. Bodies with a listed signature are
// transformed exactly like translated FnN bodies.
type SynthSig struct {
	Params []wasm.ValType
	Result *wasm.ValType
	// Packed: the caller passes (m, *[len(Params)]uint64) and the
	// body unpacks — the register ABI carries any boundary width.
	Packed bool
}

func Build(mod *wasm.Module, mainSrc []byte, resFiles map[string][]byte, importPath string, fused map[string]*simdfuse.Tree, fusedLoops map[string]*simdfuse.Loop, outlined map[string][]string, synth map[string]SynthSig, cfg Config) (map[string][]byte, *BuildStats, error) {
	all := map[string][]byte{}
	if len(mainSrc) > 0 {
		all["gen.go"] = mainSrc
	}
	for name, data := range resFiles {
		all[name] = data
	}
	pure := PureFilter(all)

	// Assembly overrides by function symbol: the translator names a
	// defined function fn<idx> in single-package output and Fn<idx>
	// (exported across chunks) in multi-package output.
	ovr := map[string]*AsmOverride{}
	if cfg.AsmOverrides != nil {
		for _, k := range cfg.AsmOverrides.Functions {
			ovr[fmt.Sprintf("Fn%d", k.FuncIdx)] = k
			ovr[fmt.Sprintf("fn%d", k.FuncIdx)] = k
		}
	}

	// Capture tree.
	dir, err := os.MkdirTemp("", "gcasm-capture-*")
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if rerr := os.RemoveAll(dir); rerr != nil {
			// Best-effort temp cleanup; the OS reaps the rest.
			_ = rerr
		}
	}()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+importPath+"\n\ngo 1.25.0\n"), 0o644); err != nil {
		return nil, nil, err
	}
	pkgSet := map[string]bundlePkg{"": {relDir: "", path: importPath}}
	for name, data := range pure {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return nil, nil, err
		}
		if d := filepath.Dir(name); d != "." {
			pkgSet[d] = bundlePkg{relDir: d, path: importPath + "/" + d}
		}
	}
	// Capture each target architecture. Signatures/fallback decisions
	// are arch-independent; only the instruction bodies and data syms
	// differ, so each arch gets its own fns/datas.
	type archCapture struct {
		fns   []*Fn
		dm    map[string]*DataSym
		byPkg map[string][]*Fn
	}
	caps := map[string]*archCapture{}
	for _, spec := range archSpecs {
		afns, adatas, cerr := captureArch(dir, importPath+"/...", spec.name)
		if cerr != nil {
			return nil, nil, fmt.Errorf("capture %s: %w", spec.name, cerr)
		}
		adm := map[string]*DataSym{}
		for _, d := range adatas {
			adm[d.Name] = d
		}
		caps[spec.name] = &archCapture{fns: afns, dm: adm}
	}

	// Signatures. FnN come from the wasm module (exact); everything
	// else from parsing the pure sources per package.
	pkgSigs := map[string]map[string]goSigB{} // relDir → name → sig
	for name, data := range pure {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		rel := filepath.Dir(name)
		if rel == "." {
			rel = ""
		}
		if pkgSigs[rel] == nil {
			pkgSigs[rel] = map[string]goSigB{}
		}
		if err := parseSigsAST(data, pkgSigs[rel]); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", name, err)
		}
	}

	// The fallback set is decided by signature alone, up front, so
	// call sites can pick the right cross-package mechanism.
	fnKinds := func(idx uint32) (params []ArgKind, names []string, hasRes bool, res ArgKind) {
		ft := mod.FuncTypeOf(idx)
		params = []ArgKind{ArgPtr}
		names = []string{"m"}
		for i, p := range ft.Params {
			params = append(params, wasmKind(p))
			names = append(names, fmt.Sprintf("l%d", i))
		}
		if len(ft.Results) == 1 {
			hasRes, res = true, wasmKind(ft.Results[0])
		}
		return
	}
	// DUFFZERO/DUFFCOPY functions fall back to pure (see errUnsupportedDuff).
	// Whether gc emits a duff sequence is toolchain- AND arch-dependent, so
	// take the UNION across every captured arch — a function that duffs on
	// one arch falls back on all of them, keeping the fallback set
	// arch-consistent (the pure guard and cross-package wiring assume it).
	duffIdx := map[uint32]bool{}
	for _, spec := range archSpecs {
		for _, f := range caps[spec.name].fns {
			if !hasDuffPseudo(f.Insns) {
				continue
			}
			i := strings.LastIndex(f.Name, ".")
			if i < 0 {
				continue
			}
			m := fnSymRe.FindStringSubmatch(f.Name[i+1:])
			if m == nil {
				continue
			}
			if idx64, perr := strconv.ParseUint(m[1], 10, 32); perr == nil {
				duffIdx[uint32(idx64)] = true
			}
		}
	}
	isFallbackSig := func(idx uint32) bool {
		if duffIdx[idx] {
			return true
		}
		ft := mod.FuncTypeOf(idx)
		if len(ft.Results) > 1 {
			return true
		}
		params, _, hasRes, res := fnKinds(idx)
		args, _, err := AssignABIInternal(params, hasRes, res)
		if err != nil {
			return true
		}
		for _, a := range args {
			if a.Reg == "" {
				return true
			}
		}
		return false
	}

	out := map[string][]byte{}
	stats := &BuildStats{}
	var pkgList []string
	for rel := range pkgSet {
		pkgList = append(pkgList, rel)
	}
	sort.Strings(pkgList)

	// Group each arch's captured fns by package relDir; record each
	// symbol's owning package for cross-chunk reference resolution.
	// The owner map is PER ARCH: direct cross-chunk asm CALLs (see
	// calleeSig) are sound only when the callee's own package emits
	// either the TEXT or the gcasmABI0Keep anchor for it on the SAME
	// arch, which is exactly membership in that arch's capture.
	fnOwnerByArch := map[string]map[string]string{} // arch → "Fn83" → qualified path
	for _, spec := range archSpecs {
		ac := caps[spec.name]
		ac.byPkg = map[string][]*Fn{}
		fnOwner := map[string]string{}
		fnOwnerByArch[spec.name] = fnOwner
		for _, f := range ac.fns {
			i := strings.LastIndex(f.Name, ".")
			if i < 0 {
				continue
			}
			if _, isSynth := synth[f.Name[i+1:]]; !isSynth && !fnSymRe.MatchString(f.Name[i+1:]) {
				continue
			}
			fpkg := f.Name[:i]
			rel := strings.TrimPrefix(strings.TrimPrefix(fpkg, importPath), "/")
			ac.byPkg[rel] = append(ac.byPkg[rel], f)
			fnOwner[f.Name[i+1:]] = fpkg
		}
	}

	for _, spec := range archSpecs {
		ac := caps[spec.name]
		// stats accumulate across arches; count only the first (amd64)
		// so Transformed/Fallback reflect the fn set, not 2×.
		archStats := stats
		if spec.name != "amd64" {
			archStats = &BuildStats{}
		}
		// The Module field offsets for the SIMD memory-op splices,
		// read from this arch's captured probe. nil (no probe in the
		// capture — a module with no SIMD) keeps memory ops on the
		// marshalled path.
		modOffs := FindModuleOffsets(ac.fns, spec.name)
		if modOffs != nil {
			modOffs.Cfg = cfg
		}
		for _, rel := range pkgList {
			pfns := ac.byPkg[rel]
			if len(pfns) == 0 {
				continue
			}
			files, err := buildPkg(mod, importPath, rel, pfns, ac.dm, pkgSigs, fnKinds, isFallbackSig, fnOwnerByArch[spec.name], pure, archStats, spec, modOffs, fused, fusedLoops, outlined[rel], synth, ovr, cfg)
			if err != nil {
				return nil, nil, fmt.Errorf("gcasm bundle %s/%s: %w", pkgOrRoot(rel), spec.name, err)
			}
			for k, v := range files {
				out[k] = v
			}
		}
		// The SIMD splice counters are per-arch work (each arch
		// transforms every body), so they are summed across arches
		// rather than sampled from amd64 like the fn-set counters.
		if archStats != stats {
			stats.SimdSpliced += archStats.SimdSpliced
			stats.SimdKept += archStats.SimdKept
		}
	}

	// Interface-method keep-alives: import calls (m.XImports.M(...))
	// live in ASSEMBLY after the transform, so the linker's method
	// pruning sees no Go-level interface call of those names and
	// fills every itab slot with runtime.unreachableMethod. Method
	// EXPRESSIONS pin the names. Emitted next to each file that
	// declares a *Imports interface.
	ifaceRe := regexp.MustCompile(`(?ms)^type (\w+Imports) interface \{\n(.*?)^\}`)
	methRe := regexp.MustCompile(`(?m)^\t(\w+)\(([^)]*)\)`)
	keepByDir := map[string][]string{}
	for name, data := range pure {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		d := filepath.Dir(name)
		if d == "." {
			d = ""
		}
		for _, im := range ifaceRe.FindAllStringSubmatch(string(data), -1) {
			decl := fmt.Sprintf("(%s)(nil)", im[1])
			for _, mm := range methRe.FindAllStringSubmatch(im[2], -1) {
				nargs := 0
				if strings.TrimSpace(mm[2]) != "" {
					nargs = strings.Count(mm[2], ",") + 1
				}
				args := make([]string, nargs)
				for i := range args {
					// Every import parameter is m/int32/int64 —
					// untyped 0 (or nil for *Module) converts.
					if i == 0 {
						args[i] = "nil"
					} else {
						args[i] = "0"
					}
				}
				keepByDir[d] = append(keepByDir[d],
					fmt.Sprintf("%s.%s(%s)", decl, mm[1], strings.Join(args, ", ")))
			}
		}
	}
	for d, ifaces := range keepByDir {
		sort.Strings(ifaces)
		prefix := ""
		if d != "" {
			prefix = d + "/"
		}
		// One keep-alive per gcasm arch (the itab pruning happens per
		// linked binary, i.e. per arch).
		for _, spec := range archSpecs {
			var ob strings.Builder
			ob.WriteString("//go:build " + spec.buildTag + "\n\n")
			ob.WriteString("// Code generated by wasm2go (gcasm backend). DO NOT EDIT.\n//\n")
			ob.WriteString("// Import calls live in assembly, invisible to the linker's\n")
			ob.WriteString("// method pruning, which would fill every itab slot with\n")
			ob.WriteString("// runtime.unreachableMethod. init() is always reachable, so\n")
			ob.WriteString("// the never-taken calls below emit genuine interface call\n")
			ob.WriteString("// sites that pin each method. gcasmKeepAlive is never set.\n\n")
			ob.WriteString("package " + pkgNameOf(d, pure) + "\n\nvar gcasmKeepAlive bool\n\nfunc init() {\n\tif !gcasmKeepAlive {\n\t\treturn\n\t}\n")
			for _, call := range ifaces {
				ob.WriteString("\t" + call + "\n")
			}
			ob.WriteString("}\n")
			out[prefix+"keepalive_"+spec.name+".go"] = []byte(ob.String())
		}
	}

	// Rewrite the translated tree around the gcasm files: the
	// own-backend asm (.s) and its decls/alias sources (tagged
	// `amd64 || arm64`) go away; gcasm now serves BOTH amd64 and arm64,
	// so the pure guards stay `!amd64 && !arm64` (the pure fallback for
	// other arches + the `-tags purego` escape).
	for name, data := range all {
		if base := filepath.Base(name); strings.HasPrefix(base, "simd_") || strings.HasPrefix(base, "cpufeat_") {
			// The SIMD helper set (scalar reference + its own per-arch
			// asm + fallback aliases) and the CPU feature detection are
			// arch-complete on their own and independent of the gcasm
			// bundle — leave them untouched. In particular the
			// feature-dispatch stubs read base.HasAVX2/CPUDotProd, so
			// deleting cpufeat_amd64.go with the own-backend amd64
			// decls would break the bundle build.
			continue
		}
		switch {
		case strings.HasSuffix(name, ".s"):
			out[name] = nil // delete
		case strings.HasPrefix(string(data), "//go:build "):
			line := string(data)
			if idx := strings.Index(line, "\n"); idx >= 0 {
				line = line[:idx]
			}
			expr := strings.TrimSpace(strings.TrimPrefix(line, "//go:build"))
			switch {
			case strings.Contains(expr, "!amd64"):
				// Keep the pure body as-is (already !amd64 && !arm64).
			case strings.Contains(expr, "amd64"):
				out[name] = nil // delete the own-backend decls/alias
			}
		}
	}
	return out, stats, nil
}

func pkgOrRoot(rel string) string {
	if rel == "" {
		return "(root)"
	}
	return rel
}

func wasmKind(v wasm.ValType) ArgKind {
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

// abi0ArgBytes is the ABI0 stack-argument byte count of a wasm
// signature carried behind the module pointer: m at +0, then each
// parameter at its natural size and alignment (4 for i32/f32, 8 for
// i64/f64), then — when there is a result — the result section at the
// next pointer-aligned offset. This is the "-N" the TEXT directive of
// the fn's own asm body carries, which the gc toolchain checks against
// the Go declaration.
func abi0ArgBytes(ft wasm.FuncType) int {
	off := 8
	add := func(v wasm.ValType) {
		sz := 8
		if v == wasm.ValI32 || v == wasm.ValF32 {
			sz = 4
		}
		off = (off + sz - 1) &^ (sz - 1)
		off += sz
	}
	for _, p := range ft.Params {
		add(p)
	}
	if len(ft.Results) > 0 {
		off = (off + 7) &^ 7
		for _, r := range ft.Results {
			add(r)
		}
	}
	return off
}

// goSigB is the bundle-side signature entry (AST-parsed).
type goSigB struct {
	params []ArgKind
	hasRes bool
	res    ArgKind
	ok     bool
}

// parseSigsAST extracts plain top-level function signatures via
// go/parser (exact, unlike regex parsing).
func parseSigsAST(src []byte, out map[string]goSigB) error {
	fset := token.NewFileSet()
	// SkipObjectResolution: only top-level func signatures are read
	// below (no ident.Obj / scope use), so the deprecated resolver is
	// dead work — and its maxScopeDepth=1000 bailout would reject the
	// deeply nested bodies gc compiles fine (setjmp/longjmp dispatch).
	f, err := parser.ParseFile(fset, "src.go", src, parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		sig := goSigB{ok: true}
		for _, fld := range fd.Type.Params.List {
			k, ok := exprKind(fld.Type)
			if !ok {
				sig.ok = false
				break
			}
			n := len(fld.Names)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				sig.params = append(sig.params, k)
			}
		}
		if sig.ok && fd.Type.Results != nil {
			n := 0
			for _, fld := range fd.Type.Results.List {
				c := len(fld.Names)
				if c == 0 {
					c = 1
				}
				n += c
				k, ok := exprKind(fld.Type)
				if !ok {
					sig.ok = false
					break
				}
				sig.hasRes, sig.res = true, k
			}
			if n > 1 {
				sig.ok = false
			}
		}
		out[fd.Name.Name] = sig
	}
	return nil
}

func exprKind(e ast.Expr) (ArgKind, bool) {
	switch t := e.(type) {
	case *ast.ArrayType:
		// [2]uint64 — a wasm v128 value (the SIMD helpers' currency).
		if l, ok := t.Len.(*ast.BasicLit); ok && l.Value == "2" {
			if id, ok := t.Elt.(*ast.Ident); ok && id.Name == "uint64" {
				return ArgV128, true
			}
		}
	case *ast.StarExpr:
		return ArgPtr, true
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok && id.Name == "unsafe" && t.Sel.Name == "Pointer" {
			return ArgPtr, true
		}
	case *ast.Ident:
		switch t.Name {
		case "int32":
			return ArgI32, true
		case "uint32":
			return ArgU32, true
		case "int64", "uint64", "int", "uint":
			return ArgI64, true
		case "float32":
			return ArgF32, true
		case "float64":
			return ArgF64, true
		case "uintptr":
			return ArgPtr, true
		}
	}
	return 0, false
}

// fnBodyRe extracts one top-level function (gofmt-formatted output:
// the body's closing brace sits in column 0).
func fnBodyRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?ms)^func ` + regexp.QuoteMeta(name) + `\(.*?^\}$`)
}

// stdlibWrapperTable: stdlib callees reachable from inlined helper
// bodies. Wrapper functions are emitted into the decls file; asm
// references only materialise ABI0 wrappers for same-package symbols.
var stdlibWrapperTable = map[string]struct {
	sig  goSigB
	wrap string
	body string
}{
	"math.Ceil":                 {goSigB{[]ArgKind{ArgF64}, true, ArgF64, true}, "gcasmMathCeil", "func gcasmMathCeil(x float64) float64 { return math.Ceil(x) }"},
	"math.Floor":                {goSigB{[]ArgKind{ArgF64}, true, ArgF64, true}, "gcasmMathFloor", "func gcasmMathFloor(x float64) float64 { return math.Floor(x) }"},
	"math.Trunc":                {goSigB{[]ArgKind{ArgF64}, true, ArgF64, true}, "gcasmMathTrunc", "func gcasmMathTrunc(x float64) float64 { return math.Trunc(x) }"},
	"math.RoundToEven":          {goSigB{[]ArgKind{ArgF64}, true, ArgF64, true}, "gcasmMathRoundToEven", "func gcasmMathRoundToEven(x float64) float64 { return math.RoundToEven(x) }"},
	"math.Sqrt":                 {goSigB{[]ArgKind{ArgF64}, true, ArgF64, true}, "gcasmMathSqrt", "func gcasmMathSqrt(x float64) float64 { return math.Sqrt(x) }"},
	"math/bits.OnesCount32":     {goSigB{[]ArgKind{ArgU32}, true, ArgI64, true}, "gcasmBitsOnesCount32", "func gcasmBitsOnesCount32(x uint32) int { return bits.OnesCount32(x) }"},
	"math/bits.OnesCount64":     {goSigB{[]ArgKind{ArgI64}, true, ArgI64, true}, "gcasmBitsOnesCount64", "func gcasmBitsOnesCount64(x uint64) int { return bits.OnesCount64(x) }"},
	"math/bits.LeadingZeros32":  {goSigB{[]ArgKind{ArgU32}, true, ArgI64, true}, "gcasmBitsLeadingZeros32", "func gcasmBitsLeadingZeros32(x uint32) int { return bits.LeadingZeros32(x) }"},
	"math/bits.LeadingZeros64":  {goSigB{[]ArgKind{ArgI64}, true, ArgI64, true}, "gcasmBitsLeadingZeros64", "func gcasmBitsLeadingZeros64(x uint64) int { return bits.LeadingZeros64(x) }"},
	"math/bits.TrailingZeros32": {goSigB{[]ArgKind{ArgU32}, true, ArgI64, true}, "gcasmBitsTrailingZeros32", "func gcasmBitsTrailingZeros32(x uint32) int { return bits.TrailingZeros32(x) }"},
	"math/bits.TrailingZeros64": {goSigB{[]ArgKind{ArgI64}, true, ArgI64, true}, "gcasmBitsTrailingZeros64", "func gcasmBitsTrailingZeros64(x uint64) int { return bits.TrailingZeros64(x) }"},
}

// buildPkg transforms one package's functions and renders its bundle
// files (amd64.s, decls_amd64.go, retagged pure file).
// archSpec carries the per-architecture transform and its emission
// details so buildPkg can produce amd64 and arm64 bundles from one
// code path.
type archSpec struct {
	name      string // "amd64" / "arm64"
	buildTag  string // //go:build expression for the emitted asm + decls
	transform func(*Fn, TransformOptions) (string, error)
	jtMarker  string // jump-tree marker for the stats counter
	// Feature-gated ISA dispatch: a transformed body containing
	// gatedMarker used instructions past the architecture baseline.
	// Build then emits the body twice — a <sym><gatedSuffix> feature
	// body and a <sym><portableSuffix> baseline twin (transformed with
	// PortableSIMD) — plus a NOSPLIT tail-jump stub under the original
	// name that branches on a package-local mirror of featureVar (a
	// bool in the base package). The stub keeps the caller's frame, so
	// dispatch costs one predicted branch, not an extra call layer.
	// Empty gatedMarker disables the mechanism for the arch.
	gatedMarker    string
	gatedSuffix    string
	portableSuffix string
	featureVar     string
	// dispatchStub renders the stub body. argBytes is the argument
	// area size from the transformed body's TEXT header.
	dispatchStub func(sym, featSym, portSym, mirrorVar, argBytes string) string
}

var archSpecs = []archSpec{
	// amd64 requires x86-64-v2: the SIMD splices use SSE4.1
	// (PINSRQ/PEXTRQ/PMOVSX...), same baseline as the helper asm.
	// GOAMD64=v1 builds compile the pure tree instead.
	{name: "amd64", buildTag: "amd64 && amd64.v2", transform: Transform, jtMarker: "_jt",
		gatedMarker: "// avx2 dot", gatedSuffix: "avx2", portableSuffix: "sse",
		featureVar: "HasAVX2", dispatchStub: x64DispatchStub},
	{name: "arm64", buildTag: "arm64", transform: TransformARM64, jtMarker: "_jt",
		gatedMarker: "// sdot v", gatedSuffix: "dotprod", portableSuffix: "generic",
		featureVar: "CPUDotProd", dispatchStub: a64DispatchStub},
}

// x64DispatchStub is the amd64 feature-dispatch stub: compare the mirror
// bool against 0 and tail-jump to the portable SSE twin when it is
// clear, else to the AVX2 body. The compare reads memory and sets flags
// only — no register is touched — so the tail targets see the original
// caller's ABIInternal argument registers intact. Same frame ($0), one
// predicted branch.
func x64DispatchStub(sym, featSym, portSym, mirrorVar, argBytes string) string {
	return "TEXT ·" + sym + "(SB), NOSPLIT, $0-" + argBytes + "\n" +
		"\tCMPB ·" + mirrorVar + "(SB), $0\n" +
		"\tJEQ 2(PC)\n" +
		"\tJMP ·" + featSym + "(SB)\n" +
		"\tJMP ·" + portSym + "(SB)\n"
}

// a64DispatchStub is the arm64 feature-dispatch stub: read the mirror
// bool, tail-jump to the portable twin when it is clear. Same frame,
// same FP layout — the targets see the original caller's arguments.
func a64DispatchStub(sym, featSym, portSym, mirrorVar, argBytes string) string {
	return "TEXT ·" + sym + "(SB), NOSPLIT, $0-" + argBytes + "\n" +
		"\tMOVBU ·" + mirrorVar + "(SB), R27\n" +
		"\tCBZ R27, 2(PC)\n" +
		"\tJMP ·" + featSym + "(SB)\n" +
		"\tJMP ·" + portSym + "(SB)\n"
}

// declSig renders the Go declaration signature shared by the plain
// decl, the gated stub decls, and the direct-asm path. Packed
// boundaries carry only the module pointer; their values ride the
// per-module scratch.
func declSig(rel, name string, declParams []wasm.ValType, hasRes bool, res ArgKind, synth map[string]SynthSig) string {
	var sigB strings.Builder
	fmt.Fprintf(&sigB, "(m %s", moduleTypeName(rel))
	if ss, isSynth := synth[name]; !isSynth || !ss.Packed {
		for i, p := range declParams {
			fmt.Fprintf(&sigB, ", l%d %s", i, goTypeName(wasmKind(p)))
		}
	}
	sigB.WriteString(")")
	if hasRes {
		fmt.Fprintf(&sigB, " (r0 %s)", goTypeName(res))
	}
	return sigB.String()
}

func buildPkg(
	mod *wasm.Module,
	importPath, rel string,
	pfns []*Fn,
	dm map[string]*DataSym,
	pkgSigs map[string]map[string]goSigB,
	fnKinds func(uint32) ([]ArgKind, []string, bool, ArgKind),
	isFallbackSig func(uint32) bool,
	fnOwner map[string]string,
	pure map[string][]byte,
	stats *BuildStats,
	arch archSpec,
	modOffs *ModuleOffsets,
	fused map[string]*simdfuse.Tree,
	fusedLoops map[string]*simdfuse.Loop,
	outlinedNames []string,
	synth map[string]SynthSig,
	ovr map[string]*AsmOverride,
	cfg Config,
) (map[string][]byte, error) {
	directSSA := cfg.DirectAsm
	selfPath := importPath
	if rel != "" {
		selfPath = importPath + "/" + rel
	}

	// Cross-package resolution state (all deterministic: sorted at
	// emission).
	goForwards := map[string]string{} // localWrap → remote qualified
	goForwardSig := map[string]goSigB{}
	stdlibUsed := map[string]bool{}

	fallbackNames := map[string]bool{}
	// spelledRemote / pulledRemote record, per qualified symbol, every
	// remote fn this package's ASM references by its spelled dotted
	// name and every remote symbol this package's GO declares through
	// a bodyless //go:linkname pull. The two sets must stay disjoint:
	// a bodyless linkname pull of a symbol the same package's asm also
	// references makes the compiler emit a DUPOK ABI0 wrapper under the
	// REMOTE name (symabis reports the asm reference, the pull supplies
	// the declaration), and the linker keeps whichever of that wrapper
	// and the remote's real TEXT it loads first — when the wrapper wins,
	// the two ABI wrappers call each other forever and the link fails
	// with "nosplit stack over ... infinite cycle". buildPkg refuses to
	// emit such a package (see the check after the decls are built).
	spelledRemote := map[string]bool{}
	pulledRemote := map[string]bool{}
	// textNames records every captured fn that emitted a TEXT body
	// (transformed, gated-split, or direct-asm). Together with
	// fallbackNames it must cover the whole capture — the invariant
	// the post-loop check below enforces.
	textNames := map[string]bool{}
	pool := &ConstPool{}
	types := &TypeTable{}
	jt := &JTTable{}
	var asmB strings.Builder
	// The build tag pins GOARCH explicitly: the bundle uses bare
	// arch filenames (amd64.s/arm64.s), which — having no prefix
	// before the arch — get NO implicit GOARCH constraint from the
	// name (Go 1.4+ only auto-tags files with a non-empty prefix).
	// This is exactly the header the own-asm backend emitted, and
	// matches the plain `//go:build <arch>` tag on the decls and
	// keepalive files below.
	asmB.WriteString("//go:build " + arch.buildTag + "\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
	var declFns strings.Builder
	mirrorVars := map[string]bool{} // feature mirrors already declared in this package

	calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
		if std, ok := stdlibWrapperTable[sym]; ok {
			stdlibUsed[sym] = true
			return std.sig.params, std.sig.hasRes, std.sig.res, "·" + std.wrap, true
		}
		i := strings.LastIndex(sym, ".")
		if i < 0 || !strings.HasPrefix(sym, importPath) {
			return nil, false, 0, "", false
		}
		cpkg, cname := sym[:i], sym[i+1:]
		crel := strings.TrimPrefix(strings.TrimPrefix(cpkg, importPath), "/")
		if m := fnSymRe.FindStringSubmatch(cname); m != nil {
			idx, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				return nil, false, 0, "", false
			}
			params, _, hasRes, res := fnKinds(uint32(idx))
			if cpkg == selfPath {
				return params, hasRes, res, "·" + cname, true
			}
			// Remote fn (transformed or fallback): CALL the remote
			// symbol directly. The plan 9 lexer maps U+00B7 to "." and
			// U+2215 to "/", so a dotted import path is spellable in an
			// asm operand and the linker sees the canonical symbol —
			// no forwarding frame. Transformed remotes resolve against
			// the remote TEXT (ABI0, the exact layout the marshalling
			// below stages); fallback remotes resolve against the ABI0
			// wrapper their own package's gcasmABI0Keep anchor forces
			// the compiler to emit. Imports still cannot be used (chunk
			// call graphs are cyclic), but no import is needed: every
			// chunk is linked via the root package's import chain, the
			// same guarantee the old //go:linkname forwards relied on.
			// A path plan 9 cannot spell (e.g. a hyphenated host repo)
			// or a callee outside the capture keeps the historical
			// Go-wrapper hop.
			if fnOwner[cname] == cpkg && asmgen.Plan9AsmPathSafe(cpkg) {
				spelledRemote[sym] = true
				return params, hasRes, res, asmSpellPath(cpkg) + "·" + cname, true
			}
			wrap := "gcasmFwd" + cname
			goForwards[wrap] = sym
			goForwardSig[wrap] = goSigB{params: params, hasRes: hasRes, res: res, ok: true}
			return params, hasRes, res, "·" + wrap, true
		}
		// Helper (plain Go function). Same package: direct. Other
		// package (base): local Go wrapper via linkname.
		hs, found := pkgSigs[crel][cname]
		if !found || !hs.ok {
			return nil, false, 0, "", false
		}
		if cpkg == selfPath {
			return hs.params, hs.hasRes, hs.res, "·" + cname, true
		}
		wrap := "gcasmFwdH_" + strings.ReplaceAll(crel, "/", "_") + "_" + cname
		goForwards[wrap] = sym
		goForwardSig[wrap] = hs
		return hs.params, hs.hasRes, hs.res, "·" + wrap, true
	}

	sort.Slice(pfns, func(i, j int) bool { return pfns[i].Name < pfns[j].Name })
	var splices SpliceStats
	seenSynth := map[string]bool{}
	for _, f := range pfns {
		name := f.Name[strings.LastIndex(f.Name, ".")+1:]
		var params []ArgKind
		var names []string
		var hasRes bool
		var res ArgKind
		var declParams []wasm.ValType
		if ss, isSynth := synth[name]; isSynth {
			seenSynth[name] = true
			if ss.Packed {
				// The boundary rides the per-module scratch; only m
				// crosses the call.
				params, names = []ArgKind{ArgPtr}, []string{"m"}
			} else {
				params, names = []ArgKind{ArgPtr}, []string{"m"}
				for i, p := range ss.Params {
					params = append(params, wasmKind(p))
					names = append(names, fmt.Sprintf("l%d", i))
				}
			}
			if ss.Result != nil {
				hasRes, res = true, wasmKind(*ss.Result)
			}
			declParams = ss.Params
			// Pure-Go bodies are forbidden on the asm GOARCHs, so a
			// boundary the register marshalling cannot carry is a hard
			// error — the outline eligibility caps should have kept
			// this shape from ever being extracted.
			args, _, err := AssignABIInternal(params, hasRes, res)
			if err != nil {
				return nil, fmt.Errorf("outlined %s: %w", name, err)
			}
			for _, a := range args {
				if a.Reg == "" {
					return nil, fmt.Errorf("outlined %s: argument beyond the register ABI", name)
				}
			}
		} else {
			m := fnSymRe.FindStringSubmatch(name)
			idx64, err := strconv.ParseUint(m[1], 10, 32)
			if err != nil {
				return nil, err
			}
			idx := uint32(idx64)
			if isFallbackSig(idx) {
				fallbackNames[name] = true
				stats.Fallback++
				continue
			}
			params, names, hasRes, res = fnKinds(idx)
			declParams = mod.FuncTypeOf(idx).Params
		}
		// Direct-asm body: emitted straight from the retained SSA by
		// internal/asmgen (see emitDirectAsmBody); replaces the
		// listing transform for this function. The decl matches the
		// transformed path's shape, so callers see no difference.
		// Emission shares this package's ConstPool so spliced bodies'
		// constants intern alongside the transform's.
		if df, isDirect := directSSA[name]; isDirect {
			if dab, ok := emitDirectAsmBody(mod, name, df, arch.name, cfg, modOffs, pool, importPath, rel, calleeSig, fnOwner, stats); ok {
				asmB.WriteString(dab)
				asmB.WriteString("\n")
				stats.DirectAsm++
				textNames[name] = true
				declFns.WriteString("func " + name + declSig(rel, name, declParams, hasRes, res, synth) + "\n")
				continue
			}
			stats.DirectAsmFallback++
		}
		body, terr := arch.transform(f, TransformOptions{
			SymName:     name,
			CalleeSig:   calleeSig,
			Params:      params,
			HasResult:   hasRes,
			Result:      res,
			ArgNames:    names,
			Datas:       dm,
			Consts:      pool,
			Types:       types,
			JT:          jt,
			SpliceStats: &splices,
			ModOffsets:  modOffs,
			FusedSimd:   fused,
			FusedLoops:  fusedLoops,
		})
		if terr != nil {
			// A duff body, or a jump table whose flag state cannot be replayed
			// at the leaf asm, falls back to the pure Go body (transparent to
			// callers) rather than aborting the whole bundle. Outlined
			// bodies are the exception: they must not exist as pure Go
			// on the asm GOARCHs, so nothing may quietly degrade.
			if _, isSynth := synth[name]; !isSynth &&
				(errors.Is(terr, errUnsupportedDuff) || errors.Is(terr, errUnsupportedJumpTable) || errors.Is(terr, errSimdPairUnspliced)) {
				// The failed attempt may already have registered
				// jump-table sites; their stubs will not exist in the
				// emitted asm, so the registrations must go with it.
				jt.Drop(name)
				fallbackNames[name] = true
				stats.Fallback++
				continue
			}
			return nil, fmt.Errorf("transform %s: %w", f.Name, terr)
		}
		sig := declSig(rel, name, declParams, hasRes, res, synth)
		// Synthetic bodies take the same feature-gated twin split as
		// wasm functions (outlined extraction bodies historically never
		// contained gated instructions, so including them is a no-op).
		// A assembly override rides the same split: the override bodies
		// become the feature-selected symbols and the lowered body,
		// transformed with PortableSIMD, stays as the baseline twin.
		ov, isOverride := ovr[name]
		isOverride = isOverride && modOffs != nil && len(ov.Bodies[arch.name]) > 0
		if isOverride && strings.Contains(body, arch.jtMarker) {
			return nil, fmt.Errorf("transform %s: assembly override %s: the lowered body carries a jump table, which the override split does not support", f.Name, ov.Export)
		}
		if isOverride || (arch.gatedMarker != "" &&
			strings.Contains(body, arch.gatedMarker) && !strings.Contains(body, arch.jtMarker)) {
			// Feature-gated body: the feature symbol keeps this body, a
			// baseline twin is transformed with PortableSIMD, and a
			// NOSPLIT tail-jump stub under the original name dispatches
			// at runtime on a package-local mirror of the base package's
			// CPU feature var.
			featSym, portSym := name+arch.gatedSuffix, name+arch.portableSuffix
			featBody := strings.Replace(body, "TEXT ·"+name+"(SB)", "TEXT ·"+featSym+"(SB)", 1)
			portBody, perr := arch.transform(f, TransformOptions{
				SymName:      portSym,
				CalleeSig:    calleeSig,
				Params:       params,
				HasResult:    hasRes,
				Result:       res,
				ArgNames:     names,
				Datas:        dm,
				Consts:       pool,
				Types:        types,
				JT:           jt,
				SpliceStats:  &splices,
				ModOffsets:   modOffs,
				FusedSimd:    fused,
				FusedLoops:   fusedLoops,
				PortableSIMD: true,
			})
			if perr != nil {
				return nil, fmt.Errorf("transform %s (portable twin): %w", f.Name, perr)
			}
			if strings.Contains(portBody, arch.gatedMarker) {
				return nil, fmt.Errorf("transform %s: portable twin still contains gated instructions", f.Name)
			}
			m := regexp.MustCompile(`^TEXT [^,]+, \$\d+-(\d+)`).FindStringSubmatch(featBody)
			if m == nil {
				return nil, fmt.Errorf("transform %s: no arg size in the TEXT header", f.Name)
			}
			if isOverride {
				if want := abi0ArgBytes(mod.FuncTypeOf(ov.FuncIdx)); m[1] != strconv.Itoa(want) {
					return nil, fmt.Errorf("transform %s: assembly override %s: the lowered body declares a %s-byte argument frame, the ABI rule gives %d", f.Name, ov.Export, m[1], want)
				}
				trapSym := "wasm_trap_simd_oob"
				if rel != "" && rel != "base" {
					trapSym = "gcasmFwdH_base_Wasm_trap_simd_oob"
				}
				var levels [][2]string
				baseSym := portSym
				for _, ob := range ov.Bodies[arch.name] {
					bsym := name + "ovr" + ob.Feature
					asmB.WriteString(asmOverrideText(arch.name, bsym, trapSym, modOffs, ob, m[1]))
					asmB.WriteString("\n")
					fmt.Fprintf(&declFns, "func %s%s\n", bsym, sig)
					featureVar := ""
					for _, l := range overrideFeatureLevels[arch.name] {
						if l.name == ob.Feature {
							featureVar = l.featureVar
						}
					}
					if featureVar == "" {
						baseSym = bsym
						continue
					}
					mirror := "gcasm" + featureVar
					if !mirrorVars[mirror] {
						mirrorVars[mirror] = true
						ref := featureVar
						if rel != "" && rel != "base" {
							ref = "base." + ref
						}
						fmt.Fprintf(&declFns, "// %s mirrors %s for the feature-dispatch stubs\n// (asm reads package-local data only).\nvar %s = %s\n\n", mirror, ref, mirror, ref)
					}
					levels = append(levels, [2]string{mirror, bsym})
				}
				asmB.WriteString(overrideDispatchStub(arch.name, name, levels, baseSym, m[1]))
				asmB.WriteString("\n")
				if baseSym == portSym {
					asmB.WriteString(portBody)
					asmB.WriteString("\n")
					fmt.Fprintf(&declFns, "func %s%s\n", portSym, sig)
				}
				fmt.Fprintf(&declFns, "func %s%s\n", name, sig)
				textNames[name] = true
				stats.Transformed++
				stats.AsmOverrides++
				continue
			}
			mirrorVar := "gcasm" + arch.featureVar
			asmB.WriteString(arch.dispatchStub(name, featSym, portSym, mirrorVar, m[1]))
			asmB.WriteString("\n")
			asmB.WriteString(featBody)
			asmB.WriteString("\n")
			asmB.WriteString(portBody)
			asmB.WriteString("\n")
			stats.Transformed++
			if !mirrorVars[mirrorVar] {
				mirrorVars[mirrorVar] = true
				featureRef := arch.featureVar
				if rel != "" && rel != "base" {
					featureRef = "base." + featureRef
				}
				fmt.Fprintf(&declFns, "// %s mirrors %s for the feature-dispatch stubs\n// (asm reads package-local data only).\nvar %s = %s\n\n",
					mirrorVar, featureRef, mirrorVar, featureRef)
			}
			fmt.Fprintf(&declFns, "func %s%s\nfunc %s%s\nfunc %s%s\n", name, sig, featSym, sig, portSym, sig)
			textNames[name] = true
			continue
		}
		asmB.WriteString(body)
		asmB.WriteString("\n")
		if strings.Contains(body, arch.jtMarker) {
			stats.JumpTables++
		}
		stats.Transformed++
		textNames[name] = true
		declFns.WriteString("func " + name + sig + "\n")
	}
	stats.SimdSpliced += splices.Spliced
	stats.SimdKept += splices.Kept
	// Every outlined function must have surfaced in the capture and
	// been transformed; a missing one would silently keep a pure-Go
	// body on an asm GOARCH.
	for _, n := range outlinedNames {
		if !seenSynth[n] {
			return nil, fmt.Errorf("outlined %s: not present in the %s capture", n, arch.name)
		}
	}
	// Every captured fn must leave the loop above either with a TEXT
	// body or registered as a pure-Go fallback. A name that slips
	// both sets has no symbol in this package at all, and — worse —
	// other chunks may already have spelled a direct CALL against it
	// (see calleeSig), a hole that would otherwise surface only as a
	// link error in the consumer build. Each degrade path added to
	// the loop must keep this invariant; the check catches the one
	// that forgets.
	for _, f := range pfns {
		name := f.Name[strings.LastIndex(f.Name, ".")+1:]
		if !textNames[name] && !fallbackNames[name] {
			return nil, fmt.Errorf("%s: dropped by the %s build: neither transformed to asm nor registered as a pure-Go fallback", name, arch.name)
		}
	}

	// ABI0 anchor: reference every pure-Go fallback fn from this
	// package's own asm, so the compiler emits its ABI0 wrapper
	// (symabis marks the fn as asm-referenced). Other chunks' asm
	// CALLs the fn's dotted symbol directly — see calleeSig — and
	// that reference resolves against this wrapper when the fn kept
	// its Go body. Dead code (never jumped to), alive as an object
	// symbol regardless of linker deadcode decisions.
	//
	// Needed ONLY when calleeSig actually emits spelled direct CALLs,
	// i.e. when the import path is plan-9-spellable. An unspellable
	// path (a hyphenated host repo) keeps the gcasmFwd linkname
	// wrappers for every cross-chunk call, so no direct reference to a
	// fallback fn is ever made and the anchor would be pure dead
	// weight — skip it there.
	if len(fallbackNames) > 0 && asmgen.Plan9AsmPathSafe(importPath) {
		var names []string
		for n := range fallbackNames {
			names = append(names, n)
		}
		sort.Strings(names)
		asmB.WriteString("// gcasmABI0Keep: asm references forcing ABI0 wrappers for the\n// pure-Go fallback fns, so cross-chunk direct CALLs link.\nTEXT ·gcasmABI0Keep(SB), NOSPLIT, $0-0\n")
		for _, n := range names {
			asmB.WriteString("\tJMP ·" + n + "(SB)\n")
		}
		asmB.WriteString("\n")
		declFns.WriteString("\n// gcasmABI0Keep is an assembly-only anchor (see the .s file).\nfunc gcasmABI0Keep()\n\nvar _ = gcasmABI0Keep\n")
	}

	// Fallback bodies (extracted early: their Go-level FnN references
	// feed the trampoline/linkname sets below).
	var fallbackBodies []string
	fnTokRe := regexp.MustCompile(`\b[Ff]n\d+\b`)
	remoteFallbackLN := map[string]string{} // local FnN name → remote qualified (unspellable owner paths)
	remoteTramp := map[string]string{}      // local FnN name → owner import path (spellable)
	if len(fallbackNames) > 0 {
		var names []string
		for n := range fallbackNames {
			names = append(names, n)
		}
		sort.Strings(names)
		var pureSrc []byte
		for name, data := range pure {
			d := filepath.Dir(name)
			if d == "." {
				d = ""
			}
			if d == rel && strings.Contains(string(data), "func "+names[0]+"(") {
				pureSrc = data
				break
			}
		}
		if pureSrc == nil {
			return nil, fmt.Errorf("pure source with fallback fn %s not found", names[0])
		}
		for _, n := range names {
			m := fnBodyRe(n).Find(pureSrc)
			if m == nil {
				return nil, fmt.Errorf("fallback body %s not extractable", n)
			}
			body := string(m)
			fallbackBodies = append(fallbackBodies, body)
			// Cross-chunk references from Go code. On a plan-9-spellable
			// owner path the reference goes through a LOCAL bodyless
			// decl implemented by a NOSPLIT tail-JMP trampoline to the
			// spelled remote symbol: the compiler then binds the decl to
			// this package's own asm (symabis def) and never sees a
			// declaration of the remote symbol, so no ABI wrapper is
			// emitted under the remote name — the remote's real TEXT
			// (or, for a remote fallback fn, the ABI0 wrapper its own
			// gcasmABI0Keep anchor forces) stays the only ABI0
			// definition (see spelledRemote / pulledRemote). Only an
			// unspellable owner path keeps the bodyless //go:linkname
			// pull: no asm reference can be spelled there, so the pull
			// is the sole reference and the wrapper it induces is the
			// sole ABI0 definition.
			for _, tok := range fnTokRe.FindAllString(body, -1) {
				owner, known := fnOwner[tok]
				if !known || owner == selfPath {
					continue
				}
				if asmgen.Plan9AsmPathSafe(owner) {
					remoteTramp[tok] = owner
					continue
				}
				remoteFallbackLN[tok] = owner + "." + tok
			}
		}
	}

	// Cross-chunk trampolines for the fallback bodies' remote calls
	// (see the collection above). $0 frame, NOSPLIT: the JMP hands the
	// caller's argument frame to the remote unchanged, and the remote's
	// own prologue performs the stack check.
	if len(remoteTramp) > 0 {
		var names []string
		for n := range remoteTramp {
			names = append(names, n)
		}
		sort.Strings(names)
		asmB.WriteString("// Cross-chunk trampolines: local ABI0 entry points the fallback\n// bodies' Go calls bind to; each tail-jumps to the remote fn's spelled\n// symbol (no //go:linkname pull of an asm-referenced symbol).\n")
		for _, n := range names {
			fm := fnSymRe.FindStringSubmatch(n)
			idx, err := strconv.ParseUint(fm[1], 10, 32)
			if err != nil {
				return nil, err
			}
			target := asmSpellPath(remoteTramp[n]) + "·" + n
			spelledRemote[remoteTramp[n]+"."+n] = true
			fmt.Fprintf(&asmB, "TEXT ·%s(SB), NOSPLIT, $0-%d\n\tJMP %s(SB)\n\n", n, abi0ArgBytes(mod.FuncTypeOf(uint32(idx))), target)
		}
	}

	asmB.WriteString(pool.Emit())
	asmB.WriteString(jt.EmitAsm(arch.name))

	// Decls file.
	var decl strings.Builder
	decl.WriteString("//go:build " + arch.buildTag + "\n\n")
	decl.WriteString("// Code generated by wasm2go (gcasm backend). DO NOT EDIT.\n\n")
	decl.WriteString("package " + pkgNameOf(rel, pure) + "\n\n")
	// unsafe is always imported: gcasmTypePtr needs it, and the
	// //go:linkname forwards require it in scope. Chunk packages
	// reference the shared Module type as base.Module.
	mathUsed, bitsUsed, atomicUsed := false, false, false
	for k := range stdlibUsed {
		if strings.HasPrefix(k, "math/bits.") {
			bitsUsed = true
		} else if strings.HasPrefix(k, "math.") {
			mathUsed = true
		}
	}
	// Extracted fallback bodies may reference math/bits directly
	// (float NaN/Inf constants, rotate helpers inlined by gofmt) and
	// sync/atomic (the inline full-width atomic loads/stores, see
	// codegen/emit_memops.go).
	for _, body := range fallbackBodies {
		if strings.Contains(body, "math.") {
			mathUsed = true
		}
		if strings.Contains(body, "bits.") {
			bitsUsed = true
		}
		if strings.Contains(body, "atomic.") {
			atomicUsed = true
		}
	}
	decl.WriteString("import (\n")
	if mathUsed {
		decl.WriteString("\t\"math\"\n")
	}
	if bitsUsed {
		decl.WriteString("\t\"math/bits\"\n")
	}
	if atomicUsed {
		decl.WriteString("\t\"sync/atomic\"\n")
	}
	decl.WriteString("\t\"unsafe\"\n")
	if rel != "" && rel != "base" {
		fmt.Fprintf(&decl, "\n\tbase %q\n", importPath+"/base")
	}
	decl.WriteString(")\n\n")
	decl.WriteString("var _ = unsafe.Pointer(nil)\n\n")
	if rel != "" && rel != "base" {
		decl.WriteString("var _ = base.Module{}\n\n")
	}
	decl.WriteString(declFns.String())
	decl.WriteString("\n")
	if len(stdlibUsed) > 0 {
		var keys []string
		for k := range stdlibUsed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			decl.WriteString(stdlibWrapperTable[k].body + "\n")
		}
		decl.WriteString("\n")
	}
	// Go forwards via linkname (fallback fns + cross-package helpers).
	if len(goForwards) > 0 {
		var keys []string
		for k := range goForwards {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sig := goForwardSig[k]
			var ps, call strings.Builder
			for i, p := range sig.params {
				if i > 0 {
					ps.WriteString(", ")
					call.WriteString(", ")
				}
				tn := goTypeName(p)
				if i == 0 && p == ArgPtr {
					tn = moduleTypeName(rel)
				}
				fmt.Fprintf(&ps, "a%d %s", i, tn)
				fmt.Fprintf(&call, "a%d", i)
			}
			ret := ""
			if sig.hasRes {
				ret = " " + goTypeName(sig.res)
			}
			pulledRemote[goForwards[k]] = true
			fmt.Fprintf(&decl, "//go:linkname gcasmLN%s %s\nfunc gcasmLN%s(%s)%s\n\n", k, goForwards[k], k, ps.String(), ret)
			fmt.Fprintf(&decl, "func %s(%s)%s {\n\t", k, ps.String(), ret)
			if sig.hasRes {
				decl.WriteString("return ")
			}
			fmt.Fprintf(&decl, "gcasmLN%s(%s)\n}\n\n", k, call.String())
		}
	}
	// Type descriptor vars.
	if len(types.Names) > 0 {
		decl.WriteString("func gcasmTypePtr(v any) uintptr {\n\treturn *(*uintptr)(unsafe.Pointer(&v))\n}\n\n")
		for i, typ := range types.Names {
			fmt.Fprintf(&decl, "var gcasmType%d = gcasmTypePtr((%s)(nil))\n", i, localTypeSpelling(typ, importPath, rel))
		}
		decl.WriteString("\n")
	}
	// Never-returning trap targets. Self-contained per package: the
	// wasm_trap_* helpers live in base only under the multi-package
	// layout. Messages match the pure trap helpers.
	decl.WriteString(`//go:noinline
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

	// Remote fns referenced from the fallback bodies (extracted above):
	// a bare local decl per trampoline (the asm above implements it),
	// and — for unspellable owner paths only — the bodyless linkname
	// pull (plain Go on both sides; chunk import graphs are cyclic).
	remoteDecl := func(k string) (string, error) {
		fm := fnSymRe.FindStringSubmatch(k)
		idx, err := strconv.ParseUint(fm[1], 10, 32)
		if err != nil {
			return "", err
		}
		ft := mod.FuncTypeOf(uint32(idx))
		var sb strings.Builder
		fmt.Fprintf(&sb, "func %s(m %s", k, moduleTypeName(rel))
		for i, pk := range ft.Params {
			fmt.Fprintf(&sb, ", l%d %s", i, goTypeName(wasmKind(pk)))
		}
		sb.WriteString(")")
		if len(ft.Results) == 1 {
			fmt.Fprintf(&sb, " (r0 %s)", goTypeName(wasmKind(ft.Results[0])))
		}
		return sb.String(), nil
	}
	if len(remoteTramp) > 0 {
		var keys []string
		for k := range remoteTramp {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		decl.WriteString("\n// Remote functions referenced from local fallback bodies, reached\n// through the tail-JMP trampolines in the asm file.\n\n")
		for _, k := range keys {
			d, err := remoteDecl(k)
			if err != nil {
				return nil, err
			}
			decl.WriteString(d + "\n\n")
		}
	}
	if len(remoteFallbackLN) > 0 {
		var keys []string
		for k := range remoteFallbackLN {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		decl.WriteString("\n// Remote functions referenced from local fallback bodies on an\n// import path plan 9 asm cannot spell (Go-to-Go via linkname).\n\n")
		for _, k := range keys {
			d, err := remoteDecl(k)
			if err != nil {
				return nil, err
			}
			pulledRemote[remoteFallbackLN[k]] = true
			fmt.Fprintf(&decl, "//go:linkname %s %s\n%s\n\n", k, remoteFallbackLN[k], d)
		}
	}
	if conflicts := crossChunkPullConflicts(pulledRemote, spelledRemote); len(conflicts) > 0 {
		return nil, fmt.Errorf("%s/%s: cross-chunk symbols both //go:linkname-pulled and asm-referenced in one package (the compiler would emit a DUPOK ABI0 wrapper that can shadow the remote TEXT): %s", pkgOrRoot(rel), arch.name, strings.Join(conflicts, ", "))
	}
	if len(fallbackBodies) > 0 {
		decl.WriteString("\n// Per-function pure fallbacks (signatures ABIInternal cannot\n// register-assign).\n\n")
		for _, body := range fallbackBodies {
			decl.WriteString(body)
			decl.WriteString("\n\n")
		}
	}

	// O(1) jump-table support: table vars + the init that fills them
	// by scanning for the pad signatures (see jumppad.go).
	if jtGo := jt.EmitGo(arch.name); jtGo != "" {
		decl.WriteString("\n// Jump-table dispatch tables, filled at init by signature scan.\n\n")
		decl.WriteString(jtGo)
	}

	prefix := ""
	if rel != "" {
		prefix = rel + "/"
	}
	files := map[string][]byte{
		prefix + arch.name + ".s":             []byte(asmB.String()),
		prefix + "decls_" + arch.name + ".go": []byte(decl.String()),
	}
	return files, nil
}

// moduleTypeName spells the Module pointer type from inside a chunk
// package (base.Module) or the root package (Module).
func moduleTypeName(rel string) string {
	if rel == "" || rel == "base" {
		return "*Module"
	}
	return "*base.Module"
}

func goTypeName(k ArgKind) string {
	switch k {
	case ArgV128:
		return "[2]uint64"
	case ArgI64:
		return "int64"
	case ArgF32:
		return "float32"
	case ArgF64:
		return "float64"
	case ArgPtr:
		return "uintptr"
	case ArgU32:
		return "uint32"
	}
	return "int32"
}

// pkgNameOf finds the package clause used by the pure sources of rel.
func pkgNameOf(rel string, pure map[string][]byte) string {
	for name, data := range pure {
		d := filepath.Dir(name)
		if d == "." {
			d = ""
		}
		if d != rel || !strings.HasSuffix(name, ".go") {
			continue
		}
		for _, ln := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(ln, "package ") {
				return strings.TrimSpace(strings.TrimPrefix(ln, "package "))
			}
		}
	}
	if rel == "" {
		return "pkg"
	}
	return filepath.Base(rel)
}

// localTypeSpelling rewrites a captured type string (import-path
// qualified) into the in-package spelling.
func localTypeSpelling(typ, importPath, rel string) string {
	if rel == "" || rel == "base" {
		// Single-package root (importPath.Module) or base itself.
		typ = strings.ReplaceAll(typ, importPath+"/base.", "")
		return strings.ReplaceAll(typ, importPath+".", "")
	}
	typ = strings.ReplaceAll(typ, importPath+"/base.", "base.")
	selfPath := importPath + "/" + rel
	return strings.ReplaceAll(typ, selfPath+".", "")
}

// crossChunkPullConflicts returns, sorted, the qualified symbols a
// package both declares through a bodyless //go:linkname pull and
// references from its own asm by spelled name. The set must be empty:
// see the spelledRemote / pulledRemote comment in buildPkg.
func crossChunkPullConflicts(pulled, spelled map[string]bool) []string {
	var out []string
	for sym := range pulled {
		if spelled[sym] {
			out = append(out, sym)
		}
	}
	sort.Strings(out)
	return out
}
