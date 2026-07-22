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
func Build(mod *wasm.Module, mainSrc []byte, resFiles map[string][]byte, importPath string) (map[string][]byte, *BuildStats, error) {
	all := map[string][]byte{}
	if len(mainSrc) > 0 {
		all["gen.go"] = mainSrc
	}
	for name, data := range resFiles {
		all[name] = data
	}
	pure := PureFilter(all)

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
	// GCASM_FALLBACK_RANGE=lo-hi forces fn indices in [lo,hi) to the
	// pure fallback - a debugging knob for bisecting a miscompiled
	// function by halving the transformed set (fallback is fully
	// transparent to callers).
	bisectLo, bisectHi := -1, -1
	if r := os.Getenv("GCASM_FALLBACK_RANGE"); r != "" {
		if _, err := fmt.Sscanf(r, "%d-%d", &bisectLo, &bisectHi); err != nil {
			return nil, nil, fmt.Errorf("bad GCASM_FALLBACK_RANGE %q: %w", r, err)
		}
	}
	// DUFFZERO/DUFFCOPY functions fall back to pure (see errUnsupportedDuff).
	// Whether gc emits a duff sequence is toolchain- AND arch-dependent, so
	// take the UNION across every captured arch — a function that duffs on
	// one arch falls back on all of them, keeping the fallback set
	// arch-consistent (the pure guard and cross-package wiring assume it).
	duffIdx := map[uint32]bool{}
	// ehIdx: functions whose bodies use exception-handling / defer-recover
	// runtime machinery (panic/recover, &wasmExc heap alloc, defer). Those
	// bodies are not representable as leaf asm, so — like duff — they run
	// through the pure Go fallback on every arch.
	ehIdx := map[uint32]bool{}
	for _, spec := range archSpecs {
		for _, f := range caps[spec.name].fns {
			duff := hasDuffPseudo(f.Insns)
			eh := hasEHRuntimeCall(f.Insns)
			if !duff && !eh {
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
				if duff {
					duffIdx[uint32(idx64)] = true
				}
				if eh {
					ehIdx[uint32(idx64)] = true
				}
			}
		}
	}
	isFallbackSig := func(idx uint32) bool {
		if duffIdx[idx] || ehIdx[idx] {
			return true
		}
		if bisectLo >= 0 && int(idx) >= bisectLo && int(idx) < bisectHi {
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
	// symbol's owning package (arch-independent) for cross-chunk
	// reference resolution.
	fnOwner := map[string]string{} // "Fn83" → qualified path
	for _, spec := range archSpecs {
		ac := caps[spec.name]
		ac.byPkg = map[string][]*Fn{}
		for _, f := range ac.fns {
			i := strings.LastIndex(f.Name, ".")
			if i < 0 || !fnSymRe.MatchString(f.Name[i+1:]) {
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
		for _, rel := range pkgList {
			pfns := ac.byPkg[rel]
			if len(pfns) == 0 {
				continue
			}
			files, err := buildPkg(mod, importPath, rel, pfns, ac.dm, pkgSigs, fnKinds, isFallbackSig, fnOwner, pure, archStats, spec)
			if err != nil {
				return nil, nil, fmt.Errorf("gcasm bundle %s/%s: %w", pkgOrRoot(rel), spec.name, err)
			}
			for k, v := range files {
				out[k] = v
			}
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
			var kb strings.Builder
			kb.WriteString("//go:build " + spec.name + "\n\n")
			kb.WriteString("// Code generated by wasm2go (gcasm backend). DO NOT EDIT.\n//\n")
			kb.WriteString("// Import calls live in assembly, invisible to the linker's\n")
			kb.WriteString("// method pruning, which would fill every itab slot with\n")
			kb.WriteString("// runtime.unreachableMethod. init() is always reachable, so\n")
			kb.WriteString("// the never-taken calls below emit genuine interface call\n")
			kb.WriteString("// sites that pin each method. gcasmKeepAlive is never set.\n\n")
			kb.WriteString("package " + pkgNameOf(d, pure) + "\n\nvar gcasmKeepAlive bool\n\nfunc init() {\n\tif !gcasmKeepAlive {\n\t\treturn\n\t}\n")
			for _, call := range ifaces {
				kb.WriteString("\t" + call + "\n")
			}
			kb.WriteString("}\n")
			out[prefix+"keepalive_"+spec.name+".go"] = []byte(kb.String())
		}
	}

	// Rewrite the translated tree around the gcasm files: the
	// own-backend asm (.s) and its decls/alias sources (tagged
	// `amd64 || arm64`) go away; gcasm now serves BOTH amd64 and arm64,
	// so the pure guards stay `!amd64 && !arm64` (the pure fallback for
	// other arches + the `-tags purego` escape).
	for name, data := range all {
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
	transform func(*Fn, TransformOptions) (string, error)
	jtMarker  string // jump-tree marker for the stats counter
}

var archSpecs = []archSpec{
	{name: "amd64", transform: Transform, jtMarker: "\tJCC jt"},
	{name: "arm64", transform: TransformARM64, jtMarker: "\tBHS jt"},
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
) (map[string][]byte, error) {
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
	pool := &ConstPool{}
	types := &TypeTable{}
	var asmB strings.Builder
	// The build tag pins GOARCH explicitly: the bundle uses bare
	// arch filenames (amd64.s/arm64.s), which — having no prefix
	// before the arch — get NO implicit GOARCH constraint from the
	// name (Go 1.4+ only auto-tags files with a non-empty prefix).
	// This is exactly the header the own-asm backend emitted, and
	// matches the plain `//go:build <arch>` tag on the decls and
	// keepalive files below.
	asmB.WriteString("//go:build " + arch.name + "\n\n#include \"textflag.h\"\n#include \"funcdata.h\"\n\n")
	var declFns strings.Builder

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
			// Remote fn (transformed or fallback): a local Go wrapper
			// forwards through //go:linkname — the classic alias.go
			// shape. Imports cannot be used (chunk call graphs are
			// cyclic) and direct asm references cannot either (real
			// import paths contain dots, which Plan9 asm cannot
			// spell). For transformed remotes the linkname resolves
			// against the remote package's Go decl, whose compile
			// provides the ABI bridge onto the asm body.
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
	for _, f := range pfns {
		name := f.Name[strings.LastIndex(f.Name, ".")+1:]
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
		params, names, hasRes, res := fnKinds(idx)
		body, terr := arch.transform(f, TransformOptions{
			SymName:   name,
			CalleeSig: calleeSig,
			Params:    params,
			HasResult: hasRes,
			Result:    res,
			ArgNames:  names,
			Datas:     dm,
			Consts:    pool,
			Types:     types,
		})
		if terr != nil {
			// A duff body, or a jump table whose flag state cannot be replayed
			// at the leaf asm, falls back to the pure Go body (transparent to
			// callers) rather than aborting the whole bundle.
			if errors.Is(terr, errUnsupportedDuff) || errors.Is(terr, errUnsupportedJumpTable) {
				fallbackNames[name] = true
				stats.Fallback++
				continue
			}
			return nil, fmt.Errorf("transform %s: %w", f.Name, terr)
		}
		asmB.WriteString(body)
		asmB.WriteString("\n")
		if strings.Contains(body, arch.jtMarker) {
			stats.JumpTables++
		}
		stats.Transformed++
		// Bodyless Go declaration.
		ft := mod.FuncTypeOf(idx)
		var sb strings.Builder
		fmt.Fprintf(&sb, "func %s(m %s", name, moduleTypeName(rel))
		for i, p := range ft.Params {
			fmt.Fprintf(&sb, ", l%d %s", i, goTypeName(wasmKind(p)))
		}
		sb.WriteString(")")
		if hasRes {
			fmt.Fprintf(&sb, " (r0 %s)", goTypeName(res))
		}
		declFns.WriteString(sb.String() + "\n")
	}

	// Fallback bodies (extracted early: their Go-level FnN references
	// feed the trampoline/linkname sets below).
	var fallbackBodies []string
	fnTokRe := regexp.MustCompile(`\b[Ff]n\d+\b`)
	remoteFallbackLN := map[string]string{} // local FnN name → remote qualified
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
			// Cross-chunk references from Go code: transformed remote
			// fns get a local decl + tail-JMP trampoline (Go callers
			// reach the local ABI0 symbol via symabis); fallback
			// remote fns are plain Go, reached via //go:linkname.
			for _, tok := range fnTokRe.FindAllString(body, -1) {
				owner, known := fnOwner[tok]
				if !known || owner == selfPath {
					continue
				}
				remoteFallbackLN[tok] = owner + "." + tok
			}
		}
	}

	asmB.WriteString(pool.Emit())

	// Decls file.
	var decl strings.Builder
	decl.WriteString("//go:build " + arch.name + "\n\n")
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

	// Fallback bodies on amd64 (extracted above), plus linkname decls
	// for the remote FALLBACK fns those bodies reference (plain Go on
	// both sides).
	if len(remoteFallbackLN) > 0 {
		var keys []string
		for k := range remoteFallbackLN {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		decl.WriteString("\n// Remote pure-fallback functions referenced from local fallback\n// bodies (Go-to-Go via linkname; chunk import graphs are cyclic).\n\n")
		for _, k := range keys {
			fm := fnSymRe.FindStringSubmatch(k)
			idx, err := strconv.ParseUint(fm[1], 10, 32)
			if err != nil {
				return nil, err
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
			fmt.Fprintf(&decl, "//go:linkname %s %s\n%s\n\n", k, remoteFallbackLN[k], sb.String())
		}
	}
	if len(fallbackBodies) > 0 {
		decl.WriteString("\n// Per-function pure fallbacks (signatures ABIInternal cannot\n// register-assign).\n\n")
		for _, body := range fallbackBodies {
			decl.WriteString(body)
			decl.WriteString("\n\n")
		}
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
