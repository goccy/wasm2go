package gcasm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/wasm"
)

// TestGate3RealModule is the scale gate: translate a REAL wasm module
// (python.wasm / googlesql.wasm), capture the pure build, and push
// every generated function through the transform. No execution — the
// gate inventories which shapes survive, which fail and why, and
// whether the whole-module output is deterministic.
//
// Manual: GCASM_GATE3_WASM=/path/to/module.wasm go test -run TestGate3RealModule -v
func TestGate3RealModule(t *testing.T) {
	wasmPath := os.Getenv("GCASM_GATE3_WASM")
	if wasmPath == "" {
		t.Skip("set GCASM_GATE3_WASM to run the real-module scale gate")
	}
	bin, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := wasm.Parse(bytes.NewReader(bin))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	res, err := codegen.Translate(&buf, mod, codegen.Options{Package: "pkg", OutputImportPath: "gentest/pkg"})
	if err != nil {
		t.Fatal(err)
	}

	pureFiles := map[string][]byte{}
	if buf.Len() > 0 { // multi-package mode leaves the main writer empty
		pureFiles["gen.go"] = buf.Bytes()
	}
	for name, data := range res.Sidecars {
		pureFiles[name] = data
	}
	for name, data := range res.Files {
		pureFiles[name] = data
	}
	pureFiles = PureFilter(pureFiles)
	t.Logf("pure tree: %d files", len(pureFiles))

	dir := t.TempDir()
	files := map[string][]byte{"go.mod": []byte("module gentest\n\ngo 1.25.0\n")}
	pkgs := map[string]bool{"gentest/pkg": true}
	for name, data := range pureFiles {
		files["pkg/"+name] = data
		if d := filepath.Dir(name); d != "." {
			pkgs["gentest/pkg/"+d] = true
		}
	}
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var pkgList []string
	for p := range pkgs {
		pkgList = append(pkgList, p)
	}
	sort.Strings(pkgList)
	t.Logf("packages: %v", pkgList)

	// Capture ALL generated packages in one build.
	fns, datas, err := Capture(dir, "gentest/pkg/...")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("captured %d fns, %d data syms", len(fns), len(datas))
	dm := map[string]*DataSym{}
	for _, d := range datas {
		dm[d.Name] = d
	}
	sigs := parseSigs(pureFiles)

	fnRe := regexp.MustCompile(`^(gentest/pkg(?:/[a-z0-9]+)?)\.([Ff]n\d+)$`)
	countByPkg := map[string]int{}
	for _, f := range fns {
		if m := fnRe.FindStringSubmatch(f.Name); m != nil {
			countByPkg[m[1]]++
		}
	}
	t.Logf("fn counts by package: %v", countByPkg)

	// Per-function transform attempt. Callee resolution: same-package
	// plain functions with parseable sigs marshal; cross-package and
	// unknown callees fail that function (inventoried, not fatal).
	failKinds := map[string]int{}
	failSamples := map[string]string{}
	okCount, jtCount, tyCount := 0, 0, 0
	pool := &ConstPool{}
	types := &TypeTable{}
	var totalOut int
	for _, f := range fns {
		m := fnRe.FindStringSubmatch(f.Name)
		if m == nil {
			continue
		}
		var failReason string
		calleeSig := func(sym string) ([]ArgKind, bool, ArgKind, string, bool) {
			// Stdlib callees resolve to the local wrapper functions
			// the pipeline emits (see fixtureGate's stdlibWrappers).
			if std, ok := gate3StdlibSigs[sym]; ok {
				return std.params, std.hasRes, std.res, "·" + std.wrap, true
			}
			i := strings.LastIndex(sym, ".")
			if i < 0 {
				return nil, false, 0, "", false
			}
			cpkg, cname := sym[:i], sym[i+1:]
			if !strings.HasPrefix(cpkg, "gentest/") {
				return nil, false, 0, "", false
			}
			// Cross-package FnN resolve to the same bare local symbol:
			// the pipeline provides ABI0 tail-JMP trampolines (the
			// asm backend's appendAsmCrossChunkTrampolines pattern),
			// so the callee's stack contract is identical.
			sig, found := sigs[cname]
			if !found || !sig.ok {
				if failReason == "" {
					failReason = "unparseable callee sig: " + sym
				}
				return nil, false, 0, "", false
			}
			return sig.params, sig.hasRes, sig.res, "·" + cname, true
		}
		// Wasm signature for this fn.
		sig, found := sigs[m[2]]
		if !found || !sig.ok {
			failKinds["own sig unparseable"]++
			continue
		}
		names := []string{"m"}
		for i := 1; i < len(sig.params); i++ {
			names = append(names, fmt.Sprintf("l%d", i-1))
		}
		body, terr := Transform(f, TransformOptions{
			SymName:   m[2],
			CalleeSig: calleeSig,
			Params:    sig.params,
			HasResult: sig.hasRes,
			Result:    sig.res,
			ArgNames:  names,
			Datas:     dm,
			Consts:    pool,
			Types:     types,
		})
		switch {
		case terr == nil && failReason == "":
			okCount++
			totalOut += len(body)
			if strings.Contains(body, "\tjt") || strings.Contains(body, "JCC jt") {
				jtCount++
			}
		default:
			reason := failReason
			if terr != nil {
				reason = terr.Error()
			}
			kind := classifyFail(reason)
			failKinds[kind]++
			if _, ok := failSamples[kind]; !ok {
				failSamples[kind] = f.Name + ": " + reason
			}
		}
	}
	tyCount = len(types.Names)
	t.Logf("transform OK: %d fns (%.1f MB asm), jump-table fns: %d, type refs: %d, const pool: %d",
		okCount, float64(totalOut)/1e6, jtCount, tyCount, len(pool.names))
	var kinds []string
	for k := range failKinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		t.Logf("FAIL[%d] %s — e.g. %s", failKinds[k], k, failSamples[k])
	}
}

// gate3StdlibSigs mirrors fixtureGate's stdlib wrapper table.
var gate3StdlibSigs = func() map[string]struct {
	params []ArgKind
	hasRes bool
	res    ArgKind
	wrap   string
} {
	out := map[string]struct {
		params []ArgKind
		hasRes bool
		res    ArgKind
		wrap   string
	}{}
	f64u := []ArgKind{ArgF64}
	for name, wrap := range map[string]string{
		"math.Ceil": "gcasmMathCeil", "math.Floor": "gcasmMathFloor",
		"math.Trunc": "gcasmMathTrunc", "math.RoundToEven": "gcasmMathRoundToEven",
		"math.Sqrt": "gcasmMathSqrt",
	} {
		out[name] = struct {
			params []ArgKind
			hasRes bool
			res    ArgKind
			wrap   string
		}{f64u, true, ArgF64, wrap}
	}
	for name, e := range map[string]struct {
		k    ArgKind
		wrap string
	}{
		"math/bits.OnesCount32":     {ArgI32, "gcasmBitsOnesCount32"},
		"math/bits.OnesCount64":     {ArgI64, "gcasmBitsOnesCount64"},
		"math/bits.LeadingZeros32":  {ArgI32, "gcasmBitsLeadingZeros32"},
		"math/bits.LeadingZeros64":  {ArgI64, "gcasmBitsLeadingZeros64"},
		"math/bits.TrailingZeros32": {ArgI32, "gcasmBitsTrailingZeros32"},
		"math/bits.TrailingZeros64": {ArgI64, "gcasmBitsTrailingZeros64"},
	} {
		out[name] = struct {
			params []ArgKind
			hasRes bool
			res    ArgKind
			wrap   string
		}{[]ArgKind{e.k}, true, ArgI64, e.wrap}
	}
	return out
}()

// classifyFail buckets a transform failure reason for inventory.
// "pure-fallback" buckets are per-function shapes the pipeline keeps
// as pure Go (correct + gc-native body; only the call boundary pays).
func classifyFail(reason string) string {
	switch {
	case strings.Contains(reason, "exceeds ABIInternal registers"):
		return "pure-fallback: >9 int args"
	case strings.Contains(reason, "unparseable callee"):
		return "unparseable callee sig"
	case strings.Contains(reason, "unhandled runtime call"):
		i := strings.Index(reason, "unhandled runtime call")
		return reason[i:min(i+45, len(reason))]
	case strings.Contains(reason, "unmarshalled direct call"):
		return "unmarshalled direct call"
	case strings.Contains(reason, "type-descriptor"):
		return "unhandled type-descriptor operand"
	case strings.Contains(reason, "jump table"):
		return "jump-table shape"
	default:
		if len(reason) > 60 {
			return reason[:60]
		}
		return reason
	}
}
