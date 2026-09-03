package gcasm

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/goccy/wasm2go/internal/wasm"
)

// Assembly overrides let the PROJECT that produced the wasm supply the
// asm body of an exported leaf function, in place of the body the
// transpiler would lower from the wasm. wasm2go stays agnostic of what
// the function computes: it validates the manifest against the module
// (export present, signature as declared, pointer width as declared),
// wraps each body in the fixed ABI below, and dispatches at runtime on
// the CPU features each body declares. The lowered body stays as the
// portable fallback, and the pure-Go build is untouched.
//
// The contract (docs/asm-overrides.md) keeps a body inside the wasm
// execution model: it may touch linear memory only through the base
// and size the prologue hands it, must send every out-of-range access
// to the ovr_oob trap, and must not call anything — no host imports, no
// other functions. A body that needs more than that is not an assembly
// override; it is a change to the wasm.
//
// Manifest (JSON):
//
//	{
//	  "version": 1,
//	  "memory64": true,
//	  "functions": [
//	    {
//	      "export": "my_dot",
//	      "params": ["i32", "i64", "i64"],
//	      "result": "f32",
//	      "bodies": [
//	        {"arch": "arm64", "feature": "dotprod", "frame": 16, "file": "my_dot_arm64_dotprod.s"},
//	        {"arch": "amd64", "feature": "avx2",    "frame": 16, "file": "my_dot_amd64_avx2.s"}
//	      ]
//	    }
//	  ]
//	}
//
// File paths resolve relative to the manifest. "result" is omitted or
// null for a function without a result.

// AsmOverrides is a validated manifest: functions keyed by export name.
type AsmOverrides struct {
	Functions map[string]*AsmOverride
}

// AsmOverride is one exported function with its replacement bodies.
type AsmOverride struct {
	Export  string
	FuncIdx uint32
	Params  []wasm.ValType
	Result  *wasm.ValType
	// Bodies by architecture, each list ordered from the most specific
	// feature level to the baseline (see overrideFeatureLevels).
	Bodies map[string][]AsmOverrideBody
}

// AsmOverrideBody is one architecture/feature-level body.
type AsmOverrideBody struct {
	Arch    string
	Feature string
	Frame   int
	File    string
	Asm     string
}

// overrideFeatureLevels lists, per architecture, the feature names a body
// may declare, most specific first. The first entry of each list that
// the running CPU supports wins; the baseline entry (last) needs no
// check. The mirror names are the base package's CPU feature vars.
var overrideFeatureLevels = map[string][]struct {
	name       string
	featureVar string // "" for the architecture baseline
}{
	"arm64": {{"i8mm", "CPUI8MM"}, {"dotprod", "CPUDotProd"}, {"neon", ""}},
	"amd64": {{"avx512vnni", "HasAVX512VNNI"}, {"avx2", "HasAVX2"}, {"sse4", ""}},
}

// overrideFeatureRank maps arch/feature to its position in
// overrideFeatureLevels, or -1 when unknown.
func overrideFeatureRank(arch, feature string) int {
	for i, l := range overrideFeatureLevels[arch] {
		if l.name == feature {
			return i
		}
	}
	return -1
}

// overrideValType parses a manifest type name.
func overrideValType(s string) (wasm.ValType, error) {
	switch s {
	case "i32":
		return wasm.ValI32, nil
	case "i64":
		return wasm.ValI64, nil
	case "f32":
		return wasm.ValF32, nil
	case "f64":
		return wasm.ValF64, nil
	}
	return 0, fmt.Errorf("unsupported value type %q (i32, i64, f32, f64)", s)
}

type overrideManifest struct {
	Version   int  `json:"version"`
	Memory64  bool `json:"memory64"`
	Functions []struct {
		Export string   `json:"export"`
		Params []string `json:"params"`
		Result *string  `json:"result"`
		Bodies []struct {
			Arch    string `json:"arch"`
			Feature string `json:"feature"`
			Frame   int    `json:"frame"`
			File    string `json:"file"`
		} `json:"bodies"`
	} `json:"functions"`
}

// LoadAsmOverrides reads and validates a manifest against mod.
func LoadAsmOverrides(path string, mod *wasm.Module) (*AsmOverrides, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("assembly overrides: %w", err)
	}
	var man overrideManifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&man); err != nil {
		return nil, fmt.Errorf("assembly overrides %s: %w", path, err)
	}
	if man.Version != 1 {
		return nil, fmt.Errorf("assembly overrides %s: unsupported version %d", path, man.Version)
	}
	if man.Memory64 != mod.Memory64() {
		return nil, fmt.Errorf("assembly overrides %s: manifest declares memory64=%v, module is memory64=%v", path, man.Memory64, mod.Memory64())
	}
	if len(man.Functions) == 0 {
		return nil, fmt.Errorf("assembly overrides %s: no functions", path)
	}
	exports := map[string]uint32{}
	for _, e := range mod.Exports {
		if e.Kind == wasm.ExportFunc {
			exports[e.Name] = e.Index
		}
	}
	dir := filepath.Dir(path)
	out := &AsmOverrides{Functions: map[string]*AsmOverride{}}
	for _, k := range man.Functions {
		if _, dup := out.Functions[k.Export]; dup {
			return nil, fmt.Errorf("assembly overrides: export %q listed twice", k.Export)
		}
		idx, ok := exports[k.Export]
		if !ok {
			return nil, fmt.Errorf("assembly overrides: export %q is not an exported function of the module", k.Export)
		}
		if idx < mod.NumImportedFuncs {
			return nil, fmt.Errorf("assembly overrides: export %q is an imported function", k.Export)
		}
		ov := &AsmOverride{Export: k.Export, FuncIdx: idx, Bodies: map[string][]AsmOverrideBody{}}
		for _, p := range k.Params {
			vt, err := overrideValType(p)
			if err != nil {
				return nil, fmt.Errorf("assembly overrides: %s: %w", k.Export, err)
			}
			ov.Params = append(ov.Params, vt)
		}
		if k.Result != nil {
			vt, err := overrideValType(*k.Result)
			if err != nil {
				return nil, fmt.Errorf("assembly overrides: %s: result: %w", k.Export, err)
			}
			ov.Result = &vt
		}
		sig := mod.FuncTypeOf(idx)
		if !overrideSigEqual(sig, ov.Params, ov.Result) {
			return nil, fmt.Errorf("assembly overrides: %s: manifest signature %s does not match the module's %s",
				k.Export, overrideSigString(ov.Params, ov.Result), overrideSigString(sig.Params, overrideResultOf(sig)))
		}
		if len(k.Bodies) == 0 {
			return nil, fmt.Errorf("assembly overrides: %s: no bodies", k.Export)
		}
		seen := map[string]bool{}
		for _, b := range k.Bodies {
			if _, known := overrideFeatureLevels[b.Arch]; !known {
				return nil, fmt.Errorf("assembly overrides: %s: unsupported arch %q", k.Export, b.Arch)
			}
			if overrideFeatureRank(b.Arch, b.Feature) < 0 {
				return nil, fmt.Errorf("assembly overrides: %s: unsupported feature %q for %s", k.Export, b.Feature, b.Arch)
			}
			key := b.Arch + "/" + b.Feature
			if seen[key] {
				return nil, fmt.Errorf("assembly overrides: %s: body for %s listed twice", k.Export, key)
			}
			seen[key] = true
			if b.Frame < 0 || b.Frame%8 != 0 {
				return nil, fmt.Errorf("assembly overrides: %s (%s): frame must be a non-negative multiple of 8, got %d", k.Export, key, b.Frame)
			}
			file := b.File
			if !filepath.IsAbs(file) {
				file = filepath.Join(dir, file)
			}
			text, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("assembly overrides: %s (%s): %w", k.Export, key, err)
			}
			if err := checkAsmOverrideBody(string(text)); err != nil {
				return nil, fmt.Errorf("assembly overrides: %s (%s): %s: %w", k.Export, key, b.File, err)
			}
			ov.Bodies[b.Arch] = append(ov.Bodies[b.Arch], AsmOverrideBody{Arch: b.Arch, Feature: b.Feature, Frame: b.Frame, File: file, Asm: string(text)})
		}
		for arch := range ov.Bodies {
			bs := ov.Bodies[arch]
			sort.Slice(bs, func(i, j int) bool {
				return overrideFeatureRank(arch, bs[i].Feature) < overrideFeatureRank(arch, bs[j].Feature)
			})
		}
		out.Functions[k.Export] = ov
	}
	return out, nil
}

func overrideResultOf(sig wasm.FuncType) *wasm.ValType {
	if len(sig.Results) == 0 {
		return nil
	}
	r := sig.Results[0]
	return &r
}

func overrideSigEqual(sig wasm.FuncType, params []wasm.ValType, result *wasm.ValType) bool {
	if len(sig.Params) != len(params) {
		return false
	}
	for i := range params {
		if sig.Params[i] != params[i] {
			return false
		}
	}
	switch {
	case len(sig.Results) == 0:
		return result == nil
	case len(sig.Results) == 1:
		return result != nil && *result == sig.Results[0]
	}
	return false
}

func overrideSigString(params []wasm.ValType, result *wasm.ValType) string {
	var ps []string
	for _, p := range params {
		ps = append(ps, p.String())
	}
	s := "(" + strings.Join(ps, ", ") + ")"
	if result != nil {
		s += " -> " + result.String()
	}
	return s
}

// checkAsmOverrideBody enforces the parts of the contract visible in the
// text: no TEXT (wasm2go writes the header), no calls or system
// instructions (a body is a leaf inside the wasm execution model), and
// no symbol references except the body's own ovr_-prefixed data. The
// assembler is the real parser; this is the structural gate over a
// foreign format, and every line either passes a rule or is left to
// the assembler.
func checkAsmOverrideBody(text string) error {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if i := strings.Index(l, "//"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		fields := strings.Fields(l)
		op := fields[0]
		if strings.HasSuffix(op, ":") {
			if strings.HasPrefix(op, "ovr_") {
				return fmt.Errorf("line %d: label %q uses the reserved ovr_ prefix", line, op)
			}
			if len(fields) == 1 {
				continue
			}
			op = fields[1]
		}
		switch op {
		case "TEXT":
			return fmt.Errorf("line %d: TEXT directive: wasm2go writes the function header", line)
		case "CALL", "BL", "BLR", "SYSCALL", "SVC", "INT", "RET;":
			return fmt.Errorf("line %d: %s: an override body is a leaf; it may not call or trap on its own (use ovr_oob)", line, op)
		case "DATA", "GLOBL":
			if len(fields) < 2 || !strings.HasPrefix(fields[1], "·ovr_") {
				return fmt.Errorf("line %d: %s symbol must be ·ovr_-prefixed", line, op)
			}
			continue
		}
		// Symbol references: only the body's own ovr_ data.
		rest := l
		for {
			i := strings.Index(rest, "·")
			if i < 0 {
				break
			}
			ref := rest[i+len("·"):]
			j := strings.IndexAny(ref, "(+ ,\t")
			if j < 0 {
				j = len(ref)
			}
			if !strings.HasPrefix(ref[:j], "ovr_") {
				return fmt.Errorf("line %d: reference to symbol %q: an override body may only reference its own ·ovr_ data", line, ref[:j])
			}
			rest = ref[j:]
		}
	}
	return sc.Err()
}

// overrideArgOffsets is the argument layout a body addresses as
// l<i>+<offset>(FP) / r0+<offset>(FP): the ABI0 rule of abi0ArgBytes
// (each value at its natural size and alignment after the 8-byte
// module pointer; a result at the next 8-aligned offset).
func overrideArgOffsets(params []wasm.ValType, result *wasm.ValType) map[string]int {
	offsets := map[string]int{}
	off := 8
	size := func(vt wasm.ValType) int {
		if vt == wasm.ValI32 || vt == wasm.ValF32 {
			return 4
		}
		return 8
	}
	for i, p := range params {
		sz := size(p)
		off = (off + sz - 1) &^ (sz - 1)
		offsets[fmt.Sprintf("l%d", i)] = off
		off += sz
	}
	if result != nil {
		off = (off + 7) &^ 7
		offsets["r0"] = off
	}
	return offsets
}

// asmOverrideText wraps body in the override ABI under sym: the
// TEXT header, the prologue that loads the linear-memory base and size
// into the contract registers, the body, and the ovr_oob epilogue that
// calls the module's out-of-bounds trap.
//
//	arm64: R20 = memory base, R21 = memory size (bytes); R0 holds the
//	       module pointer on entry and may be clobbered.
//	amd64: R14 = memory base, R15 = memory size (bytes); AX holds the
//	       module pointer on entry and may be clobbered.
func asmOverrideText(arch, sym, trapSym string, offs *ModuleOffsets, body AsmOverrideBody, argBytes string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s: assembly override (%s/%s) from %s.\n", sym, body.Arch, body.Feature, filepath.Base(body.File))
	fmt.Fprintf(&b, "TEXT ·%s(SB), $%d-%s\n", sym, body.Frame, argBytes)
	b.WriteString("\tNO_LOCAL_POINTERS\n")
	switch arch {
	case "arm64":
		b.WriteString("\tMOVD\tm+0(FP), R0\n")
		fmt.Fprintf(&b, "\tMOVD\t%d(R0), R21\n", offs.MemSize)
		b.WriteString("\tMOVD\t(R21), R21\n")
		fmt.Fprintf(&b, "\tMOVD\t%d(R0), R20\n", offs.M)
	case "amd64":
		b.WriteString("\tMOVQ\tm+0(FP), AX\n")
		fmt.Fprintf(&b, "\tMOVQ\t%d(AX), R15\n", offs.MemSize)
		b.WriteString("\tMOVQ\t(R15), R15\n")
		fmt.Fprintf(&b, "\tMOVQ\t%d(AX), R14\n", offs.M)
	}
	b.WriteString(strings.TrimRight(body.Asm, "\n"))
	b.WriteString("\novr_oob:\n")
	if arch == "amd64" && body.Feature != "sse4" {
		b.WriteString("\tVZEROUPPER\n")
	}
	fmt.Fprintf(&b, "\tCALL\t·%s(SB)\n\tRET\n", trapSym)
	return b.String()
}

// overrideDispatchStub is the frameless entry under the function's own
// name: one predicted branch per feature level, most specific first,
// then the baseline target. levels pairs each mirror var with the
// body symbol it selects.
func overrideDispatchStub(arch, sym string, levels [][2]string, baseSym, argBytes string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TEXT ·%s(SB), NOSPLIT, $0-%s\n", sym, argBytes)
	for _, l := range levels {
		mirror, target := l[0], l[1]
		if arch == "amd64" {
			fmt.Fprintf(&b, "\tCMPB ·%s(SB), $0\n\tJEQ 2(PC)\n\tJMP ·%s(SB)\n", mirror, target)
		} else {
			fmt.Fprintf(&b, "\tMOVBU ·%s(SB), R27\n\tCBZ R27, 2(PC)\n\tJMP ·%s(SB)\n", mirror, target)
		}
	}
	fmt.Fprintf(&b, "\tJMP ·%s(SB)\n", baseSym)
	return b.String()
}
