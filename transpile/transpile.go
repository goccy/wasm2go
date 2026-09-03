// Package transpile is the public library API of the wasm2go transpiler:
// parse a WebAssembly binary and translate it to standalone Go source.
//
// It is the importable counterpart of the `wasm2go` command. External
// tools that need to drive translation programmatically (for example a
// code generator that emits a Go bridge over a transpiled module) call
// Translate directly instead of shelling out to the CLI.
//
// Usage:
//
//	m, err := transpile.Parse(bytes.NewReader(wasmBytes))
//	if err != nil { ... }
//	res, err := transpile.Translate(out, m, transpile.Options{
//		Package:          "genwasm",
//		OutputImportPath: "example.com/myproj/internal/genwasm",
//	})
//
// The SSA pipeline, data sidecar layout, native wasip1 implementation,
// and (for large modules) the multi-package + linkname-split layout
// are auto-derived from the input and have no caller-visible knobs.
package transpile

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/goccy/wasm2go/internal/asmgen"
	"github.com/goccy/wasm2go/internal/codegen"
	"github.com/goccy/wasm2go/internal/gcasm"
	"github.com/goccy/wasm2go/internal/wasm"
)

// Module is a parsed WebAssembly module — an opaque handle produced by
// Parse and consumed by Translate.
type Module = wasm.Module

// Options configures Translate. Package and OutputImportPath are
// required; the remaining fields are described in the field
// documentation on the type. See the package doc above for the list
// of behaviors wasm2go auto-derives — none of them are configurable.
type Options = codegen.Options

// Result holds the auxiliary outputs of Translate:
//
//   - Sidecars: data files (e.g. the data.bin //go:embed blob).
//   - Files: in multi-package mode, the relative-path → contents map of
//     every generated Go file; nil in single-file mode.
//   - AuxFiles: extra Go-source files that must land next to the main
//     output (e.g. future runtime companions). Currently always empty —
//     the WASI runtime is a single self-contained file with no
//     per-platform splits — but the field is retained so callers can
//     keep handling it generically.
type Result = codegen.Result

// Parse decodes a WebAssembly binary module from r.
func Parse(r io.Reader) (*Module, error) {
	return wasm.Parse(r)
}

// Translate emits Go source for module m. When the wasm fits the
// single-file budget, source is written to w and Result.Files is nil.
// When the wasm exceeds the budget, w is unused and Result.Files
// holds the relative-path → bytes for the multi-package layout. It
// is the library entry point that the wasm2go command itself wraps.
//
// The amd64 fast path is the gcasm backend: the pure-Go bodies are
// compiled by the host Go toolchain at GENERATION time, the -S
// listings are captured and mechanically transformed into ABI0 .s
// (see internal/gcasm). Functions the transform cannot register-map
// keep their pure bodies per-function. Every non-amd64 GOARCH builds
// the pure code, which outperforms the retired own-emitter asm in
// every measured configuration.
func Translate(w io.Writer, m *Module, opts Options) (Result, error) {
	var mainBuf bytes.Buffer
	// Assembly overrides: validate the project's manifest against the
	// module up front, and pin its exports out of line before lowering.
	var ovr *gcasm.AsmOverrides
	if opts.AsmOverrides != "" {
		var err error
		if ovr, err = gcasm.LoadAsmOverrides(opts.AsmOverrides, m); err != nil {
			return Result{}, err
		}
		names := make([]string, 0, len(ovr.Functions))
		for name := range ovr.Functions {
			names = append(names, name)
		}
		sort.Strings(names)
		opts.NoInlineExports = append(append([]string(nil), opts.NoInlineExports...), names...)
	}
	res, err := codegen.Translate(&mainBuf, m, opts)
	if err != nil {
		return res, err
	}

	// PureOnly: the pure bodies were emitted untagged, so they compile
	// on every GOARCH and no asm bundle is wanted. This is the
	// ABIInternal reference backend for benchmarking.
	if opts.PureOnly {
		if _, err := w.Write(mainBuf.Bytes()); err != nil {
			return res, err
		}
		return res, nil
	}

	// gcasm backend: replace the own-emitter asm bundle.
	treeIn := map[string][]byte{}
	for name, data := range res.Sidecars {
		treeIn[name] = data
	}
	for name, data := range res.Files {
		treeIn[name] = data
	}
	synthSigs := map[string]gcasm.SynthSig{}
	for name, sig := range res.OutlinedSigs {
		synthSigs[name] = gcasm.SynthSig{Params: sig.Params, Result: sig.Result, Packed: sig.Packed}
	}
	var directAsm map[string]gcasm.DirectAsmFn
	for name, df := range res.DirectAsmSSA {
		if directAsm == nil {
			directAsm = map[string]gcasm.DirectAsmFn{}
		}
		var windows []asmgen.FusedWindow
		for _, w := range df.Windows {
			conv := func(srcs []codegen.DirectAsmParamSrc) []asmgen.FusedParamSrc {
				out := make([]asmgen.FusedParamSrc, len(srcs))
				for i, s := range srcs {
					out[i] = asmgen.FusedParamSrc{IsConst: s.IsConst, Const: s.Const, Val: s.Val, ArgIdx: s.ArgIdx}
				}
				return out
			}
			windows = append(windows, asmgen.FusedWindow{
				Tree: w.Tree, Members: w.Members, Roots: w.Roots,
				ScalarSrc: conv(w.ScalarSrc), FloatSrc: conv(w.FloatSrc), PairSrc: conv(w.PairSrc),
			})
		}
		directAsm[name] = gcasm.DirectAsmFn{Fn: df.Fn, Sig: df.Sig, Packed: df.Packed, PackedParams: df.PackedParams, Windows: windows}
	}
	var directAsmExc *asmgen.ExcOffsets
	if res.DirectAsmExc != nil {
		directAsmExc = &asmgen.ExcOffsets{
			Pending: res.DirectAsmExc.Pending,
			Tag:     res.DirectAsmExc.Tag,
			Vals:    res.DirectAsmExc.Vals,
		}
	}
	gcasmFiles, gstats, err := gcasm.Build(m, mainBuf.Bytes(), treeIn, opts.OutputImportPath, res.FusedSimd, res.FusedLoops, res.Outlined, synthSigs, gcasm.Config{
		FastMath:         opts.FastMath,
		AsmOverrides:     ovr,
		FuseLoopUnroll:   opts.FuseLoopUnroll,
		DirectAsm:        directAsm,
		DirectAsmGlobals: res.DirectAsmGlobals,
		DirectAsmExc:     directAsmExc,
	})
	if err != nil {
		return res, fmt.Errorf("gcasm backend: %w", err)
	}
	if n := gstats.SimdSpliced + gstats.SimdKept; n > 0 {
		fmt.Fprintf(os.Stderr, "wasm2go: gcasm SIMD splice: %d call sites inlined, %d kept as calls\n",
			gstats.SimdSpliced, gstats.SimdKept)
	}
	if n := gstats.DirectAsm + gstats.DirectAsmFallback; n > 0 {
		fmt.Fprintf(os.Stderr, "wasm2go: direct-asm: %d bodies emitted, %d fell back to the transform\n",
			gstats.DirectAsm, gstats.DirectAsmFallback)
	}
	if res.Files == nil {
		res.Files = map[string][]byte{}
	}
	for name, data := range gcasmFiles {
		if data == nil {
			delete(res.Files, name)
			continue
		}
		res.Files[name] = data
	}
	if _, err := w.Write(mainBuf.Bytes()); err != nil {
		return res, err
	}
	return res, nil
}

// Transpile is the one-shot convenience wrapper that runs Parse followed
// by Translate, returning the same Result Translate would. It is the
// path most callers want when they have the wasm bytes in hand and do
// not need to inspect the parsed Module.
func Transpile(r io.Reader, w io.Writer, opts Options) (Result, error) {
	m, err := Parse(r)
	if err != nil {
		return Result{}, err
	}
	return Translate(w, m, opts)
}

// SetMultiPackageThreshold overrides the auto-multi-package decision
// threshold to b bytes for the rest of the current process. Pass 0 to
// always select the multi-package + linkname-split layout regardless
// of wasm size; pass -1 to restore the default (auto-derived from
// wasm size). The returned closure restores the previous value and
// should be invoked via defer:
//
//	defer transpile.SetMultiPackageThreshold(0)()
//
// //
// The defaults are auto-derived from wasm size and most callers
// should not touch this. The override is supported for diagnostics,
// build-time memory tuning, and exercising the multi-package path on
// small fixtures in tests.
func SetMultiPackageThreshold(b int) func() {
	return codegen.SetMultiPackageThreshold(b)
}
