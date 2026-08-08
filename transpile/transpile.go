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
	res, err := codegen.Translate(&mainBuf, m, opts)
	if err != nil {
		return res, err
	}

	// PureOnly (or its subprocess form WASM2GO_PURE, honored inside
	// codegen.Translate): the pure bodies were emitted untagged, so
	// they compile on every GOARCH and no asm bundle is wanted. This
	// is the ABIInternal reference backend for benchmarking.
	if opts.PureOnly || os.Getenv("WASM2GO_PURE") != "" {
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
	var nrc2 *gcasm.Nrc2Spec
	if res.Nrc2VecDot != "" {
		nrc2 = &gcasm.Nrc2Spec{VecDot: res.Nrc2VecDot, Companion: res.Nrc2Companion}
	}
	gcasmFiles, gstats, err := gcasm.Build(m, mainBuf.Bytes(), treeIn, opts.OutputImportPath, res.FusedSimd, res.FusedLoops, res.Outlined, synthSigs, nrc2)
	if err != nil {
		return res, fmt.Errorf("gcasm backend: %w", err)
	}
	if n := gstats.SimdSpliced + gstats.SimdKept; n > 0 {
		fmt.Fprintf(os.Stderr, "wasm2go: gcasm SIMD splice: %d call sites inlined, %d kept as calls\n",
			gstats.SimdSpliced, gstats.SimdKept)
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
// Subprocess invocations of wasm2go (e.g. a wasm2go-using protoc
// plugin spawned by buf generate) can override the threshold through
// the WASM2GO_MULTIPACKAGE_THRESHOLD environment variable; the
// in-process override takes priority when both are set.
//
// The defaults are auto-derived from wasm size and most callers
// should not touch this. The override is supported for diagnostics,
// build-time memory tuning, and exercising the multi-package path on
// small fixtures in tests.
func SetMultiPackageThreshold(b int) func() {
	return codegen.SetMultiPackageThreshold(b)
}
