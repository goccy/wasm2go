// Package transpile is the public library API of the wasm2go transpiler:
// parse a WebAssembly binary and translate it to standalone Go source.
//
// It is the importable counterpart of the `wasm2go` command. External
// tools — for example protoc-gen-wasmify-go, which generates a Go bridge
// that drives a wasm2go-transpiled module — call Translate directly
// instead of shelling out to the CLI.
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
	"io"

	"github.com/goccy/wasm2go/internal/codegen"
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
func Translate(w io.Writer, m *Module, opts Options) (Result, error) {
	return codegen.Translate(w, m, opts)
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
