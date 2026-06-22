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
	"io"
	"strings"

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
	res, err := codegen.Translate(w, m, opts)
	if err != nil {
		return res, err
	}
	// Weave a `purego` escape into every generated build constraint so the
	// pure-Go fallback can be selected on ANY GOARCH with `-tags purego`.
	// This is a no-op for normal builds (purego is off by default, so the
	// constraints behave exactly as before) and exists so the asm path can be
	// differentially compared against / bisected for codegen bugs.
	addPuregoBuildTagEscape(res.Files)
	return res, nil
}

// addPuregoBuildTagEscape rewrites the leading //go:build constraint of every
// generated file so that:
//   - the pure-Go fallback ("!amd64 && !arm64") additionally activates under
//     the `purego` tag: "(!amd64 && !arm64) || purego"
//   - every asm-side constraint (e.g. "amd64", "arm64", "amd64 || arm64")
//     additionally deactivates under `purego`: "(<expr>) && !purego"
//
// With `purego` unset (the default) these are semantically identical to the
// originals; with `-tags purego` the pure path replaces the asm path.
func addPuregoBuildTagEscape(files map[string][]byte) {
	for name, content := range files {
		files[name] = rewriteLeadingBuildConstraint(content)
	}
}

func rewriteLeadingBuildConstraint(src []byte) []byte {
	lines := bytes.Split(src, []byte("\n"))
	for i, ln := range lines {
		t := strings.TrimSpace(string(ln))
		if t == "" || strings.HasPrefix(t, "//") {
			if !strings.HasPrefix(t, "//go:build ") {
				continue // blank or non-build comment: keep scanning the header
			}
		} else {
			break // reached a non-comment line; constraints must precede it
		}
		expr := strings.TrimSpace(strings.TrimPrefix(t, "//go:build "))
		if strings.Contains(expr, "purego") {
			return src // already escaped
		}
		var ne string
		if expr == "!amd64 && !arm64" {
			ne = "(!amd64 && !arm64) || purego"
		} else {
			ne = "(" + expr + ") && !purego"
		}
		lines[i] = []byte("//go:build " + ne)
		return bytes.Join(lines, []byte("\n"))
	}
	return src
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
