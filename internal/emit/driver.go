package emit

import "github.com/goccy/wasm2go/internal/wasm"

// Driver is the backend-neutral surface that an SSA-driven emitter
// needs from its host. It captures three categories of dependency:
//
//   - Module access (Module): the parsed wasm being translated.
//   - Identifier resolution (FieldName, FuncName, FuncRefName,
//     HelperName, ImportMethodName): name spelling rules that depend
//     on the host's packaging strategy (single-package vs
//     multi-package + linkname-split) but not on the output language.
//   - Side-effect registration (UseHelper, UsePackage): the emitter
//     announces which runtime helpers and which Go imports the
//     emitted body relies on so the host can stitch them into the
//     final file's header.
//
// Two host implementations are anticipated:
//
//   - The Go-source codegen translator implements Driver and adds
//     Go-AST-returning sister methods (helperRef, funcRef, ...) that
//     it consumes directly. Those AST methods stay outside Driver
//     because their return types would couple the interface to
//     go/ast and prevent an asm host from satisfying it.
//   - A future asm host will implement Driver and pair it with
//     asm-instruction-emitting sister methods to drive the plan9
//     emitter.
//
// New Driver methods are added when they describe genuinely
// host-agnostic state. Anything language-specific stays on the
// concrete host type.
type Driver interface {
	// Module returns the parsed wasm module being translated.
	Module() *wasm.Module
	// MultiPackage reports whether the host is producing the
	// multi-package + linkname-split layout. Identifier-resolution
	// methods consult this to decide between bare and chunk-qualified
	// names; downstream emitters consult it when they need to know
	// whether a cross-chunk hop is on the table.
	MultiPackage() bool

	// FieldName returns the *Module struct field name (multipkg-aware
	// capitalization). Used wherever the emitter spells out an access
	// like `m.<field>` so the field is reachable from outside the
	// owning package in multi-package mode.
	FieldName(s string) string
	// FuncName returns the generated function's bare identifier for a
	// wasm function index (capitalized in multipkg mode, lowercase
	// otherwise).
	FuncName(funcIdx uint32) string
	// FuncRefName returns the identifier to use when *calling* the
	// function from the current emit context. In multi-package mode
	// this may register a //go:linkname forward so a bare name is
	// safe even across chunks.
	FuncRefName(funcIdx uint32) string
	// HelperName returns the qualified identifier for a runtime
	// helper as it should appear at the call site. In multi-package
	// mode the base-package qualifier is added when the caller lives
	// outside the base package.
	HelperName(name string) string
	// ImportMethodName returns the Go method name for an imported
	// wasm function. Always capitalized so it is reachable from the
	// caller package's host-imports interface.
	ImportMethodName(imp wasm.Import) string

	// UseHelper records that the named runtime helper is referenced
	// by an emitted body so the host writes its definition into the
	// output file.
	UseHelper(name string)
	// UsePackage records that the given Go import path is referenced
	// so the host adds it to the file's import block.
	UsePackage(pkg string)
}
