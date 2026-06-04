package codegen

import (
	"github.com/goccy/wasm2go/internal/emit"
	"github.com/goccy/wasm2go/internal/wasm"
)

// *translator implements emit.Driver. The interface defines the
// backend-neutral surface (identifier-resolution rules, helper /
// import registration, module access) that an SSA-driven emitter
// needs from its host. The methods here are thin exported wrappers
// over the package-private translator helpers so the same naming
// rules are used by every emitter (the Go-source emitter today, the
// plan9 asm emitter later) without each one having to reinvent
// multi-package qualification.
//
// AST-returning methods (helperRef, funcRef, ...) stay outside the
// interface because they would couple it to go/ast and prevent an
// asm host from satisfying it.
var _ emit.Driver = (*translator)(nil)

// Module returns the parsed wasm module being translated.
func (t *translator) Module() *wasm.Module { return t.mod }

// MultiPackage reports whether the translator is producing the
// multi-package + linkname-split layout.
func (t *translator) MultiPackage() bool { return t.multiPackage }

// FieldName is the exported alias for fieldName, satisfying emit.Driver.
func (t *translator) FieldName(s string) string { return t.fieldName(s) }

// FuncName is the exported alias for funcName, satisfying emit.Driver.
func (t *translator) FuncName(funcIdx uint32) string { return t.funcName(funcIdx) }

// FuncRefName returns the bare identifier used to call funcIdx from
// the current emit context. In multi-package mode this may register
// a //go:linkname forward as a side effect so the returned bare name
// is safe to use across chunk packages — the chunk-file assembler
// will then attach the //go:linkname directive. funcRef relies on
// the same registration and just wraps the returned name in an AST
// identifier.
func (t *translator) FuncRefName(funcIdx uint32) string {
	if t.multiPackage && t.plan != nil {
		if targetChunk, ok := t.plan.FuncToChunk[funcIdx]; ok && targetChunk != t.currentChunk {
			t.registerLinknameForward(t.currentChunk, funcIdx, targetChunk)
		}
	}
	return t.funcName(funcIdx)
}

// HelperName returns the qualified identifier (possibly `base.Up`)
// for a runtime helper as it should appear at the call site. Mirrors
// helperRef's qualification rule but returns text so an asm emitter
// can spell the same call as a plan9 symbol reference.
func (t *translator) HelperName(name string) string {
	if t.multiPackage {
		up := capitalize(name)
		if t.currentChunk == -2 {
			return up
		}
		return "base." + up
	}
	return name
}

// ImportMethodName is the exported alias for importMethodName,
// satisfying emit.Driver.
func (t *translator) ImportMethodName(imp wasm.Import) string {
	return t.importMethodName(imp)
}

// UseHelper is the exported alias for useHelper, satisfying emit.Driver.
func (t *translator) UseHelper(name string) { t.useHelper(name) }

// UsePackage is the exported alias for use, satisfying emit.Driver.
// (Renamed from `use` so the host-facing name makes its role
// explicit: it registers an external dependency, not a generic
// utility.)
func (t *translator) UsePackage(pkg string) { t.use(pkg) }
