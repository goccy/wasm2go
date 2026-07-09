package codegen

import (
	"fmt"

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

// FuncRefName returns the qualified Go-syntax identifier the asm
// emitter should hand to goAsmSymbol when rendering a CALL. For an
// own-chunk callee or single-package mode the result is the bare
// name (e.g. "Fn42") so the CALL stays as a local-package
// ·Fn42(SB). For a cross-chunk callee in multi-package mode the
// result is the FULL Go-side qualified name (e.g.
// "github.com/foo/bar/pX.Fn42") so goAsmSymbol can render a direct
// cross-package CALL — plan 9 asm's scanner accepts U+2215 in
// place of "/" as an identifier rune (see
// src/cmd/asm/internal/lex/tokenizer.go: isIdentRune), so we don't
// need a per-chunk Go-body trampoline to bounce the asm caller
// through a local-package symbol. The Go-body trampoline pair is
// still emitted for the pure-Go fallback bodies in pN_pure.go via
// funcRef (the AST-side ref), and the Go linker DCEs it on the
// amd64/arm64 build where the .s files supply the asm bodies.
func (t *translator) FuncRefName(funcIdx uint32) string {
	if t.multiPackage && t.plan != nil {
		if targetChunk, ok := t.plan.FuncToChunk[funcIdx]; ok && targetChunk != t.currentChunk {
			return fmt.Sprintf("%s/p%d.%s", t.opts.OutputImportPath, targetChunk, t.funcName(funcIdx))
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
		if t.currentChunk == chunkBase {
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
