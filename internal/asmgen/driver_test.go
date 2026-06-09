package asmgen

import (
	"testing"

	"github.com/goccy/wasm2go/internal/wasm"
)

// fakeDriver is a deliberately minimal emit.Driver impl whose only
// purpose is to verify FuncOptionsFromDriver wires its outputs to
// the right Driver methods.
type fakeDriver struct {
	mod          *wasm.Module
	multipkg     bool
	funcRefCalls []uint32
	funcRefRet   string
}

func (d *fakeDriver) Module() *wasm.Module      { return d.mod }
func (d *fakeDriver) MultiPackage() bool        { return d.multipkg }
func (d *fakeDriver) FieldName(s string) string { return s }
func (d *fakeDriver) FuncName(idx uint32) string {
	return ""
}
func (d *fakeDriver) FuncRefName(idx uint32) string {
	d.funcRefCalls = append(d.funcRefCalls, idx)
	return d.funcRefRet
}
func (d *fakeDriver) HelperName(name string) string         { return name }
func (d *fakeDriver) ImportMethodName(_ wasm.Import) string { return "" }
func (d *fakeDriver) UseHelper(string)                      {}
func (d *fakeDriver) UsePackage(string)                     {}

// TestFuncOptionsFromDriver verifies that
//   - Module flows through Driver.Module()
//   - HelperPrefix is "base" when MultiPackage()==true, "" otherwise
//   - FuncSymbol delegates to FuncRefName
//
// The asm-symbol wrapping (text "base.Fn42" → asm "base·Fn42(SB)")
// is exercised by goAsmSymbol directly.
func TestFuncOptionsFromDriver(t *testing.T) {
	mod := &wasm.Module{}
	d := &fakeDriver{mod: mod, multipkg: true, funcRefRet: "base.Fn42"}
	opts := FuncOptionsFromDriver(d, "*base.Module")
	if opts.Module != mod {
		t.Errorf("Module not propagated")
	}
	if opts.ModulePkgRef != "*base.Module" {
		t.Errorf("ModulePkgRef = %q", opts.ModulePkgRef)
	}
	if opts.HelperPrefix != "base" {
		t.Errorf("HelperPrefix = %q want base", opts.HelperPrefix)
	}
	if got := opts.FuncSymbol(42); got != "base.Fn42" {
		t.Errorf("FuncSymbol(42) = %q want base.Fn42", got)
	}
	if len(d.funcRefCalls) != 1 || d.funcRefCalls[0] != 42 {
		t.Errorf("FuncRefName not delegated to: %v", d.funcRefCalls)
	}

	// Single-package mode should set HelperPrefix to "".
	d2 := &fakeDriver{mod: mod, multipkg: false}
	opts2 := FuncOptionsFromDriver(d2, "*Module")
	if opts2.HelperPrefix != "" {
		t.Errorf("single-pkg HelperPrefix = %q want empty", opts2.HelperPrefix)
	}
}

// TestGoAsmSymbol pins the qualified-name → asm-symbol translation.
// This is the boundary where text names from emit.Driver become
// plan9 asm SB references.
func TestGoAsmSymbol(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Fn42", "·Fn42(SB)"},
		{"base.Fn42", "base·Fn42(SB)"},
		{"callImport_3", "·callImport_3(SB)"},
		{"base.SubG", "base·SubG(SB)"},
		// Full import path: slashes become U+2215 (division slash)
		// and intra-component dots become U+00B7 (middle dot) so
		// plan 9 asm's scanner accepts them as identifier runes.
		// Last `.` in the qualified name is the package/symbol
		// boundary and renders as the canonical "·" separator.
		{"github.com/foo/bar.Fn42", "github·com∕foo∕bar·Fn42(SB)"},
		{"x/y.Z", "x∕y·Z(SB)"},
	}
	for _, c := range cases {
		if got := goAsmSymbol(c.in); got != c.want {
			t.Errorf("goAsmSymbol(%q) = %q want %q", c.in, got, c.want)
		}
	}
}
