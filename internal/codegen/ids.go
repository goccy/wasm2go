package codegen

import (
	"fmt"
	"strings"
	"unicode"
)

// goKeywords lists Go reserved words that must not be used as identifiers.
var goKeywords = map[string]bool{
	"break": true, "case": true, "chan": true, "const": true, "continue": true,
	"default": true, "defer": true, "else": true, "fallthrough": true, "for": true,
	"func": true, "go": true, "goto": true, "if": true, "import": true,
	"interface": true, "map": true, "package": true, "range": true, "return": true,
	"select": true, "struct": true, "switch": true, "type": true, "var": true,
	// also a few predeclared names we never want to shadow.
	"any": true, "true": true, "false": true, "nil": true, "iota": true,
}

// MangleID returns a valid Go identifier derived from the given wasm name.
// Empty input becomes "_". A leading digit is prefixed with "_". Any rune
// outside [A-Za-z0-9_] is encoded as "_x{hex}". Go keywords get a trailing
// underscore.
func MangleID(name string) string {
	if name == "" {
		return "_"
	}
	var b strings.Builder
	b.Grow(len(name))
	first := true
	for _, r := range name {
		switch {
		case r == '_':
			b.WriteRune(r)
		case unicode.IsLetter(r):
			b.WriteRune(r)
		case unicode.IsDigit(r):
			if first {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, "_x%x", r)
		}
		first = false
	}
	out := b.String()
	if goKeywords[out] {
		out += "_"
	}
	return out
}

// MangleModuleType returns the Go type name used for the interface that
// represents an imported module (e.g. "env" -> "envImports").
func MangleModuleType(name string) string {
	return MangleID(name) + "Imports"
}

// MangleModuleField returns the Go struct-field name for an imported module
// (e.g. "wasi_snapshot_preview1" -> "wasi_snapshot_preview1").
func MangleModuleField(name string) string {
	return MangleID(name)
}

// ExportMethodName returns the Go method name for a wasm export. The
// algorithm preserves underscores between numeric segments so names like
// `w_56_10` and `w_561_0` (which collide if underscores are stripped) stay
// distinct as `W_56_10` and `W_561_0`. Letter-bordered underscores are
// dropped and CamelCased — `wasm_alloc` → `WasmAlloc`. Always starts with
// an uppercase letter so the method is exported.
func ExportMethodName(name string) string {
	if name == "" {
		return "Export_"
	}
	parts := strings.Split(name, "_")
	var b strings.Builder
	for i, p := range parts {
		if p == "" {
			continue
		}
		// Keep an underscore separator if either side of the boundary is
		// purely numeric — preserves identity in `_<digit>_` chains. The
		// first part never gets a leading underscore.
		if i > 0 && b.Len() > 0 && (allDigits(p) || allDigits(parts[i-1])) {
			b.WriteByte('_')
			b.WriteString(p)
			continue
		}
		runes := []rune(p)
		runes[0] = unicode.ToUpper(runes[0])
		b.WriteString(string(runes))
	}
	out := MangleID(b.String())
	if out == "" {
		return "Export_"
	}
	r0 := []rune(out)[0]
	if !unicode.IsUpper(r0) {
		// Numeric or other non-letter start: prefix with `X` so the name is
		// a valid exported method.
		out = "X" + out
	}
	return out
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
