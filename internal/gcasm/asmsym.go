package gcasm

import "strings"

// plan9AsmPathSafe reports whether an import path can be embedded in a
// plan 9 asm symbol operand. The asm lexer accepts letters, digits,
// "_", U+00B7 and U+2215 as identifier runes and maps the latter two
// back to "." and "/" (src/cmd/asm/internal/lex), so "." and "/" are
// the only ASCII punctuation an operand can carry — anything else
// ("-", "+", "~", ...) is unrepresentable and forces the Go-wrapper
// forwarding path. This mirrors codegen.isPlan9AsmSafe; the two
// packages cannot share it without an import cycle.
func plan9AsmPathSafe(path string) bool {
	if path == "" {
		return false
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '/':
		default:
			return false
		}
	}
	return true
}

// asmSpellPath renders an import path as a plan 9 asm identifier
// prefix: "." becomes U+00B7 ("·") and "/" becomes U+2215 ("∕"),
// which the asm lexer folds back to the ASCII forms, so the linker
// sees the canonical dotted path. Only meaningful for paths
// plan9AsmPathSafe accepts.
func asmSpellPath(path string) string {
	path = strings.ReplaceAll(path, ".", "·")
	return strings.ReplaceAll(path, "/", "∕")
}
