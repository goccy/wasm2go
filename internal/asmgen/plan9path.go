package asmgen

// Plan9AsmPathSafe reports whether an import path can be embedded in
// a plan 9 asm symbol operand (via the U+00B7 / U+2215 spelling that
// goAsmSymbol applies — see its doc comment for the lexer mechanics).
//
// The asm lexer (src/cmd/asm/internal/lex/tokenizer.go: isIdentRune)
// accepts letters, "_", U+00B7 and U+2215 as identifier runes, plus
// digits AFTER the first rune, and nothing else. Two consequences:
//
//   - "." and "/" are the only ASCII punctuation an operand can
//     carry (through the Unicode substitution); anything else Go
//     module paths permit ("-", "+", "~", " ", ...) has no plan 9
//     counterpart and is unrepresentable — there is no escape
//     syntax.
//
//   - A spelled path lexes as ONE identifier starting at the path's
//     first byte, so a digit-leading host ("4d63.com/...",
//     "0xacab.org/...") is unrepresentable too: position 0 of the
//     identifier would be a digit and the token lexes as a number.
//
// The empty path is rejected so callers treat it as unsafe.
//
// This single function is the contract both halves of a generated
// bundle consult: internal/codegen keys the decl-only vs
// wrapper-pair linkname alias shape off it, and internal/gcasm keys
// the direct-CALL vs gcasmFwd forwarding shape plus the
// gcasmABI0Keep anchor off it. Keeping one copy is what guarantees
// the two decisions can never disagree.
func Plan9AsmPathSafe(path string) bool {
	if path == "" {
		return false
	}
	if c := path[0]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_') {
		return false
	}
	for i := 1; i < len(path); i++ {
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
