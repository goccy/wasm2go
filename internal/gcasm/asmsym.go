package gcasm

import "strings"

// Whether an import path can be embedded in a plan 9 asm symbol
// operand at all is decided by asmgen.Plan9AsmPathSafe — the single
// shared predicate this package's direct-CALL / gcasmABI0Keep gates
// and codegen's linkname alias shape both consult, so the two halves
// of a bundle can never disagree.

// asmSpellPath renders an import path as a plan 9 asm identifier
// prefix: "." becomes U+00B7 ("·") and "/" becomes U+2215 ("∕"),
// which the asm lexer folds back to the ASCII forms, so the linker
// sees the canonical dotted path. Only meaningful for paths
// asmgen.Plan9AsmPathSafe accepts.
func asmSpellPath(path string) string {
	path = strings.ReplaceAll(path, ".", "·")
	return strings.ReplaceAll(path, "/", "∕")
}
