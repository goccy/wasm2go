package asmgen

import "testing"

// TestPlan9AsmPathSafe pins the shared safety predicate that decides
// whether an import path can be embedded verbatim into a plan 9 asm
// symbol operand (mapping "/" → "∕" and "." → "·") or whether the
// generators must fall back to per-chunk Go-body wrappers because
// some byte of the path has no plan 9 identifier substitute.
func TestPlan9AsmPathSafe(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Single-name stdlib-style paths: safe.
		{"runtime", true},
		{"syscall", true},
		// Nested paths with letters / digits / underscores: safe.
		{"internal/runtime/atomic", true},
		{"a/b/c", true},
		{"foo_bar/baz", true},
		{"_x/y", true},
		{"gentest/pkg", true},
		// Domain-style paths: dots are remapped to U+00B7, still safe.
		{"github.com/foo/bar", true},
		{"github.com/goccy/wasm2go/internal", true},
		{"x.y.z/pkg", true},
		{"example.org/x_y/v2", true},
		// Digits are identifier runes only AFTER the first rune: a
		// digit-leading host would put a digit at position 0 of the
		// spelled operand, which the asm lexer scans as a number, not
		// an identifier. Real Go module hosts like this exist.
		{"4d63.com/mymod/pkg", false},
		{"0xacab.org/x", false},
		// ...while a digit anywhere later in the path is fine.
		{"h4d63.com/mymod/pkg", true},
		{"example.org/0user/pkg", true},
		// Hyphen has no identifier-rune substitute — unsafe. This is
		// what makes any module path containing a "-" fall back to
		// the per-chunk Go-body wrappers.
		{"github.com/example/foo-bar", false},
		{"github.com/goccy/some-hyphen/pkg", false},
		{"a-b", false},
		// Other punctuation that can legally appear in module paths
		// but breaks plan 9 asm identifier scanning.
		{"a+b", false},
		{"host.tld/a+b", false},
		{"a~b", false},
		{"foo bar", false},
		{"host.tld/sp ace", false},
		// Empty path: treated as unsafe so the caller skips the
		// optimization rather than emitting "·" alone.
		{"", false},
	}
	for _, c := range cases {
		if got := Plan9AsmPathSafe(c.path); got != c.want {
			t.Errorf("Plan9AsmPathSafe(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
