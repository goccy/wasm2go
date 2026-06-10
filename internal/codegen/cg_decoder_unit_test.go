package codegen

import "testing"

// TestGoEscapedBytes covers the Go-string-literal escaper used to inline
// data segments.
func TestGoEscapedBytes(t *testing.T) {
	got := goEscapedBytes([]byte("ab\n\t\"\\\x00\xff"))
	want := `"ab\n\t\"\\\x00\xff"`
	if got != want {
		t.Errorf("goEscapedBytes=%q want %q", got, want)
	}
	if goEscapedBytes(nil) != `""` {
		t.Errorf("goEscapedBytes(nil)=%q want \"\"", goEscapedBytes(nil))
	}
}
