package transpile

import "testing"

func TestRewriteLeadingBuildConstraint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"//go:build amd64\n\npackage p\n", "//go:build (amd64) && !purego\n\npackage p\n"},
		{"//go:build arm64\n\npackage p\n", "//go:build (arm64) && !purego\n\npackage p\n"},
		{"//go:build amd64 || arm64\n\npackage p\n", "//go:build (amd64 || arm64) && !purego\n\npackage p\n"},
		{"//go:build !amd64 && !arm64\n\npackage p\n", "//go:build (!amd64 && !arm64) || purego\n\npackage p\n"},
		// already escaped: unchanged
		{"//go:build (amd64) && !purego\n\npackage p\n", "//go:build (amd64) && !purego\n\npackage p\n"},
		// no constraint: unchanged
		{"package p\n", "package p\n"},
		// .s file with leading comment lines then constraint
		{"// header\n//go:build amd64\n\nTEXT x(SB)\n", "// header\n//go:build (amd64) && !purego\n\nTEXT x(SB)\n"},
	}
	for i, c := range cases {
		got := string(rewriteLeadingBuildConstraint([]byte(c.in)))
		if got != c.want {
			t.Errorf("case %d:\n got=%q\nwant=%q", i, got, c.want)
		}
	}
}

func TestAddPuregoBuildTagEscape(t *testing.T) {
	files := map[string][]byte{
		"amd64.s":   []byte("//go:build amd64\n\nTEXT ·F(SB)\n"),
		"p_pure.go": []byte("//go:build !amd64 && !arm64\n\npackage p\n"),
	}
	addPuregoBuildTagEscape(files)
	if got := string(files["amd64.s"]); got != "//go:build (amd64) && !purego\n\nTEXT ·F(SB)\n" {
		t.Errorf("amd64.s: %q", got)
	}
	if got := string(files["p_pure.go"]); got != "//go:build (!amd64 && !arm64) || purego\n\npackage p\n" {
		t.Errorf("p_pure.go: %q", got)
	}
}
