package gcasm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a64JtInsns builds the canonical arm64 dispatch shape gc emits —
// bounds check, table load, indexed load, indirect jump — preceded by
// the given flag-setter, plus two targets at offsets 100/200.
func a64JtInsns(setter string) []Insn {
	return []Insn{
		{Off: 0, Text: setter},
		{Off: 4, Text: "BHS\t400"},
		{Off: 8, Text: "MOVD\t$lib.FDispatch.jump0(SB), R16"},
		{Off: 12, Text: "MOVD\t(R16)(R1<<3), R17"},
		{Off: 16, Text: "JMP\t(R17)"},
		{Off: 100, Text: "BLT\t300"}, // target consuming the setter's flags
		{Off: 104, Text: "RET"},
		{Off: 200, Text: "MOVD\t$7, R0"},
		{Off: 204, Text: "RET"},
	}
}

func a64JtDatas() map[string]*DataSym {
	return map[string]*DataSym{
		"lib.FDispatch.jump0": {
			Name: "lib.FDispatch.jump0",
			Size: 16,
			Relocs: []DataReloc{
				{Off: 0, Sym: "lib.FDispatch", Addend: 100},
				{Off: 8, Sym: "lib.FDispatch", Addend: 200},
			},
		},
	}
}

// TestA64JumpTableFlagReplayDetect pins the arm64 port of the
// jump-table flag-replay logic (the amd64 fix shipped in
// findJumpTables; unported it produced the arm64 go-python SIGSEGV —
// a dispatch target consumed the pre-dispatch bounds-check flags,
// the compare tree's leftover NZCV leaked in, and a downstream branch
// went the wrong way, corrupting linear memory).
func TestA64JumpTableFlagReplayDetect(t *testing.T) {
	t.Run("clean setter replayed at leaves", func(t *testing.T) {
		sites, err := a64FindJumpTables("lib.FDispatch", a64JtInsns("CMPW\t$40, R1"), a64JtDatas())
		if err != nil {
			t.Fatal(err)
		}
		if len(sites) != 1 {
			t.Fatalf("got %d sites, want 1", len(sites))
		}
		var site *jtSite
		for _, s := range sites {
			site = s
		}
		if site.replay != "CMPW\t$40, R1" {
			t.Fatalf("site.replay = %q, want the pre-dispatch CMPW", site.replay)
		}
		var b strings.Builder
		a64EmitJumpTree(&b, site, 8)
		tree := b.String()
		// Every leaf must replay the compare immediately before its JMP.
		for _, leaf := range []string{"JMP pc100", "JMP pc200"} {
			i := strings.Index(tree, leaf)
			if i < 0 {
				t.Fatalf("leaf %q missing in tree:\n%s", leaf, tree)
			}
			pre := tree[:i]
			j := strings.LastIndex(pre, "CMPW\t$40, R1")
			if j < 0 || strings.Contains(pre[j:], "BHS jt") {
				t.Errorf("leaf %q not immediately preceded by the replay compare:\n%s", leaf, tree)
			}
		}
	})

	t.Run("no setter, flag-consuming target falls back", func(t *testing.T) {
		// Replace the compare with a flag-neutral instruction: the
		// backward scan finds no clean setter, and target 100 (BLT)
		// consumes flags → errUnsupportedJumpTable → pure fallback.
		_, err := a64FindJumpTables("lib.FDispatch", a64JtInsns("MOVD\t$40, R3"), a64JtDatas())
		if !errors.Is(err, errUnsupportedJumpTable) {
			t.Fatalf("err = %v, want errUnsupportedJumpTable", err)
		}
	})

	t.Run("setter using table registers is not replayable", func(t *testing.T) {
		// A compare reading R16/R17 cannot be replayed at the leaves —
		// the dispatch clobbers both. With target 100 consuming flags
		// the site must fall back rather than replay a clobbered
		// operand.
		_, err := a64FindJumpTables("lib.FDispatch", a64JtInsns("CMPW\t$40, R17"), a64JtDatas())
		if !errors.Is(err, errUnsupportedJumpTable) {
			t.Fatalf("err = %v, want errUnsupportedJumpTable (replay operand clobbered)", err)
		}
	})

	t.Run("no setter, flag-neutral targets stay transformed", func(t *testing.T) {
		insns := a64JtInsns("MOVD\t$40, R3")
		insns[5].Text = "MOVD\t$3, R0" // target 100 no longer reads flags
		sites, err := a64FindJumpTables("lib.FDispatch", insns, a64JtDatas())
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range sites {
			if s.replay != "" {
				t.Errorf("site.replay = %q, want empty (no setter found)", s.replay)
			}
		}
	})
}

// TestA64JumpTableFlagReplayRun is the arm64 twin of
// TestJumpTableFlagReplayRun: capture the flag-consuming dispatch
// fixture for arm64, transform it, and check every selector against
// the pure reference (executed natively when the host can run arm64;
// assemble-verified otherwise — see runArm64Gate).
func TestA64JumpTableFlagReplayRun(t *testing.T) {
	dir := t.TempDir()
	src := "package lib\n\n//go:noinline\n" + flagDispatchSrc("FDispatch")
	for name, content := range map[string]string{
		"go.mod":     "module fjta64\n\ngo 1.25.0\n",
		"lib/lib.go": src,
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fns, datas, err := captureArch(dir, "fjta64/lib", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	var disp *Fn
	for _, f := range fns {
		if strings.HasSuffix(f.Name, ".FDispatch") {
			disp = f
		}
	}
	if disp == nil {
		t.Fatalf("FDispatch not captured; got %d fns", len(fns))
	}
	dm := map[string]*DataSym{}
	for _, d := range datas {
		dm[d.Name] = d
	}
	body, err := TransformARM64(disp, TransformOptions{
		SymName:   "fdispatchAsm",
		CalleeSig: func(string) ([]ArgKind, bool, ArgKind, string, bool) { return nil, false, 0, "", false },
		Params:    []ArgKind{ArgI32, ArgI32},
		HasResult: true,
		Result:    ArgI32,
		ArgNames:  []string{"sel", "v0"},
		Datas:     dm,
	})
	if err != nil {
		if strings.Contains(err.Error(), "jump") {
			t.Skipf("no jump table emitted for this fixture on this toolchain: %v", err)
		}
		t.Fatal(err)
	}
	if !strings.Contains(body, "jt") || strings.Contains(body, ".jump") {
		t.Skipf("gc did not emit a jump table for FDispatch on this toolchain")
	}

	run := t.TempDir()
	files := map[string]string{
		"go.mod": "module fjtrun\n\ngo 1.25.0\n",
		"decl.go": "//go:build arm64\n\npackage fjtrun\n\nfunc fdispatchAsm(sel int32, v0 int32) (r0 int32)\n\n//go:noinline\n" +
			flagDispatchSrc("fdispatchRef"),
		"body_arm64.s": "#include \"textflag.h\"\n#include \"funcdata.h\"\n\n" + body,
		"run_test.go": `package fjtrun

import "testing"

func TestFDispatch(t *testing.T) {
	for sel := int32(-5); sel <= 55; sel++ {
		for _, v0 := range []int32{0, 1, -7, 1 << 20} {
			if got, want := fdispatchAsm(sel, v0), fdispatchRef(sel, v0); got != want {
				t.Fatalf("fdispatch(%d,%d)=%d want %d", sel, v0, got, want)
			}
		}
	}
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(run, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runArm64Gate(t, run, ".", "TestFDispatch", body)
}
