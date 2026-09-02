package gcasm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

func TestX64CrossDotRewrite(t *testing.T) {
	tree := crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	rt, rewrote := x64Dot8Rewrite(tree, false)
	if !rewrote {
		t.Fatal("cross-chain shape not rewritten")
	}
	ops := countOps(rt.Nodes)
	if ops[x64OpRawDot] != 1 || ops[x64OpRawDotAcc] != 1 {
		t.Fatalf("raw dot chain not built: %v", ops)
	}
	if ops["i8x16_shuffle"] != 0 || ops["i32x4_add"] != 0 ||
		ops["i32x4_dot_i16x8_s"] != 0 || ops[x64OpBlockDot] != 0 {
		t.Fatalf("combine not fully absorbed: %v", ops)
	}
	// The final accumulation must sit on the combine's slot (16), so
	// consumers and the root are untouched.
	if rt.Nodes[16].Op != x64OpRawDotAcc {
		t.Fatalf("final accumulation not at the combine slot: %s", rt.Nodes[16].Op)
	}
	head := rt.Nodes[16].Args[0]
	if head.Kind != simdfuse.ArgNode || rt.Nodes[head.Index].Op != x64OpRawDot {
		t.Fatalf("chain head malformed: %+v", rt.Nodes[16].Args)
	}
	hArgs := rt.Nodes[head.Index].Args
	if hArgs[0] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 0}) ||
		hArgs[1] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 1}) {
		t.Fatalf("head sources wrong: %+v", hArgs)
	}
	tArgs := rt.Nodes[16].Args
	if tArgs[1] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2}) ||
		tArgs[2] != (simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 3}) {
		t.Fatalf("tail sources wrong: %+v", tArgs)
	}
}

func TestX64CrossDotRewritePortableSuppresses(t *testing.T) {
	tree := crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	rt, rewrote := x64Dot8Rewrite(tree, true)
	if rewrote {
		t.Fatal("portable body must keep the literal lowering")
	}
	ops := countOps(rt.Nodes)
	if ops[x64OpRawDot] != 0 || ops[x64OpRawDotAcc] != 0 {
		t.Fatalf("portable body rewrote: %v", ops)
	}
}

// A non-matching pattern (an arbitrary shuffle pair) stays literal.
func TestX64CrossDotRewriteRejectsForeignShuffles(t *testing.T) {
	tree := crossChainTree([2]uint64{0x0102030405060708, 0x090a0b0c0d0e0f00}, a64OddSel,
		simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	rt, _ := x64Dot8Rewrite(tree, false)
	ops := countOps(rt.Nodes)
	if ops[x64OpRawDot] != 0 || ops[x64OpRawDotAcc] != 0 {
		t.Fatalf("foreign shuffle pattern rewrote: %v", ops)
	}
}

func TestX64RawDotEmitsCollapsedMadd(t *testing.T) {
	tree := crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2})
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, tree, &ConstPool{}, fuseTestOffs, false, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	for _, want := range []string{
		"VPMOVSXBW", "VPMADDWD Y3, Y2, Y2", "VPHADDD Y2, Y2, Y2",
		"VEXTRACTI128 $1, Y2, X3", "VPUNPCKLQDQ X3, X2,", "VPADDD",
		"// avx2 dot", "VZEROUPPER",
	} {
		if !strings.Contains(asm, want) {
			t.Errorf("emitted asm missing %q:\n%s", want, asm)
		}
	}
	// The absorbed shuffles and literal dots must be gone.
	for _, gone := range []string{"PSHUFB", "PMADDWL"} {
		if strings.Contains(asm, gone) {
			t.Errorf("emitted asm still contains %q:\n%s", gone, asm)
		}
	}
}

// f16Tree: one f16x4_cvt over a pair input.
func f16Tree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:     "simd_p_fxf16",
		NumPairs: 1,
		Nodes: []simdfuse.Node{
			{Op: "f16x4_cvt", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 0}}},
		},
		Roots: []int{0},
	}
}

func TestX64F16CvtFeatureBodyUsesF16C(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, f16Tree(), &ConstPool{}, fuseTestOffs, false, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	for _, want := range []string{"VPAND", "VPACKUSDW X1, X1, X1", "VCVTPH2PS X1,", "// avx2 dot"} {
		if !strings.Contains(asm, want) {
			t.Errorf("feature body missing %q:\n%s", want, asm)
		}
	}
	if strings.Contains(asm, "PCMPGTL") || strings.Contains(asm, "MULPS") {
		t.Errorf("feature body still carries the SSE2 bit trick:\n%s", asm)
	}
}

func TestX64F16CvtPortableKeepsBitTrick(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, f16Tree(), &ConstPool{}, fuseTestOffs, true, 0)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !spliced {
		t.Fatal("not spliced")
	}
	asm := b.String()
	if strings.Contains(asm, "VCVTPH2PS") {
		t.Errorf("portable body used F16C:\n%s", asm)
	}
	if !strings.Contains(asm, "PCMPGTL") {
		t.Errorf("portable body missing the SSE2 bit trick:\n%s", asm)
	}
}

// TestX64CrossDotBodiesAssemble: the raw-dot and F16C sequences pass
// the real assembler (linux/amd64), pool constants included.
func TestX64CrossDotBodiesAssemble(t *testing.T) {
	pool := &ConstPool{}
	var body strings.Builder
	body.WriteString("TEXT ·fusedProbe(SB), NOSPLIT, $0-0\n")
	for i, tree := range []*simdfuse.Tree{
		crossChainTree(a64EvenSel, a64OddSel, simdfuse.Arg{Kind: simdfuse.ArgPairIn, Index: 2}),
		f16Tree(),
	} {
		var b strings.Builder
		spliced, _, err := x64SpliceFused(&b, tree, pool, fuseTestOffs, false, 0)
		if err != nil {
			t.Fatalf("splice %d: %v", i, err)
		}
		if !spliced {
			t.Fatalf("splice %d: not spliced", i)
		}
		body.WriteString(b.String())
	}
	body.WriteString("\tRET\n")
	asm := "#include \"textflag.h\"\n\n" + body.String() + "\n" + pool.Emit()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "k_amd64.s"), []byte(asm), 0o644); err != nil {
		t.Fatal(err)
	}
	goSrc := "package main\n\nfunc fusedProbe()\nfunc main() { _ = fusedProbe }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(goSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fcheck\n\ngo 1.25.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOAMD64=v2")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fused bodies do not assemble: %v\n%s", err, out)
	}
}
