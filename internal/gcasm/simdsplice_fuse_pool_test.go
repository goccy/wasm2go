package gcasm

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// fusePoolClobberTree keeps a loaded vector (n0) live across a canned
// pair-table op (i8x16_shuffle) — the rotate-window shape (RoPE) that
// exposed the pool/scratch overlap: canned op bodies scratch X0–X7,
// so a value parked there was silently corrupted and every consumer
// after the shuffle computed garbage.
func fusePoolClobberTree() *simdfuse.Tree {
	return &simdfuse.Tree{
		Name:       "simd_p_fx2",
		NumScalars: 2,
		NumPairs:   1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 0},
				{Kind: simdfuse.ArgConst, Const: 0},
			}},
			{Op: "v128_load", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 1},
				{Kind: simdfuse.ArgConst, Const: 0},
			}},
			{Op: "v128_load", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 1},
				{Kind: simdfuse.ArgConst, Const: 16},
			}},
			{Op: "i8x16_shuffle", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 1},
				{Kind: simdfuse.ArgNode, Index: 2},
				{Kind: simdfuse.ArgPairIn, Index: 0},
			}},
			{Op: "f32x4_mul", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: 0},
				{Kind: simdfuse.ArgNode, Index: 3},
			}},
		},
		Roots: []int{4},
	}
}

// A value parked in X4–X7 that must survive a canned pair-table op
// (whose pasted body uses X0–X7 as inputs and scratch) is relocated
// to X8+ before the paste, and every later consumer reads the new
// home. Without this, the shuffle's scratch writes corrupted the
// parked load and every consumer after it computed garbage.
func TestX64FusedCannedOpRelocatesLiveValues(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, fusePoolClobberTree(), &ConstPool{}, fuseTestOffs, false, 0)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	// n0 parks in X4 (first pool register); the shuffle must move it
	// to X8+ before its canned lines run.
	if !regexp.MustCompile(`VMOVDQU X4, X(8|9|1[0-4])\b`).MatchString(body) {
		t.Fatalf("live value not relocated out of canned scratch:\n%s", body)
	}
	// The mul consumes the relocated home, never stale X4.
	if strings.Contains(body, "VMOVDQU X4, X0") {
		t.Fatalf("consumer read the clobbered X4 park:\n%s", body)
	}
}

// A tree over the shrunken pool budget must surface errFusedCapacity
// (the transform then falls the whole function back to pure Go) —
// never a silent partial splice.
func TestX64FusedPoolCapacity(t *testing.T) {
	// Twelve loads all live until a final chain of muls: more parked
	// values than the X4..X14 pool can hold.
	tree := &simdfuse.Tree{
		Name:       "simd_p_fx3",
		NumScalars: 1,
		NeedsMem:   true,
	}
	const n = 12
	for i := 0; i < n; i++ {
		tree.Nodes = append(tree.Nodes, simdfuse.Node{Op: "v128_load", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgScalar, Index: 0},
			{Kind: simdfuse.ArgConst, Const: int32(16 * i)},
		}})
	}
	prev := 0
	for i := 1; i < n; i++ {
		tree.Nodes = append(tree.Nodes, simdfuse.Node{Op: "f32x4_mul", Args: []simdfuse.Arg{
			{Kind: simdfuse.ArgNode, Index: prev},
			{Kind: simdfuse.ArgNode, Index: i},
		}})
		prev = len(tree.Nodes) - 1
	}
	tree.Roots = []int{prev}
	var b strings.Builder
	spliced, _, err := x64SpliceFused(&b, tree, &ConstPool{}, fuseTestOffs, false, 0)
	if spliced {
		t.Fatal("over-budget tree spliced")
	}
	if err == nil || !errors.Is(err, errFusedCapacity) {
		t.Fatalf("want errFusedCapacity, got %v", err)
	}
}

// Registrations from a transform attempt that later fell back must
// leave the jump-table spec set: their stubs are absent from the
// emitted asm, and a stale spec sends the generated init's signature
// scan past the end of the text segment.
func TestJTTableDrop(t *testing.T) {
	jt := &JTTable{}
	jt.fn("Fn1").Sites = append(jt.fn("Fn1").Sites, JTSite{TabVar: "Fn1_jt0"})
	jt.fn("Fn2").Sites = append(jt.fn("Fn2").Sites, JTSite{TabVar: "Fn2_jt0"})
	jt.Drop("Fn1")
	if len(jt.Fns) != 1 || jt.Fns[0].Sym != "Fn2" {
		t.Fatalf("Drop(Fn1) left %+v", jt.Fns)
	}
	jt.Drop("Fn2")
	if got := jt.EmitGo("amd64"); got != "" {
		t.Fatalf("empty table emitted Go:\n%s", got)
	}
}
