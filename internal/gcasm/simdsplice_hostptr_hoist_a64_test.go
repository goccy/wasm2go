package gcasm

import (
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// hoistLoop builds a store-free do-while accumulate loop with two
// bump-carried pointers, two loads each (the carry threshold), and a
// carried accumulator.
func hoistLoop(exitGT bool) *simdfuse.Loop {
	sc := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: i} }
	cst := func(c int32) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	tree := &simdfuse.Tree{
		Name:       "simd_p_fxhoist",
		NumScalars: 2,
		NumPairs:   1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			{Op: "v128_load", Args: []simdfuse.Arg{sc(0), cst(0)}},
			{Op: "v128_load", Args: []simdfuse.Arg{sc(0), cst(16)}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(0), nd(1)}},
			{Op: "v128_load32_splat", Args: []simdfuse.Arg{sc(1), cst(0)}},
			{Op: "v128_load32_splat", Args: []simdfuse.Arg{sc(1), cst(4)}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(3), nd(4)}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(2), nd(5)}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 0}, nd(6)}},
		},
		Roots: []int{7},
	}
	l := &simdfuse.Loop{
		Tree:          tree,
		CarriedPairs:  [][2]int{{0, 7}},
		Bumps:         []simdfuse.LoopBump{{Scalar: 0, Delta: 32, DeltaScalar: -1}, {Scalar: 1, Delta: 8, DeltaScalar: -1}},
		CounterScalar: 2,
		Dec:           1,
		ExitScalars:   []int{0, 1, 2},
	}
	if exitGT {
		l.ExitGT = true
		l.ExitThresh = 1
	}
	return l
}

// prologueAndBody splits the emitted splice at its loop label.
func prologueAndBody(t *testing.T, body string) (string, string) {
	t.Helper()
	at := strings.Index(body, "gcasmfxl")
	if at < 0 {
		t.Fatalf("no loop label:\n%s", body)
	}
	return body[:at], body[at:]
}

func TestA64LoopCheckHoisting(t *testing.T) {
	for _, exitGT := range []bool{false, true} {
		var b strings.Builder
		spliced, wantsTrap, err := a64SpliceLoop(&b, hoistLoop(exitGT), &ConstPool{}, fuseTestOffs, "0", false)
		if err != nil || !spliced {
			t.Fatalf("exitGT=%v: spliced=%v err=%v", exitGT, spliced, err)
		}
		if !wantsTrap {
			t.Fatalf("exitGT=%v: hoisted checks need the trap stub", exitGT)
		}
		pro, body := prologueAndBody(t, b.String())
		// One whole-loop check per carried pointer, in the prologue.
		if c := strings.Count(pro, "CMP R27, R21"); c != 2 {
			t.Fatalf("exitGT=%v: want 2 hoisted checks, got %d:\n%s", exitGT, c, pro)
		}
		// The loop body carries no per-load checks.
		if strings.Contains(body, "CMP R27, R21") {
			t.Fatalf("exitGT=%v: per-load check left in body:\n%s", exitGT, body)
		}
		if exitGT {
			if !strings.Contains(pro, "CSEL GE, R27, ZR, R27") {
				t.Fatalf("floor trip count not clamped:\n%s", pro)
			}
		}
	}
}

func TestA64LoopCheckHoistingSkipsPreTest(t *testing.T) {
	l := hoistLoop(false)
	l.PreTest = true
	var b strings.Builder
	spliced, _, err := a64SpliceLoop(&b, l, &ConstPool{}, fuseTestOffs, "0", false)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	pro, body := prologueAndBody(t, b.String())
	// A pre-tested loop may run zero trips: checks stay per load.
	if strings.Contains(pro, "CMP R27, R21") {
		t.Fatalf("hoisted check on a pre-tested loop:\n%s", pro)
	}
	if !strings.Contains(body, "CMP R27, R21") {
		t.Fatalf("per-load checks missing from body:\n%s", body)
	}
}

func TestA64LoopCheckHoistingSkipsStores(t *testing.T) {
	l := hoistLoop(false)
	l.Tree.Nodes = append(l.Tree.Nodes, simdfuse.Node{Op: "v128_store", Args: []simdfuse.Arg{
		{Kind: simdfuse.ArgScalar, Index: 0}, {Kind: simdfuse.ArgConst, Const: 0},
		{Kind: simdfuse.ArgNode, Index: 7},
	}})
	l.Tree.NoResult = true
	l.Tree.Roots = nil
	l.CarriedPairs = nil
	var b strings.Builder
	spliced, _, err := a64SpliceLoop(&b, l, &ConstPool{}, fuseTestOffs, "0", false)
	if err != nil || !spliced {
		t.Skipf("store loop refused outright (acceptable): spliced=%v err=%v", spliced, err)
	}
	pro, _ := prologueAndBody(t, b.String())
	if strings.Contains(pro, "CMP R27, R21") {
		t.Fatalf("hoisted check on a store-carrying loop:\n%s", pro)
	}
}

// Register assignment must not depend on map iteration order: the
// carried pointers' scalars get freeRegs in ascending scalar order,
// every run.
func TestA64LoopHostPtrsAssignmentOrder(t *testing.T) {
	for i := 0; i < 64; i++ {
		ptrs := a64LoopHostPtrs(hoistLoop(false), []string{"R7", "R8"})
		if ptrs == nil {
			t.Fatal("no carried pointers")
		}
		if got := ptrs[0].reg; got != "R7" {
			t.Fatalf("scalar 0 got %s, want R7", got)
		}
		if got := ptrs[1].reg; got != "R8" {
			t.Fatalf("scalar 1 got %s, want R8", got)
		}
	}
}
