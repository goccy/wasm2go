package gcasm

import (
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// carryLoop is a minimal accumulate loop: acc = i32x4_add(acc,
// load(s0)) over a counted range. The carried pair (node 0, the
// f32x4/i32x4 accumulator input) seeds from the argument at entry and
// must thereafter read the running value from its reserved register.
func carryLoop() *simdfuse.Loop {
	tree := &simdfuse.Tree{
		Name:       "simd_p_fxl_carry",
		NumScalars: 1, // s0 = load address
		NumPairs:   1, // the carried accumulator
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			// node 0: the memory operand of the add.
			{Op: "v128_load", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgScalar, Index: 0},
				{Kind: simdfuse.ArgConst, Const: 0},
			}},
			// node 1: acc(pair 0) + load. Pair 0 is the carry.
			{Op: "i32x4_add", Args: []simdfuse.Arg{
				{Kind: simdfuse.ArgPairIn, Index: 0},
				{Kind: simdfuse.ArgNode, Index: 0},
			}},
		},
		Roots: []int{1},
	}
	return &simdfuse.Loop{
		Tree:          tree,
		CarriedPairs:  [][2]int{{0, 1}}, // pair 0 in, node 1 out
		CounterScalar: 0,
		Dec:           1,
		PreTest:       true,
	}
}

// The loop body must read the carried accumulator from its reserved
// register (written back at the tail), NOT rebuild it from the
// incoming argument registers — those only hold the first iteration's
// value, so reading them resets the accumulator every iteration.
func TestX64LoopCarryReadsReservedRegister(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceLoop(&b, carryLoop(), &ConstPool{}, fuseTestOffs, "0", false, 0)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()

	loopStart := strings.Index(body, "gcasmfxl0:")
	if loopStart < 0 {
		t.Fatalf("no loop label in body:\n%s", body)
	}
	loopBody := body[loopStart:]

	// The carried accumulator is reserved at X14 (poolTop). The add
	// must consume it straight from X14 — either the VEX form reading
	// it as an operand or a register copy — never a MOVQ/PINSRQ
	// rebuild from a GPR pair.
	if !regexp.MustCompile(`(MOVOU X14, X\d|X14, X\d+\n)`).MatchString(loopBody) {
		t.Errorf("loop body never reads the carried register X14:\n%s", loopBody)
	}
	// The tail writes the running value back to X14.
	if !strings.Contains(loopBody, "VMOVDQU X0, X14") && !regexp.MustCompile(`MOVOU X\d+, X14`).MatchString(loopBody) {
		t.Errorf("loop body never writes back the carried register X14:\n%s", loopBody)
	}
	// The prologue (before the loop label) seeds X14 from the argument
	// registers exactly once; the body must not rebuild it there.
	prologue := body[:loopStart]
	if !regexp.MustCompile(`, X14\n`).MatchString(prologue) {
		t.Errorf("carried register not seeded from arguments before the loop:\n%s", prologue)
	}
}

// shuffleConstLoop puts an i8x16_shuffle_const between two loads and a
// carried accumulator, with a splat that stays live across the
// shuffle — the shape whose emulation once scratched X4/X5 and
// clobbered pool-resident values.
func shuffleConstLoop() *simdfuse.Loop {
	sc := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: i} }
	cst := func(c int32) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c} }
	nd := func(i int) simdfuse.Arg { return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: i} }
	tree := &simdfuse.Tree{
		Name:       "simd_p_fxl_shufconst",
		NumScalars: 1,
		NumPairs:   1,
		NeedsMem:   true,
		Nodes: []simdfuse.Node{
			// node 0: a splat that must survive past the shuffle.
			{Op: "v128_load32_splat", Args: []simdfuse.Arg{sc(0), cst(0)}},
			{Op: "v128_load", Args: []simdfuse.Arg{sc(0), cst(16)}},
			{Op: "v128_load", Args: []simdfuse.Arg{sc(0), cst(32)}},
			// node 3: const-pattern shuffle of the two loads.
			{Op: "i8x16_shuffle_const", Args: []simdfuse.Arg{
				nd(1), nd(2),
				cst(0x03020100), cst(0x0b0a0908), cst(0x13121110), cst(0x1b1a1918),
			}},
			// node 4: the splat is consumed AFTER the shuffle ran.
			{Op: "i32x4_add", Args: []simdfuse.Arg{nd(3), nd(0)}},
			{Op: "i32x4_add", Args: []simdfuse.Arg{{Kind: simdfuse.ArgPairIn, Index: 0}, nd(4)}},
		},
		Roots: []int{5},
	}
	return &simdfuse.Loop{
		Tree:          tree,
		CarriedPairs:  [][2]int{{0, 5}},
		CounterScalar: 0,
		Dec:           1,
		PreTest:       true,
	}
}

// The const-pattern shuffle emulation must stay inside the splicer's
// scratch registers (X0-X3): pool values live in X4+ for the whole
// loop body and there is no relocation pass here. The old body
// staged the biased patterns in X4/X5 and corrupted whatever the
// allocator had parked there.
func TestX64LoopShuffleConstStaysInScratch(t *testing.T) {
	var b strings.Builder
	spliced, _, err := x64SpliceLoop(&b, shuffleConstLoop(), &ConstPool{}, fuseTestOffs, "0", false, 0)
	if err != nil || !spliced {
		t.Fatalf("spliced=%v err=%v", spliced, err)
	}
	body := b.String()
	shuf := regexp.MustCompile(`(?s)MOVOU ·gcb16_[0-9a-f]+\(SB\), X2.*?POR X1, X0`).FindString(body)
	if shuf == "" {
		t.Fatalf("no shuffle-const emulation in body:\n%s", body)
	}
	for _, m := range regexp.MustCompile(`X(\d+)`).FindAllStringSubmatch(shuf, -1) {
		if m[1] != "0" && m[1] != "1" && m[1] != "2" && m[1] != "3" {
			t.Fatalf("shuffle-const emulation touches X%s (outside the X0-X3 scratch set):\n%s", m[1], shuf)
		}
	}
}
