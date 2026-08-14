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
	// must consume it via a register copy from X14, not a MOVQ/PINSRQ
	// rebuild from a GPR pair.
	if !regexp.MustCompile(`MOVOU X14, X\d`).MatchString(loopBody) {
		t.Errorf("loop body never reads the carried register X14:\n%s", loopBody)
	}
	// The tail writes the running value back to X14.
	if !strings.Contains(loopBody, "MOVOU X0, X14") && !regexp.MustCompile(`MOVOU X\d+, X14`).MatchString(loopBody) {
		t.Errorf("loop body never writes back the carried register X14:\n%s", loopBody)
	}
	// The prologue (before the loop label) seeds X14 from the argument
	// registers exactly once; the body must not rebuild it there.
	prologue := body[:loopStart]
	if !regexp.MustCompile(`, X14\n`).MatchString(prologue) {
		t.Errorf("carried register not seeded from arguments before the loop:\n%s", prologue)
	}
}
