package ssa

import (
	"fmt"
	"testing"
)

// buildSumLoopFunc constructs
//
//	func f(n i32) i32:
//	  entry:  c0 = 0; c1 = 1
//	  header: i = phi(c0, i2); acc = phi(c0, acc2); if i < n → body else exit
//	  body:   acc2 = acc + i; i2 = i + c1 → header
//	  exit:   ret acc
//
// whose loop is outline-eligible with liveIns [n] and liveOut acc.
func buildSumLoopFunc(t *testing.T) (*Func, *Block) {
	f := NewFunc("Fn9", FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}})
	entry := f.NewBlock(BlockPlain)
	f.SetEntry(entry)
	header := f.NewBlock(BlockIf)
	body := f.NewBlock(BlockPlain)
	exit := f.NewBlock(BlockRet)

	n := f.newValue(OpParam, TypeI32, nil, entry, 0, nil)
	c0 := f.newValue(OpConst32, TypeI32, nil, entry, 0, nil)
	c1 := f.newValue(OpConst32, TypeI32, nil, entry, 1, nil)
	entry.Values = append(entry.Values, n, c0, c1)

	i := f.newValue(OpPhi, TypeI32, []*Value{c0, nil}, header, 0, nil)
	acc := f.newValue(OpPhi, TypeI32, []*Value{c0, nil}, header, 0, nil)
	cond := f.newValue(OpLtS32, TypeI32, []*Value{i, n}, header, 0, nil)
	header.Values = append(header.Values, i, acc, cond)
	header.Control = cond

	acc2 := f.newValue(OpAdd32, TypeI32, []*Value{acc, i}, body, 0, nil)
	i2 := f.newValue(OpAdd32, TypeI32, []*Value{i, c1}, body, 0, nil)
	body.Values = append(body.Values, acc2, i2)
	i.Args[1] = i2
	acc.Args[1] = acc2

	rv := f.newValue(OpCopy, TypeI32, []*Value{acc}, exit, 0, nil)
	exit.Values = append(exit.Values, rv)

	AddEdge(entry, header) // pred 0: initial phi args
	AddEdge(header, body)  // then
	AddEdge(header, exit)  // else
	AddEdge(body, header)  // pred 1: latch phi args

	if err := Verify(f); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return f, header
}

func TestOutlineSumLoop(t *testing.T) {
	f, header := buildSumLoopFunc(t)
	headerID := header.ID // adoption renumbers the block afterwards
	outs, err := OutlineLoops(f, func(h BlockID) string {
		return fmt.Sprintf("Fn9l%d", h)
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 {
		t.Fatalf("extracted %d funcs, want 1", len(outs))
	}
	if outs[0].Packed {
		t.Error("small boundary marked packed")
	}
	g := outs[0].Fn
	if want := fmt.Sprintf("Fn9l%d", headerID); g.Name != want {
		t.Errorf("name %q, want %q", g.Name, want)
	}
	if len(g.Sig.Params) != 1 || g.Sig.Params[0] != TypeI32 {
		t.Errorf("params %v, want [i32] (constants must clone, not ride)", g.Sig.Params)
	}
	if len(g.Sig.Results) != 1 || g.Sig.Results[0] != TypeI32 {
		t.Errorf("results %v, want [i32]", g.Sig.Results)
	}
	// The parent must now be loop-free and carry one named direct call.
	var call *Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpCallDirect {
				if call != nil {
					t.Fatal("more than one call in parent")
				}
				call = v
			}
		}
	}
	if call == nil {
		t.Fatal("no call in parent")
	}
	if name, _ := call.Aux.(string); name != g.Name {
		t.Errorf("call Aux %v, want %q", call.Aux, g.Name)
	}
	if len(call.Args) != 1 || call.Args[0].Op != OpParam {
		t.Errorf("call args %v, want the n parameter", call.Args)
	}
	// The parent's return value must be the call result.
	for _, b := range f.Blocks {
		if b.Kind != BlockRet {
			continue
		}
		last := b.Values[len(b.Values)-1]
		if last.Args[0] != call {
			t.Errorf("parent returns %v, want the call result", last.Args[0])
		}
	}
	// No block of the parent may still branch into g's blocks.
	inG := map[*Block]bool{}
	for _, b := range g.Blocks {
		inG[b] = true
	}
	for _, b := range f.Blocks {
		for _, s := range b.Succs {
			if inG[s.Block] {
				t.Errorf("parent block L%d still targets extracted block", b.ID)
			}
		}
	}
	// The extracted function must contain the loop: a phi and a
	// back edge, plus a Ret block returning the accumulator.
	phis, rets := 0, 0
	for _, b := range g.Blocks {
		for _, v := range b.Values {
			if v.Op == OpPhi {
				phis++
			}
		}
		if b.Kind == BlockRet {
			rets++
		}
	}
	if phis != 2 || rets != 1 {
		t.Errorf("extracted: %d phis, %d ret blocks; want 2 and 1", phis, rets)
	}
}

func TestOutlineRejectsMultiLiveOut(t *testing.T) {
	f, _ := buildSumLoopFunc(t)
	// Make the exit use i as well: two live-outs → ineligible.
	var header *Block
	for _, b := range f.Blocks {
		if b.Kind == BlockIf {
			header = b
		}
	}
	iPhi := header.Values[0]
	for _, b := range f.Blocks {
		if b.Kind == BlockRet {
			v := f.newValue(OpAdd32, TypeI32, []*Value{b.Values[0].Args[0], iPhi}, b, 0, nil)
			b.Values = append(b.Values[:len(b.Values)-1], v,
				f.newValue(OpCopy, TypeI32, []*Value{v}, b, 0, nil))
		}
	}
	outs, err := OutlineLoops(f, func(h BlockID) string { return "x" }, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 0 {
		t.Fatalf("extracted %d funcs from a two-live-out loop, want 0", len(outs))
	}
}

// buildTwoExitLoopFunc: a sum loop with an early break —
//
//	header: i, acc phis; if i < n → chk else exitA
//	chk:    if acc > 100 → exitB else body
//	body:   acc += i; i++ → header
//	exitA:  ret acc      exitB: ret acc + 1000
func buildTwoExitLoopFunc(t *testing.T) *Func {
	f := NewFunc("Fn7", FuncSig{Params: []Type{TypeI32}, Results: []Type{TypeI32}})
	entry := f.NewBlock(BlockPlain)
	f.SetEntry(entry)
	header := f.NewBlock(BlockIf)
	chk := f.NewBlock(BlockIf)
	body := f.NewBlock(BlockPlain)
	exitA := f.NewBlock(BlockRet)
	exitB := f.NewBlock(BlockRet)

	n := f.newValue(OpParam, TypeI32, nil, entry, 0, nil)
	c0 := f.newValue(OpConst32, TypeI32, nil, entry, 0, nil)
	c1 := f.newValue(OpConst32, TypeI32, nil, entry, 1, nil)
	c100 := f.newValue(OpConst32, TypeI32, nil, entry, 100, nil)
	entry.Values = append(entry.Values, n, c0, c1, c100)

	i := f.newValue(OpPhi, TypeI32, []*Value{c0, nil}, header, 0, nil)
	acc := f.newValue(OpPhi, TypeI32, []*Value{c0, nil}, header, 0, nil)
	cond := f.newValue(OpLtS32, TypeI32, []*Value{i, n}, header, 0, nil)
	header.Values = append(header.Values, i, acc, cond)
	header.Control = cond

	over := f.newValue(OpLtS32, TypeI32, []*Value{c100, acc}, chk, 0, nil)
	chk.Values = append(chk.Values, over)
	chk.Control = over

	acc2 := f.newValue(OpAdd32, TypeI32, []*Value{acc, i}, body, 0, nil)
	i2 := f.newValue(OpAdd32, TypeI32, []*Value{i, c1}, body, 0, nil)
	body.Values = append(body.Values, acc2, i2)
	i.Args[1] = i2
	acc.Args[1] = acc2

	ra := f.newValue(OpCopy, TypeI32, []*Value{acc}, exitA, 0, nil)
	exitA.Values = append(exitA.Values, ra)
	ck := f.newValue(OpConst32, TypeI32, nil, exitB, 1000, nil)
	rbv := f.newValue(OpAdd32, TypeI32, []*Value{acc, ck}, exitB, 0, nil)
	rb := f.newValue(OpCopy, TypeI32, []*Value{rbv}, exitB, 0, nil)
	exitB.Values = append(exitB.Values, ck, rbv, rb)

	AddEdge(entry, header) // pred 0
	AddEdge(header, chk)   // then
	AddEdge(header, exitA) // else
	AddEdge(chk, exitB)    // then (early break)
	AddEdge(chk, body)     // else
	AddEdge(body, header)  // pred 1
	if err := Verify(f); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return f
}

func TestOutlineTwoExitLoop(t *testing.T) {
	f := buildTwoExitLoopFunc(t)
	outs, err := OutlineLoops(f, func(h BlockID) string { return fmt.Sprintf("Fn7l%d", h) }, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 {
		t.Fatalf("extracted %d funcs, want 1", len(outs))
	}
	g := outs[0].Fn
	if len(g.Sig.Results) != 1 || g.Sig.Results[0] != TypeI64 {
		t.Fatalf("results %v, want the encoded int64", g.Sig.Results)
	}
	rets := 0
	for _, b := range g.Blocks {
		if b.Kind == BlockRet {
			rets++
		}
	}
	if rets != 2 {
		t.Errorf("extracted has %d ret blocks, want 2", rets)
	}
	// The parent's call block must dispatch on the decoded index.
	var ifBlk *Block
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpCallDirect {
				ifBlk = b
			}
		}
	}
	if ifBlk == nil || ifBlk.Kind != BlockIf || len(ifBlk.Succs) != 2 {
		t.Fatalf("call block not a two-way dispatch: %+v", ifBlk)
	}
}
