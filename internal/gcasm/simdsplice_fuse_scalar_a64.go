package gcasm

// Scalar-chain preamble for fused-region splices, arm64.
//
// Scalar-class nodes (see internal/simdfuse: the scale-lookup
// vocabulary) are always scheduled as a prefix of the node list and
// evaluated here BEFORE any vector body runs: the low vector
// registers v0..v3 and the memory-preamble GPR scratch R24..R27 are
// still free, so chains run entirely in registers and each float32
// terminal lands in its home register (v15 downward, after the leaf
// float arguments), where the splat nodes broadcast from. All i32
// arithmetic uses W-form instructions, which zero-extend into the
// upper half — exactly the u32 wrap of the wasm ops this vocabulary
// lowers, and what the register-indexed addressing modes need.

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

type a64ScalarPre struct {
	b         *strings.Builder
	tree      *simdfuse.Tree
	scalarReg func(simdfuse.Arg) string
	uses      []int
	freeGpr   []string
	freeFpr   []int
	gprOf     map[int]string // ClassI32 node -> GPR holding its value
	fprOf     map[int]int    // ClassF32 node -> scratch V (value in lane 0)
	// lutBase maps a table-base scalar index to a register holding the
	// HOST address (memory base + table offset), hoisted by the loop
	// splicer. When the classic lookup shape
	// f32_load(add(shl(load16, 2), table)) hits a hoisted table, the
	// shift and add elide into one scaled-register load.
	lutBase map[int]string
	// elided marks nodes swallowed by that peephole; lutOf lists the
	// f32 loads the peephole rewrites.
	elided map[int]bool
	lutOf  []int
}

// newA64ScalarChain builds the inline scalar-chain evaluator. Chains
// are glued immediately before their vector consumer by the scheduler
// and evaluate mid-region: F0/X0 may carry a chained v128 value, so
// scratch is F1..F3 plus the memory-preamble GPRs (dead between node
// bodies). Terminals stay in their scratch FPR; the consumer splat
// broadcasts from lane 0 and releases it.
func newA64ScalarChain(b *strings.Builder, tree *simdfuse.Tree,
	scalarReg func(simdfuse.Arg) string, uses []int, lutBase map[int]string) *a64ScalarPre {
	p := &a64ScalarPre{
		b: b, tree: tree, scalarReg: scalarReg, uses: uses,
		freeGpr: []string{"R27", "R26", "R25", "R24"},
		freeFpr: []int{3, 2, 1},
		gprOf:   map[int]string{},
		fprOf:   map[int]int{},
		lutBase: lutBase,
	}
	// Pre-mark the peephole's swallowed nodes: they precede their
	// consuming load in node order, so the elision must be decided
	// before the emission walk reaches them.
	for i := range tree.Nodes {
		n := &tree.Nodes[i]
		if ldIdx, _, ok := p.lutPattern(n); ok {
			if p.elided == nil {
				p.elided = map[int]bool{}
			}
			p.elided[ldIdx] = true
			p.elided[tree.Nodes[n.Args[0].Index].Args[0].Index] = true
			p.elided[n.Args[0].Index] = true
			p.lutOf = append(p.lutOf, i)
		}
	}
	return p
}

// emitNode evaluates one scalar node in place.
func (p *a64ScalarPre) emitNode(i int, n *simdfuse.Node) error {
	return p.emit(i, n)
}

// takeSplatSource consumes a ClassF32 node feeding a splat and returns
// its register, freeing the scratch slot.
func (p *a64ScalarPre) takeSplatSource(idx int) (int, error) {
	f, ok := p.fprOf[idx]
	if !ok {
		return 0, fmt.Errorf("fused splice %s: splat source n%d not in a register", p.tree.Name, idx)
	}
	// The vector walk's placement loop already decremented this use;
	// free the scratch slot on death.
	if p.uses[idx] == 0 {
		delete(p.fprOf, idx)
		p.freeFpr = append(p.freeFpr, f)
	}
	return f, nil
}

func (p *a64ScalarPre) allocGpr() (string, error) {
	if len(p.freeGpr) == 0 {
		return "", fmt.Errorf("fused splice %s: %w: scalar GPR scratch exhausted", p.tree.Name, errFusedCapacity)
	}
	r := p.freeGpr[len(p.freeGpr)-1]
	p.freeGpr = p.freeGpr[:len(p.freeGpr)-1]
	return r, nil
}

func (p *a64ScalarPre) allocFpr() (int, error) {
	if len(p.freeFpr) == 0 {
		return 0, fmt.Errorf("fused splice %s: %w: scalar FPR scratch exhausted", p.tree.Name, errFusedCapacity)
	}
	f := p.freeFpr[len(p.freeFpr)-1]
	p.freeFpr = p.freeFpr[:len(p.freeFpr)-1]
	return f, nil
}

// takeAddrSource hands a chain-computed ADDRESS terminal to a memory
// emitter: the GPR analog of takeSplatSource. The vector walk's
// placement loop already decremented the use, so this only frees the
// scratch slot on death — the caller copies the value into the
// address register before any clobbering.
func (p *a64ScalarPre) takeAddrSource(idx int) (string, error) {
	g, ok := p.gprOf[idx]
	if !ok {
		return "", fmt.Errorf("fused splice %s: address source n%d not in a register", p.tree.Name, idx)
	}
	if p.uses[idx] == 0 {
		delete(p.gprOf, idx)
		p.freeGpr = append(p.freeGpr, g)
	}
	return g, nil
}

// takeGpr consumes an i32 operand and returns a GPR the caller may
// CLOBBER: the operand's own register when this was its last use, a
// fresh copy otherwise.
func (p *a64ScalarPre) takeGpr(a simdfuse.Arg) (string, error) {
	switch a.Kind {
	case simdfuse.ArgNode:
		src, ok := p.gprOf[a.Index]
		if !ok {
			return "", fmt.Errorf("fused splice %s: scalar operand n%d not in a register", p.tree.Name, a.Index)
		}
		p.uses[a.Index]--
		if p.uses[a.Index] == 0 {
			delete(p.gprOf, a.Index)
			return src, nil
		}
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tMOVD %s, %s\n", src, r)
		} else {
			fmt.Fprintf(p.b, "\tMOVWU %s, %s\n", src, r)
		}
		return r, nil
	case simdfuse.ArgScalar:
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tMOVD %s, %s\n", p.scalarReg(a), r)
		} else {
			fmt.Fprintf(p.b, "\tMOVWU %s, %s\n", p.scalarReg(a), r)
		}
		return r, nil
	case simdfuse.ArgSum:
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			// Full-width move + signed addend (memory64 offsets may be
			// negated struct-field subtractions).
			fmt.Fprintf(p.b, "\tMOVD %s, %s\n", p.scalarReg(a), r)
			switch {
			case a.Const == 0:
			case a.Const > 0 && a.Const < 4096:
				fmt.Fprintf(p.b, "\tADD $%d, %s, %s\n", a.Const, r, r)
			default:
				fmt.Fprintf(p.b, "\tMOVD $%d, R22\n", int64(a.Const))
				fmt.Fprintf(p.b, "\tADD R22, %s, %s\n", r, r)
			}
			return r, nil
		}
		switch {
		case a.Const == 0:
			fmt.Fprintf(p.b, "\tMOVWU %s, %s\n", p.scalarReg(a), r)
		case a.Const > 0 && a.Const < 4096:
			fmt.Fprintf(p.b, "\tADDW $%d, %s, %s\n", a.Const, p.scalarReg(a), r)
		default:
			fmt.Fprintf(p.b, "\tMOVWU %s, %s\n", p.scalarReg(a), r)
			fmt.Fprintf(p.b, "\tMOVD $%d, R22\n", int64(uint32(a.Const)))
			fmt.Fprintf(p.b, "\tADDW R22, %s, %s\n", r, r)
		}
		return r, nil
	case simdfuse.ArgConst:
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tMOVD $%d, %s\n", int64(a.Const), r)
		} else {
			fmt.Fprintf(p.b, "\tMOVD $%d, %s\n", int64(uint32(a.Const)), r)
		}
		return r, nil
	}
	return "", fmt.Errorf("fused splice %s: bad scalar operand kind", p.tree.Name)
}

// takeFpr is takeGpr for f32 operands.
func (p *a64ScalarPre) takeFpr(a simdfuse.Arg) (int, error) {
	if a.Kind != simdfuse.ArgNode {
		return 0, fmt.Errorf("fused splice %s: f32 operand must be a node", p.tree.Name)
	}
	src, ok := p.fprOf[a.Index]
	if !ok {
		return 0, fmt.Errorf("fused splice %s: f32 operand n%d not in a register", p.tree.Name, a.Index)
	}
	p.uses[a.Index]--
	if p.uses[a.Index] == 0 {
		delete(p.fprOf, a.Index)
		return src, nil
	}
	f, err := p.allocFpr()
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(p.b, "\tFMOVS F%d, F%d\n", src, f)
	return f, nil
}

// lutPattern matches f32_load(add(shl(load16(...), 2), tableScalar))
// against a hoisted table base, returning the load16 node and the
// hoisted register.
func (p *a64ScalarPre) lutPattern(n *simdfuse.Node) (int, string, bool) {
	if p.lutBase == nil || n.Op != "scalar_f32_load" || n.Args[0].Kind != simdfuse.ArgNode {
		return 0, "", false
	}
	add := &p.tree.Nodes[n.Args[0].Index]
	if add.Op != "scalar_i32_add" || add.Args[0].Kind != simdfuse.ArgNode || add.Args[1].Kind != simdfuse.ArgScalar {
		return 0, "", false
	}
	host, ok := p.lutBase[add.Args[1].Index]
	if !ok {
		return 0, "", false
	}
	shl := &p.tree.Nodes[add.Args[0].Index]
	if shl.Op != "scalar_i32_shl" || shl.Args[0].Kind != simdfuse.ArgNode || shl.Args[1].Const != 2 {
		return 0, "", false
	}
	ld := &p.tree.Nodes[shl.Args[0].Index]
	if ld.Op != "scalar_i32_load16_u" {
		return 0, "", false
	}
	// The intermediate nodes must have no other consumers.
	if p.uses[n.Args[0].Index] != 1 || p.uses[add.Args[0].Index] != 1 || p.uses[shl.Args[0].Index] != 1 {
		return 0, "", false
	}
	return shl.Args[0].Index, host, true
}

func (p *a64ScalarPre) emit(i int, n *simdfuse.Node) error {
	if p.elided != nil && p.elided[i] {
		return nil
	}
	if ldIdx, host, ok := p.lutPattern(n); ok {
		// Fused lookup: one u16 load, one scaled-register f32 load.
		ld := &p.tree.Nodes[ldIdx]
		g, err := p.takeGpr(ld.Args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(p.b, "\tMOVHU (R20)(%s), %s\n", g, g)
		f, err := p.allocFpr()
		if err != nil {
			return err
		}
		fmt.Fprintf(p.b, "\tFMOVS (%s)(%s<<2), F%d\n", host, g, f)
		p.freeGpr = append(p.freeGpr, g)
		p.fprOf[i] = f
		return nil
	}
	switch n.Op {
	case "scalar_i32_load16_u":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(p.b, "\tMOVHU (R20)(%s), %s\n", g, g)
		p.gprOf[i] = g
	case "scalar_i32_shl":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tLSL $%d, %s, %s\n", uint64(n.Args[1].Const)%64, g, g)
		} else {
			fmt.Fprintf(p.b, "\tLSLW $%d, %s, %s\n", uint32(n.Args[1].Const)%32, g, g)
		}
		p.gprOf[i] = g
	case "scalar_i32_add":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		addOp := "ADDW"
		imm := int64(uint32(n.Args[1].Const))
		if p.tree.Addr64 {
			addOp, imm = "ADD", int64(n.Args[1].Const)
		}
		r := n.Args[1]
		switch r.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(p.b, "\t%s $%d, %s, %s\n", addOp, imm, g, g)
		case simdfuse.ArgScalar:
			fmt.Fprintf(p.b, "\t%s %s, %s, %s\n", addOp, p.scalarReg(r), g, g)
		case simdfuse.ArgNode:
			g2, err := p.takeGpr(r)
			if err != nil {
				return err
			}
			fmt.Fprintf(p.b, "\t%s %s, %s, %s\n", addOp, g2, g, g)
			p.freeGpr = append(p.freeGpr, g2)
		default:
			return fmt.Errorf("fused splice %s: bad scalar_i32_add operand", p.tree.Name)
		}
		p.gprOf[i] = g
	case "scalar_f32_load":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		f, err := p.allocFpr()
		if err != nil {
			return err
		}
		fmt.Fprintf(p.b, "\tFMOVS (R20)(%s), F%d\n", g, f)
		p.freeGpr = append(p.freeGpr, g)
		p.fprOf[i] = f
	case "scalar_f32_mul":
		fl, err := p.takeFpr(n.Args[0])
		if err != nil {
			return err
		}
		fr, err := p.takeFpr(n.Args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(p.b, "\tFMULS F%d, F%d, F%d\n", fr, fl, fl)
		p.freeFpr = append(p.freeFpr, fr)
		p.fprOf[i] = fl
	default:
		return fmt.Errorf("fused splice %s: unknown scalar op %q", p.tree.Name, n.Op)
	}
	return nil
}
