package gcasm

// Scalar-chain preamble for fused-region splices, amd64 — the twin of
// simdsplice_fuse_scalar_a64.go. Chains run in R12/DX (plus AX as the
// transient memory-base load, the same protocol as x64FusedLoad), f32
// values in the X0..X3 scratch, and each terminal is packed into its
// lane of X14 with INSERTPS, after the leaf float arguments. 32-bit
// MOVL/ADDL/SHLL forms give the u32 wrap and zero-extension the
// register-indexed addressing needs.

import (
	"fmt"
	"strings"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

type x64ScalarPre struct {
	b         *strings.Builder
	tree      *simdfuse.Tree
	scalarReg func(simdfuse.Arg) string
	offs      *ModuleOffsets
	uses      []int
	freeGpr   []string
	freeFpr   []int
	gprOf     map[int]string
	fprOf     map[int]int
}

// newX64ScalarChain builds the inline scalar-chain evaluator; see the
// arm64 twin for the contract (scratch avoids X0, which may carry a
// chained v128 value mid-region).
func newX64ScalarChain(b *strings.Builder, tree *simdfuse.Tree,
	scalarReg func(simdfuse.Arg) string, offs *ModuleOffsets, uses []int) *x64ScalarPre {
	return &x64ScalarPre{
		b: b, tree: tree, scalarReg: scalarReg, offs: offs, uses: uses,
		freeGpr: []string{"DX", "R12"},
		freeFpr: []int{3, 2, 1},
		gprOf:   map[int]string{},
		fprOf:   map[int]int{},
	}
}

// emitNode evaluates one scalar node in place.
func (p *x64ScalarPre) emitNode(i int, n *simdfuse.Node) error {
	return p.emit(i, n)
}

// takeAddrSource hands a chain-computed ADDRESS terminal to a memory
// emitter (GPR analog of takeSplatSource): the vector walk's
// placement loop already decremented the use, so this only frees the
// scratch slot on death. The emitters copy the value into R12 as
// their first instruction, so handing out a register the preamble
// later clobbers is safe.
func (p *x64ScalarPre) takeAddrSource(idx int) (string, error) {
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

// takeSplatSource consumes a ClassF32 node feeding a splat, returning
// its register and freeing the scratch slot.
func (p *x64ScalarPre) takeSplatSource(idx int) (int, error) {
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

func (p *x64ScalarPre) allocGpr() (string, error) {
	if len(p.freeGpr) == 0 {
		return "", fmt.Errorf("fused splice %s: %w: scalar GPR scratch exhausted", p.tree.Name, errFusedCapacity)
	}
	r := p.freeGpr[len(p.freeGpr)-1]
	p.freeGpr = p.freeGpr[:len(p.freeGpr)-1]
	return r, nil
}

func (p *x64ScalarPre) allocFpr() (int, error) {
	if len(p.freeFpr) == 0 {
		return 0, fmt.Errorf("fused splice %s: %w: scalar FPR scratch exhausted", p.tree.Name, errFusedCapacity)
	}
	f := p.freeFpr[len(p.freeFpr)-1]
	p.freeFpr = p.freeFpr[:len(p.freeFpr)-1]
	return f, nil
}

func (p *x64ScalarPre) takeGpr(a simdfuse.Arg) (string, error) {
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
			fmt.Fprintf(p.b, "\tMOVQ %s, %s\n", src, r)
		} else {
			fmt.Fprintf(p.b, "\tMOVL %s, %s\n", src, r)
		}
		return r, nil
	case simdfuse.ArgScalar:
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tMOVQ %s, %s\n", p.scalarReg(a), r)
		} else {
			fmt.Fprintf(p.b, "\tMOVL %s, %s\n", p.scalarReg(a), r)
		}
		return r, nil
	case simdfuse.ArgSum:
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tMOVQ %s, %s\n", p.scalarReg(a), r)
			if a.Const != 0 {
				fmt.Fprintf(p.b, "\tADDQ $%d, %s\n", int64(a.Const), r)
			}
		} else {
			fmt.Fprintf(p.b, "\tMOVL %s, %s\n", p.scalarReg(a), r)
			if a.Const != 0 {
				fmt.Fprintf(p.b, "\tADDL $%d, %s\n", a.Const, r)
			}
		}
		return r, nil
	case simdfuse.ArgConst:
		r, err := p.allocGpr()
		if err != nil {
			return "", err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tMOVQ $%d, %s\n", int64(a.Const), r)
		} else {
			fmt.Fprintf(p.b, "\tMOVL $%d, %s\n", a.Const, r)
		}
		return r, nil
	}
	return "", fmt.Errorf("fused splice %s: bad scalar operand kind", p.tree.Name)
}

func (p *x64ScalarPre) takeFpr(a simdfuse.Arg) (int, error) {
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
	fmt.Fprintf(p.b, "\tMOVAPS X%d, X%d\n", src, f)
	return f, nil
}

func (p *x64ScalarPre) emit(i int, n *simdfuse.Node) error {
	switch n.Op {
	case "scalar_i32_load16_u":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(p.b, "\tMOVWLZX (%s)(%s*1), %s\n", x64MemBase(p.b, p.offs), g, g)
		p.gprOf[i] = g
	case "scalar_i32_shl":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		if p.tree.Addr64 {
			fmt.Fprintf(p.b, "\tSHLQ $%d, %s\n", uint64(n.Args[1].Const)%64, g)
		} else {
			fmt.Fprintf(p.b, "\tSHLL $%d, %s\n", uint32(n.Args[1].Const)%32, g)
		}
		p.gprOf[i] = g
	case "scalar_i32_add":
		g, err := p.takeGpr(n.Args[0])
		if err != nil {
			return err
		}
		addOp := "ADDL"
		imm := int64(n.Args[1].Const)
		if p.tree.Addr64 {
			addOp = "ADDQ"
		}
		r := n.Args[1]
		switch r.Kind {
		case simdfuse.ArgConst:
			fmt.Fprintf(p.b, "\t%s $%d, %s\n", addOp, imm, g)
		case simdfuse.ArgScalar:
			fmt.Fprintf(p.b, "\t%s %s, %s\n", addOp, p.scalarReg(r), g)
		case simdfuse.ArgNode:
			g2, err := p.takeGpr(r)
			if err != nil {
				return err
			}
			fmt.Fprintf(p.b, "\t%s %s, %s\n", addOp, g2, g)
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
		fmt.Fprintf(p.b, "\tMOVSS (%s)(%s*1), X%d\n", x64MemBase(p.b, p.offs), g, f)
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
		fmt.Fprintf(p.b, "\tMULSS X%d, X%d\n", fr, fl)
		p.freeFpr = append(p.freeFpr, fr)
		p.fprOf[i] = fl
	default:
		return fmt.Errorf("fused splice %s: unknown scalar op %q", p.tree.Name, n.Op)
	}
	return nil
}
