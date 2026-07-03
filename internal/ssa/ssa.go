// Package ssa is an in-house lightweight SSA IR for wasm2go.
//
// Design notes:
//
//   - Per-function CFG: each Func has a slice of Blocks, one Entry block,
//     and a flat list of Values. Block IDs and Value IDs are stable for
//     the lifetime of the Func.
//   - Memory is represented as an explicit token. Each OpLoad consumes the
//     current memory token; each OpStore produces a new one. Optimisations
//     respect memory dependencies via the value graph rather than via
//     instruction order in a block.
//   - Phis live at the top of their block. They are constructed lazily
//     during wasm-to-SSA lowering via Braun et al.'s "Simple and Efficient
//     Construction of SSA" (no pre-built dominator tree needed).
//
// Style is intentionally close to cmd/compile/internal/ssa so the patterns
// transfer for anyone reading those internals — but the implementation is
// independent and much smaller (no architecture-specific lowering, no
// register allocation; the next stage is emission to Go source).
package ssa

import "fmt"

// ValueID and BlockID are dense per-function identifiers. Zero is reserved
// for "invalid" / "not yet assigned" so callers can use it as a sentinel.
type (
	ValueID int32
	BlockID int32
)

// Func is a function's SSA representation. One Func per generated Go
// function. Funcs are independent; cross-function calls reference the
// callee by name (string) plus signature, not by pointer.
type Func struct {
	Name   string
	Sig    FuncSig
	Blocks []*Block
	Entry  *Block
	// Values is the flat list of every value defined anywhere in the
	// function, indexed by ValueID. Index 0 is a placeholder so a zero
	// ValueID can mean "none".
	Values []*Value

	nextValueID ValueID
	nextBlockID BlockID
}

// FuncSig captures the parameter and result types of a Func. Matches the
// shape produced by wasm.FuncType.
type FuncSig struct {
	Params  []Type
	Results []Type
}

// NewFunc creates an empty Func. The placeholder zero-value is pushed onto
// Values so subsequent IDs start at 1.
func NewFunc(name string, sig FuncSig) *Func {
	f := &Func{Name: name, Sig: sig}
	f.Values = []*Value{nil} // ValueID 0 = invalid
	f.nextValueID = 1
	f.nextBlockID = 0
	return f
}

// NewBlock allocates and registers a new Block on the Func.
func (f *Func) NewBlock(kind BlockKind) *Block {
	b := &Block{ID: f.nextBlockID, Kind: kind, f: f}
	f.nextBlockID++
	f.Blocks = append(f.Blocks, b)
	return b
}

// SetEntry marks b as the function entry. Must be called exactly once
// after the entry block is created.
func (f *Func) SetEntry(b *Block) { f.Entry = b }

// newValue allocates a fresh value with a unique ID and registers it on
// the function. Callers should prefer the Block.New* helpers.
func (f *Func) newValue(op Op, typ Type, args []*Value, block *Block, auxInt int64, aux interface{}) *Value {
	v := &Value{
		ID:     f.nextValueID,
		Op:     op,
		Type:   typ,
		Args:   args,
		AuxInt: auxInt,
		Aux:    aux,
		Block:  block,
	}
	f.nextValueID++
	f.Values = append(f.Values, v)
	return v
}

// Block is one node of the function CFG.
type Block struct {
	ID     BlockID
	Kind   BlockKind
	Preds  []Edge
	Succs  []Edge
	Values []*Value // owned values, in dependency order
	// Control is the value the block branches on (for If and BrTable
	// kinds), the returned value(s) marker (Ret kind), or nil (Plain).
	Control *Value

	// TableCases / TableDefault describe a BlockBrTable terminator
	// (nil / 0 otherwise). TableCases[i] lists the selector values
	// routed to Succs[i]; every selector value not present in any
	// list goes to Succs[TableDefault]. Successor blocks are unique
	// (a wasm br_table routing several indices — or the default — to
	// one label dedupes into a single edge), which keeps phi-arg
	// bookkeeping one-arg-per-pred like every other block kind.
	TableCases   [][]int32
	TableDefault int

	f *Func
}

// Edge is an entry in a Block's pred/succ lists. Index is the position of
// this edge in the OTHER block's complementary list — used so phi args
// can be indexed by pred index.
type Edge struct {
	Block *Block
	Index int
}

// BlockKind classifies a block's terminator.
type BlockKind uint8

const (
	BlockInvalid BlockKind = iota
	// Plain: exactly one successor. No Control value.
	BlockPlain
	// If: two successors (then, else). Control is the i32 condition value
	// (non-zero = then).
	BlockIf
	// Ret: zero successors. Control is unused; the values to return are
	// the block's last Values (matching FuncSig.Results).
	BlockRet
	// Unreachable: zero successors, traps at runtime.
	BlockUnreachable
	// BrTable: one successor per unique branch target of a wasm
	// br_table. Control is the i32 selector; Block.TableCases /
	// Block.TableDefault map selector values to successors. Lowered
	// from arity-0 br_table dispatch (a bytecode interpreter's
	// computed goto); emitted as a Go switch (pure) or a
	// binary-search compare tree (asm) instead of the O(n)
	// equality-If chain used before.
	BlockBrTable
)

// AddEdge wires src → dst as a CFG edge, updating both lists. The returned
// Edge.Index on each side records the position in the other's list.
func AddEdge(src, dst *Block) {
	si := len(dst.Preds)
	di := len(src.Succs)
	src.Succs = append(src.Succs, Edge{Block: dst, Index: si})
	dst.Preds = append(dst.Preds, Edge{Block: src, Index: di})
}

// Value is one SSA node.
type Value struct {
	ID     ValueID
	Op     Op
	Type   Type
	Args   []*Value
	AuxInt int64       // small immediate (constant value, offset, ...)
	Aux    interface{} // larger immediate (call target, string, ...)
	Block  *Block
}

// String produces a short "v3 = OpAdd32 v1 v2" rendering.
func (v *Value) String() string {
	if v == nil {
		return "<nil-value>"
	}
	s := fmt.Sprintf("v%d = %s", v.ID, v.Op)
	if v.Op.UsesAuxInt() || v.AuxInt != 0 {
		s += fmt.Sprintf(" [%d]", v.AuxInt)
	}
	if v.Aux != nil {
		s += fmt.Sprintf(" {%v}", v.Aux)
	}
	for _, a := range v.Args {
		if a == nil {
			s += " <nil>"
		} else {
			s += fmt.Sprintf(" v%d", a.ID)
		}
	}
	return s
}
