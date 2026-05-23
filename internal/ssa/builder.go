package ssa

// FuncBuilder helps construct a Func incrementally during lowering. It
// hides the bookkeeping of block ordering, value-id assignment, and
// edge wiring behind small typed methods.
//
// Usage pattern:
//
//	b := ssa.NewFuncBuilder("fn42", sig)
//	entry := b.NewBlock(BlockPlain)
//	b.SetEntry(entry)
//	b.SetCurrent(entry)
//	x := b.Const32(7)
//	y := b.Const32(35)
//	z := b.NewValue(OpAdd32, TypeI32, x, y)
//	b.FinishRet(z)
//	f := b.Func()
type FuncBuilder struct {
	f *Func
	// cur is the block new values are appended to. Set via SetCurrent.
	cur *Block
}

// NewFuncBuilder starts a fresh builder for a function with the given
// name and signature.
func NewFuncBuilder(name string, sig FuncSig) *FuncBuilder {
	return &FuncBuilder{f: NewFunc(name, sig)}
}

// Func returns the underlying Func. Called once construction is complete.
func (b *FuncBuilder) Func() *Func { return b.f }

// NewBlock allocates a Block of the given kind and registers it on the
// function. Use SetCurrent to make it the target of subsequent value
// emits.
func (b *FuncBuilder) NewBlock(kind BlockKind) *Block { return b.f.NewBlock(kind) }

// SetEntry marks the function's entry block. Must be called exactly once.
func (b *FuncBuilder) SetEntry(blk *Block) { b.f.SetEntry(blk) }

// SetCurrent makes blk the target for subsequent value emits.
func (b *FuncBuilder) SetCurrent(blk *Block) { b.cur = blk }

// Current returns the currently-targeted block.
func (b *FuncBuilder) Current() *Block { return b.cur }

// NewValue appends a value to the current block, with the given op,
// result type, and operand list. The new value is returned so callers
// can chain.
func (b *FuncBuilder) NewValue(op Op, typ Type, args ...*Value) *Value {
	if b.cur == nil {
		panic("ssa.FuncBuilder: NewValue called with no current block")
	}
	v := b.f.newValue(op, typ, args, b.cur, 0, nil)
	b.cur.Values = append(b.cur.Values, v)
	return v
}

// NewValueAuxInt is NewValue with a small immediate (used by OpConst*,
// OpLoad*, OpStore* offsets, etc).
func (b *FuncBuilder) NewValueAuxInt(op Op, typ Type, auxInt int64, args ...*Value) *Value {
	if b.cur == nil {
		panic("ssa.FuncBuilder: NewValueAuxInt called with no current block")
	}
	v := b.f.newValue(op, typ, args, b.cur, auxInt, nil)
	b.cur.Values = append(b.cur.Values, v)
	return v
}

// NewValueAux is NewValue with a boxed-object aux (used by OpCall*).
func (b *FuncBuilder) NewValueAux(op Op, typ Type, aux interface{}, args ...*Value) *Value {
	if b.cur == nil {
		panic("ssa.FuncBuilder: NewValueAux called with no current block")
	}
	v := b.f.newValue(op, typ, args, b.cur, 0, aux)
	b.cur.Values = append(b.cur.Values, v)
	return v
}

// Const32 emits an i32 constant. Convenience wrapper.
func (b *FuncBuilder) Const32(v int32) *Value {
	return b.NewValueAuxInt(OpConst32, TypeI32, int64(v))
}

// Const64 emits an i64 constant. Convenience wrapper.
func (b *FuncBuilder) Const64(v int64) *Value {
	return b.NewValueAuxInt(OpConst64, TypeI64, v)
}

// Param emits a function-parameter accessor. AuxInt = parameter index.
// Typically called once per parameter at the start of the entry block.
func (b *FuncBuilder) Param(idx int, typ Type) *Value {
	return b.NewValueAuxInt(OpParam, typ, int64(idx))
}

// LinkPlain wires the current block (kind Plain) to a single successor.
func (b *FuncBuilder) LinkPlain(succ *Block) {
	if b.cur == nil {
		panic("ssa.FuncBuilder: LinkPlain with no current block")
	}
	AddEdge(b.cur, succ)
}

// LinkIf wires the current block (kind If) to its then/else successors
// and records the branch condition.
func (b *FuncBuilder) LinkIf(cond *Value, thenBlk, elseBlk *Block) {
	if b.cur == nil {
		panic("ssa.FuncBuilder: LinkIf with no current block")
	}
	b.cur.Control = cond
	AddEdge(b.cur, thenBlk)
	AddEdge(b.cur, elseBlk)
}

// FinishRet marks the current block as Ret with the given return values
// as its last instructions. Subsequent values cannot be appended.
func (b *FuncBuilder) FinishRet(results ...*Value) {
	if b.cur == nil {
		panic("ssa.FuncBuilder: FinishRet with no current block")
	}
	b.cur.Kind = BlockRet
	// Returned values are tracked via the last len(Results) slots; the
	// emit pass will pick them up. Store a synthetic OpCopy of each in
	// the block so the emit pass can find them in a canonical place.
	for _, r := range results {
		b.cur.Values = append(b.cur.Values, b.f.newValue(OpCopy, r.Type, []*Value{r}, b.cur, 0, nil))
	}
}
