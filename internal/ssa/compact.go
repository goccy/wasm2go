package ssa

// Compact removes values marked dead (Op == OpInvalid) from every
// block's value list. Optimization passes "delete" a value by setting
// its Op to OpInvalid and clearing its Args; Compact then sweeps those
// out so the emit stage and Verify never see them.
//
// Func.Values is left sparse on purpose: it is indexed by ValueID, and
// other code (e.g. emit's hoist lookup) relies on f.Values[id] staying
// valid. A dead value simply remains in Func.Values, unreferenced.
//
// Relative order within each block is preserved, so a BlockRet's tail
// return markers stay last and the phis stay first.
func Compact(f *Func) {
	for _, b := range f.Blocks {
		w := b.Values[:0]
		for _, v := range b.Values {
			if v.Op == OpInvalid {
				continue
			}
			w = append(w, v)
		}
		b.Values = w
	}
}

// CountValues returns the number of live (non-OpInvalid) values across
// all blocks — the instruction count used to measure optimization.
func CountValues(f *Func) int {
	n := 0
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != OpInvalid {
				n++
			}
		}
	}
	return n
}
