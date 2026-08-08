package lower

import (
	"github.com/goccy/wasm2go/internal/wasm"
)

// ThrowSet answers "can a call to this function leave an exception
// pending?" — the question the branch-based EH lowering asks at every call
// site to decide whether to emit a check-and-branch.
//
// A function may throw when its body contains `throw` or `rethrow`, when it
// calls a may-throw function, or when it performs a `call_indirect` whose
// type could resolve to one (conservatively: any indirect call to a
// signature some may-throw function has). Host imports never throw: a wasm
// exception can only be raised by wasm code, and the generated host
// interfaces have no way to set the pending state.
//
// Being conservative only costs a predictable branch on a flag that is
// almost always false, so the analysis stays simple: no attempt is made to
// prove that an enclosing catch_all swallows everything.
type ThrowSet struct {
	may           map[uint32]bool // function index → may leave an exception pending
	indirectTypes map[uint32]bool // type index → some may-throw function has it
	anyIndirect   bool            // any may-throw function is a call_indirect target
}

// MayThrow reports whether calling funcIdx can leave an exception pending.
func (t *ThrowSet) MayThrow(funcIdx uint32) bool {
	if t == nil {
		return true // no analysis available: assume the worst
	}
	return t.may[funcIdx]
}

// IndirectMayThrow reports whether a call_indirect of the given type index
// can leave an exception pending.
func (t *ThrowSet) IndirectMayThrow(typeIdx uint32) bool {
	if t == nil {
		return true
	}
	return t.indirectTypes[typeIdx]
}

// AnyThrows reports whether the module contains any throwing code at all.
// When false the whole EH machinery (module state, call-site checks) can be
// skipped.
func (t *ThrowSet) AnyThrows() bool { return t != nil && len(t.may) > 0 }

// ComputeThrowSet runs the analysis over a module. callees maps a function
// index to the indices it calls directly (the call graph codegen already
// builds); when nil the direct-call edges are rescanned here.
func ComputeThrowSet(mod *wasm.Module, callees map[uint32][]uint32) (*ThrowSet, error) {
	ts := &ThrowSet{may: map[uint32]bool{}, indirectTypes: map[uint32]bool{}}

	// Seed: functions whose own body raises. Also record which of them can
	// be reached indirectly, and whether any body uses call_indirect at all
	// (a may-throw callee reached that way propagates to its caller).
	hasIndirect := map[uint32]bool{}
	for i := range mod.Functions {
		idx := mod.NumImportedFuncs + uint32(i)
		raises, indirect, err := scanThrowOps(mod.Functions[i].Body)
		if err != nil {
			return nil, err
		}
		if raises {
			ts.may[idx] = true
		}
		hasIndirect[idx] = indirect
	}
	if len(ts.may) == 0 {
		return ts, nil // module has no EH at all
	}

	// Propagate along the call graph to a fixpoint. The graph is small
	// relative to the body scan, so a simple worklist is plenty.
	if callees == nil {
		callees = map[uint32][]uint32{}
		for i := range mod.Functions {
			idx := mod.NumImportedFuncs + uint32(i)
			cs, err := scanDirectCallees(mod.Functions[i].Body)
			if err != nil {
				return nil, err
			}
			callees[idx] = cs
		}
	}
	callers := map[uint32][]uint32{}
	for caller, cs := range callees {
		for _, callee := range cs {
			callers[callee] = append(callers[callee], caller)
		}
	}
	work := make([]uint32, 0, len(ts.may))
	for idx := range ts.may {
		work = append(work, idx)
	}
	for len(work) > 0 {
		idx := work[len(work)-1]
		work = work[:len(work)-1]
		for _, c := range callers[idx] {
			if !ts.may[c] {
				ts.may[c] = true
				work = append(work, c)
			}
		}
	}

	// Indirect edges: any may-throw function that appears in an element
	// segment makes its signature (and every caller doing call_indirect of
	// that signature) may-throw. Iterate until stable, since a newly
	// may-throw caller can itself be an indirect target.
	elemTargets := map[uint32]bool{}
	for _, seg := range mod.Elements {
		for _, fi := range seg.FuncIdxs {
			elemTargets[fi] = true
		}
	}
	for {
		changed := false
		for idx := range elemTargets {
			if !ts.may[idx] || idx < mod.NumImportedFuncs {
				continue
			}
			ti := mod.Functions[idx-mod.NumImportedFuncs].TypeIdx
			if !ts.indirectTypes[ti] {
				ts.indirectTypes[ti] = true
				ts.anyIndirect = true
				changed = true
			}
		}
		if !changed {
			break
		}
		// A caller whose call_indirect can now reach a may-throw target
		// becomes may-throw itself; that may in turn open new indirect
		// signatures on the next round.
		for i := range mod.Functions {
			idx := mod.NumImportedFuncs + uint32(i)
			if ts.may[idx] || !hasIndirect[idx] {
				continue
			}
			reaches, err := indirectReachesThrow(mod.Functions[i].Body, ts)
			if err != nil {
				return nil, err
			}
			if reaches {
				ts.may[idx] = true
				work = append(work, idx)
			}
		}
		for len(work) > 0 {
			idx := work[len(work)-1]
			work = work[:len(work)-1]
			for _, c := range callers[idx] {
				if !ts.may[c] {
					ts.may[c] = true
					work = append(work, c)
				}
			}
		}
	}
	return ts, nil
}

// scanThrowOps reports whether a body raises an exception itself and
// whether it contains any call_indirect.
func scanThrowOps(body []byte) (raises, indirect bool, err error) {
	r := wasm.NewInstrReader(body)
	if err := skipLocalDecls(r); err != nil {
		return false, false, err
	}
	for !r.EOF() {
		op, err := r.ReadByte()
		if err != nil {
			return false, false, err
		}
		switch op {
		case wasm.OpThrow, wasm.OpRethrow:
			raises = true
		case wasm.OpCallIndirect:
			indirect = true
		}
		if err := r.SkipImmediates(op); err != nil {
			return false, false, err
		}
	}
	return raises, indirect, nil
}

func scanDirectCallees(body []byte) ([]uint32, error) {
	r := wasm.NewInstrReader(body)
	if err := skipLocalDecls(r); err != nil {
		return nil, err
	}
	var out []uint32
	for !r.EOF() {
		op, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if op == wasm.OpCall {
			idx, err := r.ReadU32()
			if err != nil {
				return nil, err
			}
			out = append(out, idx)
			continue
		}
		if err := r.SkipImmediates(op); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// indirectReachesThrow reports whether the body performs a call_indirect
// whose type is one a may-throw function has.
func indirectReachesThrow(body []byte, ts *ThrowSet) (bool, error) {
	r := wasm.NewInstrReader(body)
	if err := skipLocalDecls(r); err != nil {
		return false, err
	}
	for !r.EOF() {
		op, err := r.ReadByte()
		if err != nil {
			return false, err
		}
		if op == wasm.OpCallIndirect {
			ti, err := r.ReadU32()
			if err != nil {
				return false, err
			}
			if _, err := r.ReadU32(); err != nil { // table index
				return false, err
			}
			if ts.indirectTypes[ti] {
				return true, nil
			}
			continue
		}
		if err := r.SkipImmediates(op); err != nil {
			return false, err
		}
	}
	return false, nil
}
