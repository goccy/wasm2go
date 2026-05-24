package codegen

import (
	"github.com/goccy/wasm2go/internal/wasm"
)

// computeReachableFuncs returns the set of DEFINED functions — keyed by
// local (defined-relative) index — reachable from the module's entry
// points through the direct-call graph.
//
// A wasm module compiled from a large C++ program carries thousands of
// functions that the program can never actually invoke. The Go linker
// cannot drop them because the generated InvokeExport dispatch
// references every export and the element segment takes the address of
// every table entry. Computing reachability here, at transpile time,
// lets wasm2go simply not emit the dead functions.
//
// Roots:
//   - the start function;
//   - every function in an element segment — call_indirect can target
//     any table slot, so all table entries are conservatively live;
//   - the function exports. When entryExports is nil EVERY export is a
//     root, so only functions dead in the wasm itself are dropped.
//     A non-nil entryExports restricts the export roots to the named
//     subset (used by whole-program pruning when the caller knows the
//     real entry set).
//
// The returned map is keyed by local index: function localIdx is kept
// iff result[localIdx] is true.
//
// callees, when non-nil, must be the precomputed call-graph adjacency
// list (one entry per defined function, with each entry listing the
// local indices it directly calls). Passing nil falls back to running
// buildCallGraph here — both PlanMultiPackage and reachability use
// the same graph, so the caller pre-computes it once and threads the
// result through to avoid scanning the bytecode three times.
func computeReachableFuncs(mod *wasm.Module, entryExports map[string]bool, callees [][]uint32) (map[uint32]bool, error) {
	if callees == nil {
		var err error
		callees, err = buildCallGraph(mod) // callees[localIdx] = []localIdx
		if err != nil {
			return nil, err
		}
	}
	nImp := mod.NumImportedFuncs
	nDef := uint32(len(mod.Functions))

	reachable := make(map[uint32]bool, nDef)
	var work []uint32
	addLocal := func(d uint32) {
		if d >= nDef || reachable[d] {
			return
		}
		reachable[d] = true
		work = append(work, d)
	}
	addGlobal := func(fi uint32) {
		if fi < nImp { // imported function — no body to emit or walk
			return
		}
		addLocal(fi - nImp)
	}

	if mod.Start != nil {
		addGlobal(*mod.Start)
	}
	for _, seg := range mod.Elements {
		for _, fi := range seg.FuncIdxs {
			addGlobal(fi)
		}
	}
	for _, e := range mod.Exports {
		if e.Kind != wasm.ExportFunc {
			continue
		}
		// When entryExports is non-nil it lists the exact set of export
		// names to keep as reachability roots. Any export not in the
		// set is dropped from the root set (its function can still
		// become reachable through the table or a direct call).
		if entryExports != nil && !entryExports[e.Name] {
			continue
		}
		addGlobal(e.Index)
	}

	for len(work) > 0 {
		d := work[len(work)-1]
		work = work[:len(work)-1]
		for _, c := range callees[d] {
			addLocal(c)
		}
	}
	return reachable, nil
}
