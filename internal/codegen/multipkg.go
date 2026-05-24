package codegen

import (
	"fmt"
	"sort"

	"github.com/goccy/wasm2go/internal/wasm"
)

// MultiPackagePlan describes how the defined wasm functions are distributed
// across a chain of Go packages. Each chunk imports all earlier chunks so the
// Go build system compiles them strictly serially — bounding peak compiler
// memory to one chunk's SSA cost regardless of total module size.
type MultiPackagePlan struct {
	// Chunks in topological order. Chunks[0] has no chunk dependencies;
	// Chunks[i] (i>0) depends on Chunks[0..i-1] via Go imports.
	Chunks []MultiPackageChunk
	// FuncToChunk maps a defined-function index (NumImportedFuncs..end) to
	// the chunk index that holds it.
	FuncToChunk map[uint32]int
}

// MultiPackageChunk lists the function indices owned by a single chunk
// package, plus the size estimate used during packing.
type MultiPackageChunk struct {
	FuncIdxs []uint32
	Bytes    int
}

// PlanLinknamePackages builds a chunk plan for the linkname-split layout
// (Options.LinknameSplit = true). Mutually-recursive functions are still kept
// in the same SCC (so they don't have to pay a linkname hop to call each
// other), but the SCC-level topological order is NOT used to bound chunk
// dependencies — cross-chunk calls are wired by //go:linkname at emit time,
// so chunks can call any other chunk regardless of ordering. The partitioner
// uses first-fit-decreasing bin packing on SCC byte size to balance chunks
// without the "later chunks must only call earlier ones" constraint.
// PlanLinknamePackages builds the chunk plan for linkname-split mode.
// reachable, when non-nil, is the whole-function dead-code-elimination
// result keyed by local index; SCCs whose functions are all dead are
// skipped so they neither consume chunk budget nor get emitted.
func PlanLinknamePackages(mod *wasm.Module, chunkBytes int, reachable map[uint32]bool) (*MultiPackagePlan, error) {
	return planLinknamePackagesWith(mod, chunkBytes, reachable, nil)
}

// planLinknamePackagesWith is the implementation accepting a precomputed
// callees adjacency list. callees may be nil — the function will build
// the graph itself in that case. Exposed only inside the package so
// the codegen translator can share its cached call graph with the
// planner.
func planLinknamePackagesWith(mod *wasm.Module, chunkBytes int, reachable map[uint32]bool, callees [][]uint32) (*MultiPackagePlan, error) {
	if chunkBytes <= 0 {
		chunkBytes = 1024 * 1024
	}
	nDefined := uint32(len(mod.Functions))
	nImports := mod.NumImportedFuncs

	if callees == nil {
		var err error
		callees, err = buildCallGraph(mod)
		if err != nil {
			return nil, err
		}
	}
	sccs := tarjanSCC(nDefined, callees)

	// Compute SCC sizes (sum of function-body bytes for that SCC).
	// An SCC is mutually-reachable, so it is uniformly reachable or
	// uniformly dead — testing one member suffices.
	type sccBin struct {
		funcs []uint32
		bytes int
	}
	bins := make([]sccBin, 0, len(sccs))
	for _, scc := range sccs {
		if reachable != nil && len(scc) > 0 && !reachable[scc[0]] {
			continue // entire SCC is dead — drop it
		}
		size := 0
		for _, f := range scc {
			size += len(mod.Functions[f].Body)
		}
		bins = append(bins, sccBin{funcs: scc, bytes: size})
	}

	// First-fit-decreasing: pack the biggest SCCs first. SCCs that exceed
	// chunkBytes alone get their own chunk (we cannot split an SCC further
	// without breaking call closure within the SCC).
	sort.SliceStable(bins, func(i, j int) bool {
		return bins[i].bytes > bins[j].bytes
	})
	type packedChunk struct {
		funcs []uint32
		bytes int
	}
	var chunks []packedChunk
	for _, b := range bins {
		if b.bytes >= chunkBytes {
			// Oversized SCC → its own chunk. Inserted at front so subsequent
			// fitting decisions for smaller SCCs don't accidentally probe it.
			chunks = append(chunks, packedChunk(b))
			continue
		}
		// Try to fit into an existing chunk.
		fit := -1
		for i := range chunks {
			if chunks[i].bytes+b.bytes <= chunkBytes {
				fit = i
				break
			}
		}
		if fit < 0 {
			chunks = append(chunks, packedChunk(b))
		} else {
			chunks[fit].funcs = append(chunks[fit].funcs, b.funcs...)
			chunks[fit].bytes += b.bytes
		}
	}

	plan := &MultiPackagePlan{FuncToChunk: map[uint32]int{}}
	plan.Chunks = make([]MultiPackageChunk, len(chunks))
	for i, c := range chunks {
		plan.Chunks[i] = MultiPackageChunk{FuncIdxs: make([]uint32, 0, len(c.funcs)), Bytes: c.bytes}
		// Stable order within a chunk: ascending function index. This makes
		// the generated output deterministic and easier to diff across runs.
		sortedFuncs := append([]uint32(nil), c.funcs...)
		sort.Slice(sortedFuncs, func(a, b int) bool { return sortedFuncs[a] < sortedFuncs[b] })
		for _, f := range sortedFuncs {
			plan.Chunks[i].FuncIdxs = append(plan.Chunks[i].FuncIdxs, nImports+f)
			plan.FuncToChunk[nImports+f] = i
		}
	}
	return plan, nil
}

// buildCallGraph returns, for each defined-function local index, the set of
// defined-function local indices it directly calls. Imported-function calls
// are excluded (they're handled by the host-import struct, not by Go imports).
func buildCallGraph(mod *wasm.Module) ([][]uint32, error) {
	out := make([][]uint32, len(mod.Functions))
	for i, fn := range mod.Functions {
		seen := map[uint32]bool{}
		callees, err := scanDirectCalls(fn.Body, mod.NumImportedFuncs)
		if err != nil {
			return nil, fmt.Errorf("fn%d: %w", uint32(i)+mod.NumImportedFuncs, err)
		}
		for _, c := range callees {
			if c < mod.NumImportedFuncs {
				continue
			}
			localIdx := c - mod.NumImportedFuncs
			if seen[localIdx] {
				continue
			}
			seen[localIdx] = true
			out[i] = append(out[i], localIdx)
		}
	}
	return out, nil
}

// scanDirectCalls walks a function body and collects every operand of a
// `call <idx>` instruction. Skips locals, types, and other LEB128 fields by
// using a bytecode-aware skipper modeled on instrReader.skip.
func scanDirectCalls(body []byte, _ uint32) ([]uint32, error) {
	r := &instrReader{src: body}
	// Skip locals header.
	nDecls, err := r.readU32()
	if err != nil {
		return nil, fmt.Errorf("locals header: %w", err)
	}
	for i := uint32(0); i < nDecls; i++ {
		if _, err := r.readU32(); err != nil {
			return nil, err
		}
		if _, err := r.readByte(); err != nil {
			return nil, err
		}
	}
	var out []uint32
	for !r.eof() {
		op, err := r.readByte()
		if err != nil {
			return nil, err
		}
		if op == opCall {
			idx, err := r.readU32()
			if err != nil {
				return nil, err
			}
			out = append(out, idx)
			continue
		}
		// ref.func names a function whose address is taken — the named
		// function must stay live across whole-function DCE, so treat
		// it as a call-graph edge alongside opCall.
		if op == opRefFunc {
			idx, err := r.readU32()
			if err != nil {
				return nil, err
			}
			out = append(out, idx)
			continue
		}
		if err := r.skipImmediates(op); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// tarjanSCC computes the strongly connected components of the call graph
// using Tarjan's algorithm. Returns SCCs in REVERSE topological order
// (callees before callers), which is the order in which chunks should be
// packed.
func tarjanSCC(n uint32, callees [][]uint32) [][]uint32 {
	const unvisited = -1
	indexCounter := 0
	stack := make([]uint32, 0, n)
	onStack := make([]bool, n)
	indices := make([]int, n)
	lowlinks := make([]int, n)
	for i := range indices {
		indices[i] = unvisited
	}
	var sccs [][]uint32

	// Iterative DFS to avoid blowing the Go goroutine stack for huge call
	// graphs (the recursive form of Tarjan trips the runtime's stack growth
	// for graphs in the tens of thousands of nodes).
	type frame struct {
		v    uint32
		i    int
		init bool
	}
	visit := func(start uint32) {
		dfs := []frame{{v: start}}
		for len(dfs) > 0 {
			top := &dfs[len(dfs)-1]
			v := top.v
			if !top.init {
				indices[v] = indexCounter
				lowlinks[v] = indexCounter
				indexCounter++
				stack = append(stack, v)
				onStack[v] = true
				top.init = true
			}
			progressed := false
			for top.i < len(callees[v]) {
				w := callees[v][top.i]
				top.i++
				if indices[w] == unvisited {
					dfs = append(dfs, frame{v: w})
					progressed = true
					break
				}
				if onStack[w] {
					if indices[w] < lowlinks[v] {
						lowlinks[v] = indices[w]
					}
				}
			}
			if progressed {
				continue
			}
			// All successors visited; finalize.
			if lowlinks[v] == indices[v] {
				var scc []uint32
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					scc = append(scc, w)
					if w == v {
						break
					}
				}
				sccs = append(sccs, scc)
			}
			dfs = dfs[:len(dfs)-1]
			if len(dfs) > 0 {
				parent := &dfs[len(dfs)-1]
				if lowlinks[v] < lowlinks[parent.v] {
					lowlinks[parent.v] = lowlinks[v]
				}
			}
		}
	}
	for v := uint32(0); v < n; v++ {
		if indices[v] == unvisited {
			visit(v)
		}
	}
	return sccs
}

// opRefFunc / opRefNull / opSelectT model reference- and select-with-
// type opcodes that don't otherwise appear in the legacy switch.
const (
	opRefNull byte = 0xd0
	opRefFunc byte = 0xd2
)

// skipImmediates advances r past the immediate operands of opcode op
// without doing any semantic decoding. Mirrors the instruction shapes
// the function compiler handles; opcodes whose immediate shape isn't
// modeled here return an error so the call-graph scan stays in sync
// with the instruction set the codegen actually emits. Silent fall-
// through used to drop real call edges (e.g. when an unknown opcode
// was followed by a `call` opcode value that skipImmediates then
// misread as raw bytes).
func (r *instrReader) skipImmediates(op byte) error {
	// 0xfc-prefixed extended ops.
	if op == opPrefixFC {
		sub, err := r.readU32()
		if err != nil {
			return err
		}
		switch sub {
		case 0, 1, 2, 3, 4, 5, 6, 7:
			// saturating-trunc family: no immediates.
			return nil
		case 8: // memory.init: dataIdx + reserved 0x00
			if _, err := r.readU32(); err != nil {
				return err
			}
			if _, err := r.readByte(); err != nil {
				return err
			}
			return nil
		case 9: // data.drop: dataIdx
			if _, err := r.readU32(); err != nil {
				return err
			}
			return nil
		case 10: // memory.copy: two reserved 0x00 bytes
			if _, err := r.readByte(); err != nil {
				return err
			}
			if _, err := r.readByte(); err != nil {
				return err
			}
			return nil
		case 11: // memory.fill: one reserved 0x00 byte
			if _, err := r.readByte(); err != nil {
				return err
			}
			return nil
		case 12: // table.init: elemIdx + tableIdx
			if _, err := r.readU32(); err != nil {
				return err
			}
			if _, err := r.readU32(); err != nil {
				return err
			}
			return nil
		case 13: // elem.drop: elemIdx
			if _, err := r.readU32(); err != nil {
				return err
			}
			return nil
		case 14: // table.copy: src tableIdx + dst tableIdx
			if _, err := r.readU32(); err != nil {
				return err
			}
			if _, err := r.readU32(); err != nil {
				return err
			}
			return nil
		case 15, 16, 17: // table.grow / table.size / table.fill: tableIdx
			if _, err := r.readU32(); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("unsupported 0xFC subop %d", sub)
	}
	// Branch / control with single-u32 operand.
	switch op {
	case opBr, opBrIf, opLocalGet, opLocalSet, opLocalTee,
		opGlobalGet, opGlobalSet, opCall:
		if _, err := r.readU32(); err != nil {
			return err
		}
		return nil
	case opRefFunc:
		// ref.func names a function whose address is taken; the call-
		// graph caller (scanDirectCalls) must read the index itself so
		// it can extend the live-function set with the target. Here we
		// only need to advance past the immediate.
		if _, err := r.readU32(); err != nil {
			return err
		}
		return nil
	case opRefNull:
		// reftype byte.
		if _, err := r.readByte(); err != nil {
			return err
		}
		return nil
	case opCallIndirect:
		// type idx + table idx
		if _, err := r.readU32(); err != nil {
			return err
		}
		if _, err := r.readU32(); err != nil {
			return err
		}
		return nil
	case opBrTable:
		labels, err := r.readVecU32()
		if err != nil {
			return err
		}
		_ = labels
		if _, err := r.readU32(); err != nil { // default
			return err
		}
		return nil
	case opBlock, opLoop, opIf:
		// blocktype: s33
		if _, err := r.readS33(); err != nil {
			return err
		}
		return nil
	case opElse, opEnd, opReturn, opUnreachable, opNop, opDrop, opSelect:
		return nil
	case opSelectT:
		// vec(valtype) — n + n bytes
		n, err := r.readU32()
		if err != nil {
			return err
		}
		for i := uint32(0); i < n; i++ {
			if _, err := r.readByte(); err != nil {
				return err
			}
		}
		return nil
	case opMemSize, opMemGrow:
		if _, err := r.readByte(); err != nil {
			return err
		}
		return nil
	case opI32Const:
		if _, err := r.readS32(); err != nil {
			return err
		}
		return nil
	case opI64Const:
		if _, err := r.readS64(); err != nil {
			return err
		}
		return nil
	case opF32Const:
		if _, err := r.readF32(); err != nil {
			return err
		}
		return nil
	case opF64Const:
		if _, err := r.readF64(); err != nil {
			return err
		}
		return nil
	}
	// Memory ops: align (u32) + offset (u32). Range covers
	// 0x28..0x40 (loads, stores, memory.size, memory.grow). The
	// MemSize/MemGrow cases above handle 0x3f/0x40 explicitly with
	// the single reserved byte; the switch returns before we reach
	// here for those opcodes.
	if op >= 0x28 && op <= 0x3e {
		if _, err := r.readU32(); err != nil {
			return err
		}
		if _, err := r.readU32(); err != nil {
			return err
		}
		return nil
	}
	// Numeric ops have no immediates (they all read from the stack).
	if op >= 0x45 && op <= 0xC4 {
		return nil
	}
	return fmt.Errorf("unknown opcode 0x%02x", op)
}
