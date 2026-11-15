package codegen

import (
	"go/ast"
	"go/token"

	"github.com/goccy/wasm2go/internal/ssa"
)

// Bounds checks
//
// wasm traps an access whose bytes reach memory.size or past it. How the
// generated code enforces that depends on what a linear memory is, which
// the build decides: memReserved, a constant of the generated package's
// memreserve_on.go / memreserve_off.go (internal/codegen/sharedimage).
//
// Where memory is a reservation (memReserved; 64-bit unix), the pages at
// and past memory.size are inaccessible and the reservation runs
// memReserveGuard bytes past its limit, the largest size the memory in it
// may have (see memreserve_on.go). An access that lands past memory.size
// faults, and the entry into guest code turns the fault into the trap
// (guestEntryGuard). The code only has to keep every access inside the
// reservation:
//
//   - wasm32: nothing to do. Every limit is 4 GiB, and the effective
//     address is a u32 address plus a u32 offset computed without
//     wrapping (memEA32, see memOffsetExpr), so it and the access's width
//     stay below 2^33 + 16, inside the reservation.
//   - memory64: `if uint64(base) >= mRes { goto trapMem }`, a comparison
//     and a branch. mRes is the limit, a function-level local read from
//     the memory slice's capacity where mBase is read and refreshed where
//     mBase is (memory.grow may move a memory to a larger reservation).
//     The address is then below the limit, and its static offset plus
//     width at most memReserveGuard keeps the access inside; a larger one
//     compares the address with the reservation's end less offset and
//     width instead. A constant address needs no test unless its access
//     ends past where every reservation ends (the declared minimum plus
//     the guard).
//
// Everywhere else (!memReserved) memory is a Go allocation with nothing
// past it to fault on, and every access compares its whole byte range with
// memory.size. A wasm32 access does so inside memEA32, whose 33-bit
// effective address cannot wrap: it traps when ea+size > memory.size.
// Its check is part of the address expression rather than a statement of
// its own so that the fused-region chase, which sees through memEA32,
// treats the access as it treats one without a check: the scalar chains
// of the SIMD kernels it absorbs keep the same bounds (the scalar load
// helpers check as memEA32 does). A memory64 access checks in a statement
// in front of it (L is memory.size):
//
//	if uint64(base) > mLim-K {
//		goto trapMem
//	}
//
// K is the static offset plus the access width, and the access is in
// bounds exactly when base + K <= L in unbounded arithmetic. Written as
// base > L-K the comparison cannot wrap: L never drops below the memory's
// declared minimum (memory only grows, and the constructors refuse a
// smaller size), so for every K up to that minimum L-K is exact, and base
// takes its full range — an address whose sum with the offset would wrap
// fails it like any other. A K above the minimum adds the test L < K. A
// constant address needs no check when its access ends within the
// minimum, and compares L with its end otherwise; so does an address that
// is a phi of constants, through the largest of them. A K that overflows
// names bytes no memory has: such an access traps unconditionally. L lives
// in mLim, a function-level local beside mBase, read from len(m.memory)
// where mBase is read and refreshed where mBase is, after every value
// that can run memory.grow; a shared memory grows under other agents at
// any moment, so its checks read memSize afresh.
//
// The generated code carries both forms (memory64: `if memReserved { ...
// } else { ... }`; wasm32: memEA32's `!memReserved &&`), and the compiler
// keeps the one the build selects: the constant folds the other away, in
// the pure Go and in the assembly captured from it alike. The captured
// assembly is the reservation form, so only builds where memory is a
// reservation use it (see pureFallbackTag).
//
// Atomic accesses emitted inline keep the exact check in both builds: it
// also traps a misaligned address, and traps with the atomic helpers'
// message.
//
// A check is left out where one that always runs before it implies it
// (memGuardCoverage): memory never shrinks, so an address proven in
// bounds stays in bounds for the rest of the function, calls and
// memory.grow included.
//
// The checks of a function share one trap block per trap kind, at the end
// of its body (trapStmt, memTrapTail). The trap helper never returns; the
// empty loop after it tells gc so, which keeps the cold path from saving
// and restoring what the accesses need (the shape the unreachable trap
// has too).

// memLimLocal is the name of the per-function copy of memory.size the
// exact checks compare with. Like mBase, it cannot collide with generated
// value names.
const memLimLocal = "mLim"

// memGuarded reports whether the module's accesses are checked: those of
// every translated module (unit tests that emit a body without a
// translator get none).
func (em *ssaEmitter) memGuarded() bool { return em.t != nil }

// memShared reports whether the module's memory is shared (threads).
func (em *ssaEmitter) memShared() bool { return em.t != nil && em.t.memoryIsShared() }

// memLimHoisted reports whether the function keeps memory.size in mLim.
func (em *ssaEmitter) memLimHoisted() bool {
	return em.memBaseHoisted && em.memGuarded() && !em.memShared()
}

// memSizeRead is `uint64(len(m.memory))`: memory.size of a memory that
// is not shared, which every constructor and memoryGrow keep equal to
// the slice's length.
func (em *ssaEmitter) memSizeRead() ast.Expr {
	return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{
		&ast.CallExpr{Fun: newID("len"), Args: []ast.Expr{em.fieldRef("memory")}},
	}}
}

// memLimitExpr is memory.size in bytes at an exact check.
func (em *ssaEmitter) memLimitExpr() ast.Expr {
	if em.memLimHoisted() {
		return newID(memLimLocal)
	}
	if em.memShared() {
		return &ast.CallExpr{Fun: &ast.SelectorExpr{X: em.fieldRef("memSize"), Sel: newID("Load")}}
	}
	return em.memSizeRead()
}

// memMinBytes is the memory's declared minimum in bytes: memory.size is
// never below it.
func (em *ssaEmitter) memMinBytes() uint64 {
	if em.t == nil || len(em.t.mod.Memories) == 0 {
		return 0
	}
	return em.t.mod.Memories[0].Limits.Min * 65536
}

// memResLocal is the name of the per-function copy of the reservation's
// limit the memory64 reservation checks compare with. Like mBase, it
// cannot collide with generated value names.
const memResLocal = "mRes"

// memResHoisted reports whether the function keeps the limit in mRes: a
// memory64 function that keeps mLim (a shared memory's limit never
// changes, but its checks read the field like its size).
func (em *ssaEmitter) memResHoisted() bool { return em.mem64 && em.memLimHoisted() }

// memResRead is `uint64(cap(m.memory)) - memReserveGuard`: the limit of
// the reservation the memory heads (see memreserve_on.go), read back from
// the slice every constructor and memory.grow give the reservation's
// length as capacity.
func (em *ssaEmitter) memResRead() ast.Expr {
	return &ast.BinaryExpr{
		X: &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{
			&ast.CallExpr{Fun: newID("cap"), Args: []ast.Expr{em.fieldRef("memory")}},
		}},
		Op: token.SUB,
		// A literal: the _consts detour (memConstExpr) serves addressing
		// immediates, and this is a subtraction.
		Y: uintLit(memReserveGuard),
	}
}

// memResExpr is the reservation's limit at a reservation check.
func (em *ssaEmitter) memResExpr() ast.Expr {
	if em.memResHoisted() {
		return newID(memResLocal)
	}
	return em.memResRead()
}

// memElemSize is the byte width of a load/store element type.
func memElemSize(elemType string) uint64 {
	switch elemType {
	case "uint8", "int8":
		return 1
	case "uint16", "int16":
		return 2
	case "uint32", "int32", "float32":
		return 4
	}
	return 8
}

// memConstExpr is a u64 constant operand of a check: small ones inline,
// large ones through the _consts table for the addressing-immediate
// reasons memOffsetExpr routes them there.
func (em *ssaEmitter) memConstExpr(c uint64) ast.Expr {
	if c >= largeConstThreshold && em.t != nil {
		return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{em.constsIndexExpr(c)}}
	}
	return uintLit(c)
}

// memAccessShape classifies v as an access the emitter renders inline —
// a plain load or store, or an atomic emitted inline (any other atomic
// goes through a helper that checks it) — with its width and static
// offset.
func (em *ssaEmitter) memAccessShape(v *ssa.Value) (size, off uint64, atomic, ok bool) {
	if len(v.Args) == 0 {
		return 0, 0, false, false
	}
	if spec, sok := loadSpec(v); sok {
		return memElemSize(spec.elemType), uint64(v.AuxInt), false, true
	}
	if spec, sok := storeSpec(v); sok {
		return memElemSize(spec.elemType), uint64(v.AuxInt), false, true
	}
	if v.Op == ssa.OpAtomicCall {
		name, _ := v.Aux.(string)
		if spec, o, aok := em.atomicInlineAccess(v, name); aok {
			return memElemSize(spec.elemType), o, true, true
		}
	}
	return 0, 0, false, false
}

// memConstAddr returns the address v is when it is a constant: an i64 one
// of a memory64, or the unsigned value of an i32 one.
func memConstAddr(v *ssa.Value) (uint64, bool) {
	if c := ssaConstBase64(v); c != nil {
		return uint64(c.AuxInt), true
	}
	if c := ssaConstBase(v); c != nil {
		return uint64(uint32(c.AuxInt)), true
	}
	return 0, false
}

// memAddrExpr renders an access's address as the u64 the checks compare:
// a memory64's i64, or a wasm32's i32 zero-extended.
func (em *ssaEmitter) memAddrExpr(v *ssa.Value, emitExpr func(*ssa.Value) (ast.Expr, error)) (ast.Expr, error) {
	e, err := emitExpr(v)
	if err != nil {
		return nil, err
	}
	if !em.mem64 {
		e = &ast.CallExpr{Fun: newID("uint32"), Args: []ast.Expr{e}}
	}
	return &ast.CallExpr{Fun: newID("uint64"), Args: []ast.Expr{e}}, nil
}

// memPlan is memGuardCoverage's verdict on one access.
type memPlan struct {
	// covered: a check before it implies its exact check.
	covered bool
	// k, when not zero, is the span past the address its exact check
	// covers, widened over the accesses after it.
	k uint64
	// resCovered: a check before it keeps it inside the reservation.
	resCovered bool
}

// memAccessGuard returns the statements that check v's byte range before
// v runs, or nil when v is no checked access or needs no check. See
// "Bounds checks" above.
func (em *ssaEmitter) memAccessGuard(v *ssa.Value, emitExpr func(*ssa.Value) (ast.Expr, error)) ([]ast.Stmt, error) {
	if !em.memGuarded() {
		return nil, nil
	}
	size, off, atomic, ok := em.memAccessShape(v)
	if !ok || (!em.mem64 && !atomic) {
		// A wasm32 plain access bounds itself: memOffsetExpr renders
		// it through memEA32.
		return nil, nil
	}
	plan := em.memGuardPlan[v.ID]
	exact, err := em.memExactGuard(v, size, off, atomic, plan, emitExpr)
	if err != nil {
		return nil, err
	}
	if atomic {
		return exact, nil
	}
	res, err := em.memReservedGuard(v, size, off, plan, emitExpr)
	if err != nil {
		return nil, err
	}
	reserved := em.helperRef("memReserved")
	switch {
	case res == nil && exact == nil:
		return nil, nil
	case res == nil:
		return []ast.Stmt{&ast.IfStmt{
			Cond: &ast.UnaryExpr{Op: token.NOT, X: reserved},
			Body: &ast.BlockStmt{List: exact},
		}}, nil
	case exact == nil:
		return []ast.Stmt{&ast.IfStmt{Cond: reserved, Body: &ast.BlockStmt{List: res}}}, nil
	}
	return []ast.Stmt{&ast.IfStmt{
		Cond: reserved,
		Body: &ast.BlockStmt{List: res},
		Else: &ast.BlockStmt{List: exact},
	}}, nil
}

// memReservedGuard is v's check where memory is a reservation: nothing
// for wasm32, a comparison with the reservation's limit for memory64. See
// "Bounds checks".
func (em *ssaEmitter) memReservedGuard(v *ssa.Value, size, off uint64, plan memPlan, emitExpr func(*ssa.Value) (ast.Expr, error)) ([]ast.Stmt, error) {
	if !em.mem64 {
		return nil, nil
	}
	k := off + size
	minBytes := em.memMinBytes()
	if c, ok := memConstAddr(v.Args[0]); ok {
		ea := c + off
		end := ea + size
		switch {
		case ea < c || end < ea:
			return []ast.Stmt{em.trapStmt("wasm_trap_mem_oob", newID("true"))}, nil
		case end <= minBytes+memReserveGuard:
			// Every reservation runs this far: its limit is at least
			// memory.size, which is at least the declared minimum.
			return nil, nil
		}
		return []ast.Stmt{em.trapStmt("wasm_trap_mem_oob", &ast.BinaryExpr{
			X: em.memResExpr(), Op: token.LSS, Y: em.memConstExpr(end - memReserveGuard),
		})}, nil
	}
	// A phi of constants whose access ends within the declared minimum is
	// in bounds, and its address below every limit (memGuardCoverage
	// relies on that).
	if hi, ok := memConstMax(v.Args[0], nil); ok && k >= off {
		if e := hi + k; e >= hi && e <= minBytes {
			return nil, nil
		}
	}
	if plan.resCovered {
		return nil, nil
	}
	a, err := em.memAddrExpr(v.Args[0], emitExpr)
	if err != nil {
		return nil, err
	}
	var oob ast.Expr
	switch {
	case k < off: // off+size overflowed
		oob = newID("true")
	case k <= memReserveGuard:
		oob = &ast.BinaryExpr{X: a, Op: token.GEQ, Y: em.memResExpr()}
	default:
		// The access must end within the reservation: a+k <= limit+guard.
		over := k - memReserveGuard
		oob = &ast.BinaryExpr{
			X:  &ast.BinaryExpr{X: em.memResExpr(), Op: token.LSS, Y: em.memConstExpr(over)},
			Op: token.LOR,
			Y: &ast.BinaryExpr{
				X:  a,
				Op: token.GTR,
				Y:  &ast.BinaryExpr{X: em.memResExpr(), Op: token.SUB, Y: em.memConstExpr(over)},
			},
		}
	}
	return []ast.Stmt{em.trapStmt("wasm_trap_mem_oob", oob)}, nil
}

// memExactGuard is v's check against memory.size (every inline atomic's,
// and every plain access's where memory is no reservation). See
// "Bounds checks".
func (em *ssaEmitter) memExactGuard(v *ssa.Value, size, off uint64, atomic bool, plan memPlan, emitExpr func(*ssa.Value) (ast.Expr, error)) ([]ast.Stmt, error) {
	trap := "wasm_trap_mem_oob"
	if atomic {
		trap = "wasm_trap_atomic_oob"
	}
	if plan.covered && !atomic {
		return nil, nil
	}
	// k is the checked span past the address: offset plus size, or what
	// memGuardCoverage widened it to.
	k := off + size
	if plan.k != 0 && !atomic {
		k = plan.k
	}
	minBytes := em.memMinBytes()
	if !atomic && k >= off {
		if hi, ok := memConstMax(v.Args[0], nil); ok {
			if end := hi + k; end >= hi && end <= minBytes {
				return nil, nil
			}
		}
	}
	var oob, misaligned ast.Expr
	if c, ok := memConstAddr(v.Args[0]); ok {
		ea := c + off
		end := ea + size
		switch {
		case ea < off || end < ea:
			oob = newID("true")
		case end > minBytes:
			oob = &ast.BinaryExpr{X: em.memLimitExpr(), Op: token.LSS, Y: em.memConstExpr(end)}
		}
		if atomic && ea&(size-1) != 0 {
			misaligned = newID("true")
		}
	} else {
		a, err := em.memAddrExpr(v.Args[0], emitExpr)
		if err != nil {
			return nil, err
		}
		if k < off { // off+size overflowed
			oob = newID("true")
		} else {
			oob = &ast.BinaryExpr{
				X:  a,
				Op: token.GTR,
				Y:  &ast.BinaryExpr{X: em.memLimitExpr(), Op: token.SUB, Y: em.memConstExpr(k)},
			}
			if k > minBytes {
				oob = &ast.BinaryExpr{
					X:  &ast.BinaryExpr{X: em.memLimitExpr(), Op: token.LSS, Y: em.memConstExpr(k)},
					Op: token.LOR,
					Y:  oob,
				}
			}
		}
		if atomic {
			// A second rendering of the address: AST nodes are not shared.
			ea, err := em.memAddrExpr(v.Args[0], emitExpr)
			if err != nil {
				return nil, err
			}
			if off != 0 {
				ea = &ast.BinaryExpr{X: ea, Op: token.ADD, Y: em.memConstExpr(off)}
			}
			misaligned = &ast.BinaryExpr{
				X:  &ast.ParenExpr{X: &ast.BinaryExpr{X: ea, Op: token.AND, Y: uintLit(size - 1)}},
				Op: token.NEQ,
				Y:  uintLit(0),
			}
		}
	}
	var stmts []ast.Stmt
	if oob != nil {
		stmts = append(stmts, em.trapStmt(trap, oob))
	}
	if misaligned != nil {
		stmts = append(stmts, em.trapStmt("wasm_trap_atomic_unaligned", misaligned))
	}
	return stmts, nil
}

// memConstMax reports whether the address v is a constant, or a phi
// (through copies and nested phis) all of whose incoming values are
// constants, and returns the largest of them as a u64 (an i32 one
// unsigned). seen guards the phi cycles of loops; nil starts a fresh walk.
func memConstMax(v *ssa.Value, seen map[ssa.ValueID]bool) (uint64, bool) {
	for v != nil && v.Op == ssa.OpCopy && len(v.Args) == 1 {
		v = v.Args[0]
	}
	if v == nil {
		return 0, false
	}
	switch v.Op {
	case ssa.OpConst64:
		return uint64(v.AuxInt), true
	case ssa.OpConst32:
		return uint64(uint32(v.AuxInt)), true
	case ssa.OpPhi:
		if seen == nil {
			seen = map[ssa.ValueID]bool{}
		}
		if seen[v.ID] {
			// A cycle adds no value the other incoming edges lack.
			return 0, true
		}
		seen[v.ID] = true
		var hi uint64
		for _, a := range v.Args {
			c, ok := memConstMax(a, seen)
			if !ok {
				return 0, false
			}
			hi = max(hi, c)
		}
		return hi, true
	}
	return 0, false
}

// memGuardSpan describes the bytes a checked access with a run-time
// address touches as root+lo .. root+hi: root is the address value with a
// small constant addend peeled off (lo, which the guest's add put there),
// hi is lo plus the static offset and the access width. ok is false for
// anything that is no such access, or whose span does not fit.
func (em *ssaEmitter) memGuardSpan(v *ssa.Value) (root ssa.ValueID, lo, hi uint64, atomic, ok bool) {
	size, off, atomic, ok := em.memAccessShape(v)
	if !ok || off >= 1<<32 || (!em.mem64 && !atomic) {
		return 0, 0, 0, false, false
	}
	base := v.Args[0]
	for base != nil && base.Op == ssa.OpCopy && len(base.Args) == 1 {
		base = base.Args[0]
	}
	if base == nil {
		return 0, 0, 0, false, false
	}
	if _, isConst := memConstAddr(base); isConst {
		return 0, 0, 0, false, false
	}
	add, cst := ssa.OpAdd64, ssa.OpConst64
	if !em.mem64 {
		add, cst = ssa.OpAdd32, ssa.OpConst32
	}
	if base.Op == add && len(base.Args) == 2 {
		for i, a := range base.Args {
			for a != nil && a.Op == ssa.OpCopy && len(a.Args) == 1 {
				a = a.Args[0]
			}
			if a != nil && a.Op == cst && a.AuxInt >= 0 && a.AuxInt < 1<<31 {
				if x := base.Args[1-i]; x != nil {
					if _, xConst := memConstAddr(x); !xConst {
						return x.ID, uint64(a.AuxInt), uint64(a.AuxInt) + off + size, atomic, true
					}
				}
			}
		}
	}
	return base.ID, 0, off + size, atomic, true
}

// memGuardLookahead bounds how many values after a load memGuardCoverage
// looks at to widen the load's exact check.
const memGuardLookahead = 256

// memGuardCoverage plans the checks of f's accesses with a run-time
// address, for both builds (see "Bounds checks").
//
// Exact checks. An access needs none when a check that runs before it on
// every path implies its own: one of an access in a dominating position
// (an earlier value of the same block, or any value of a dominating block)
// on the same root address. The covering check proved root+lo_u ..
// root+hi_u in bounds, in the notation of memGuardSpan; memory only grows,
// so that still holds at the covered access, calls and memory.grow
// included. A span lo_v..hi_v is then in bounds when lo_v ≥ lo_u and hi_v
// ≤ hi_u: either root+lo_u did not wrap and root+lo_v is root+lo_u moved up
// by lo_v-lo_u within the proven range, or it wrapped and root+lo_v wrapped
// the same way (lo_v ≥ lo_u) and lies within the same proven range. An
// access whose addend is below the covering one's is not covered: its
// address may not have wrapped where the covering one's did.
//
// A load's exact check is widened over the accesses that follow it in its
// block on the same root, with an addend at or above its own, up to the
// next value with a side effect (included when it is such an access, a
// store): their checks are then implied. Trapping at the load for a later
// access is not observable — nothing between them writes or calls, and
// every plain access traps with the same message — and when the widened
// check fails, the original program traps by the last of them: the access
// that reaches furthest is out of bounds, or (its address having wrapped
// where this one's did not) this one is.
//
// Reservation checks (memory64). Every check of an access proves its
// address root+lo_u below the reservation's limit (the comparison with
// mRes, the comparison with the reservation's end, a phi of constants
// within the declared minimum, an exact check: memory.size never exceeds
// the limit), and a limit only grows (memory.grow moves a memory to a
// larger reservation, never a smaller one). An access on the same root
// with lo_v ≥ lo_u is then root+lo_u moved up by lo_v-lo_u, whether or not
// the sums wrapped, and stays inside the reservation when lo_v-lo_u plus
// its offset and width is at most memReserveGuard.
//
// Atomic accesses cover others but keep their own exact checks, which
// include alignment and trap with their own message. Functions with try
// regions keep every check.
func (em *ssaEmitter) memGuardCoverage(f *ssa.Func) map[ssa.ValueID]memPlan {
	if !em.memGuarded() || f.Entry == nil || len(f.TryRegions) > 0 {
		return nil
	}
	idom := ssa.Dominators(f)
	children := map[ssa.BlockID][]*ssa.Block{}
	for _, b := range f.Blocks {
		if d := idom[b.ID]; d != nil && b != f.Entry {
			children[d.ID] = append(children[d.ID], b)
		}
	}
	plans := map[ssa.ValueID]memPlan{}
	type span struct{ lo, hi uint64 }
	exact := map[ssa.ValueID][]span{}
	reserved := map[ssa.ValueID][]uint64{} // lo of each check on the root
	var walk func(b *ssa.Block)
	walk = func(b *ssa.Block) {
		for i, v := range b.Values {
			root, lo, hi, atomic, ok := em.memGuardSpan(v)
			if !ok {
				continue
			}
			plan := plans[v.ID]
			if !atomic {
				for _, l := range reserved[root] {
					if lo >= l && lo-l+hi-lo <= memReserveGuard {
						plan.resCovered = true
						break
					}
				}
				for _, s := range exact[root] {
					if lo >= s.lo && hi <= s.hi {
						plan.covered = true
						break
					}
				}
			}
			if !plan.covered {
				own := hi
				// A store is a side effect itself: a trap moved in
				// front of it would undo its write. Only a load's check
				// widens. The look-ahead is bounded so that a long block
				// of loads costs linear time.
				rest := b.Values[i+1:]
				if len(rest) > memGuardLookahead {
					rest = rest[:memGuardLookahead]
				}
				for _, w := range rest {
					if atomic || v.HasSideEffect() {
						break
					}
					if wr, wlo, whi, watomic, wok := em.memGuardSpan(w); wok && !watomic && wr == root && wlo >= lo {
						hi = max(hi, whi)
					}
					if w.HasSideEffect() {
						break
					}
				}
				if hi != own {
					plan.k = hi - lo
				}
				exact[root] = append(exact[root], span{lo, hi})
			}
			if !plan.resCovered {
				reserved[root] = append(reserved[root], lo)
			}
			plans[v.ID] = plan
		}
		for _, c := range children[b.ID] {
			walk(c)
		}
		// Undo this block's additions: each of its accesses added at most
		// one entry to each table of its root, and a root's last entries
		// are this block's.
		for _, v := range b.Values {
			root, _, _, _, ok := em.memGuardSpan(v)
			if !ok {
				continue
			}
			plan := plans[v.ID]
			if !plan.covered {
				exact[root] = exact[root][:len(exact[root])-1]
			}
			if !plan.resCovered {
				reserved[root] = reserved[root][:len(reserved[root])-1]
			}
		}
	}
	walk(f.Entry)
	return plans
}

// memTrapKinds are the traps of the checks, each with the label of the
// function's one block that raises it, in the order those blocks close the
// function (memTrapTail).
var memTrapKinds = []struct{ helper, label string }{
	{"wasm_trap_mem_oob", "trapMem"},
	{"wasm_trap_atomic_oob", "trapAtomic"},
	{"wasm_trap_atomic_unaligned", "trapUnaligned"},
}

// trapStmt renders `if cond { goto <the trap's label> }`. Every check of a
// function shares one trap block per kind (memTrapTail) instead of
// carrying a call of its own: the cold path costs one branch per check,
// and gc lays the check out to fall through to the access (with a block
// per check, gc's branch heuristics take the call that never returns for
// the likely path and fall through into it).
func (em *ssaEmitter) trapStmt(trap string, cond ast.Expr) ast.Stmt {
	label := ""
	for _, k := range memTrapKinds {
		if k.helper == trap {
			label = k.label
		}
	}
	if em.memTrapsUsed == nil {
		em.memTrapsUsed = map[string]bool{}
	}
	em.memTrapsUsed[trap] = true
	return &ast.IfStmt{
		Cond: cond,
		Body: &ast.BlockStmt{List: []ast.Stmt{&ast.BranchStmt{Tok: token.GOTO, Label: newID(label)}}},
	}
}

// memTrapTail renders the trap blocks the function's checks branch to,
// appended at the end of its body:
//
//	trapMem:
//		wasm_trap_mem_oob()
//		for {
//		}
//
// At the top level of the body, each label is in scope of every check,
// however deeply nested; no variable is declared at the top level after
// the first check (the emitters declare their values at the head of the
// body), so no goto jumps into a declaration's scope.
func (em *ssaEmitter) memTrapTail() []ast.Stmt {
	var out []ast.Stmt
	for _, k := range memTrapKinds {
		if !em.memTrapsUsed[k.helper] {
			continue
		}
		out = append(out,
			&ast.LabeledStmt{Label: newID(k.label), Stmt: &ast.ExprStmt{X: &ast.CallExpr{Fun: em.helperRef(k.helper)}}},
			&ast.ForStmt{Body: &ast.BlockStmt{}})
	}
	return out
}
