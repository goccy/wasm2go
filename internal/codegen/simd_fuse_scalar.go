package codegen

// Scalar-chain chasing for fused regions.
//
// The float arguments of a fused window are typically not free
// variables: quantized kernels compute them per block as
//
//	v119 = int32(*(*uint16)(unsafe.Add(mBase, uint32(v102))))
//	v122 = *(*float32)(unsafe.Add(mBase, uint32(v119<<2)+uint32(_consts[k])))
//	...   F32_mul(v122, v126)  ->  f32x4_splat
//
// Left as interveners, these chains dominate the loop: the splice
// clobbers every register, so gc reloads mBase, the table base and
// the block pointers from the stack for every lookup. Chasing folds
// the whole chain into the region as scalar-class nodes
// (scalar_i32_load16_u / scalar_i32_shl / scalar_i32_add /
// scalar_f32_load / scalar_f32_mul), the consumed interveners are
// dropped, and the splicers evaluate the chain once in registers.
//
// The chase is exact, not heuristic: every accepted shape is one the
// emitter itself produces (the unchecked scalar deref form, the
// masked-shift form, u32-wrapped adds), and anything else falls back
// to the plain float-argument path unchanged.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"strings"
	"sync/atomic"

	"github.com/goccy/wasm2go/internal/simdfuse"
)

// chaseSplatFloat tries to internalize a float32 splat argument as a
// scalar node chain. Returns the ArgNode argument on success. Only
// window fusion chases (interDef is nil otherwise): single-call trees
// have no intervener definitions to resolve idents through.
//
// The chase is TRANSACTIONAL: a failure partway (an ident with no
// window definition, a capacity limit) must not leave orphan nodes,
// stray scalar parameters or inflated consumption counts behind — the
// builder state is snapshotted and restored on failure.
func (fb *fusedTreeBuilder) chaseSplatFloat(e ast.Expr) (simdfuse.Arg, bool) {
	if fb.interDef == nil {
		return simdfuse.Arg{}, false
	}
	snap := fb.snapshotChase()
	idx, ok := fb.chaseF32(e)
	if !ok {
		fb.restoreChase(snap)
		return simdfuse.Arg{}, false
	}
	return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
}

// chaseSnap captures every piece of builder state a chase mutates.
// The shape key is NOT captured: window fusion rebuilds it from the
// final node list in scheduleNodes, so a dirty key is never observed.
type chaseSnap struct {
	nodes, scalars int
	scalarDedup    map[string]int
	chaseUses      map[string]int
	chaseCache     map[string]int
	chaseReads     map[string]bool
	chaseExpanded  map[string]bool
}

func copyMapInt(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	c := make(map[string]int, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func (fb *fusedTreeBuilder) snapshotChase() chaseSnap {
	var reads map[string]bool
	if fb.chaseReads != nil {
		reads = make(map[string]bool, len(fb.chaseReads))
		for k, v := range fb.chaseReads {
			reads[k] = v
		}
	}
	var expanded map[string]bool
	if fb.chaseExpanded != nil {
		expanded = make(map[string]bool, len(fb.chaseExpanded))
		for k, v := range fb.chaseExpanded {
			expanded[k] = v
		}
	}
	return chaseSnap{
		nodes: len(fb.nodes), scalars: len(fb.scalars),
		scalarDedup:   copyMapInt(fb.scalarDedup),
		chaseUses:     copyMapInt(fb.chaseUses),
		chaseCache:    copyMapInt(fb.chaseCache),
		chaseReads:    reads,
		chaseExpanded: expanded,
	}
}

func (fb *fusedTreeBuilder) restoreChase(s chaseSnap) {
	fb.nodes = fb.nodes[:s.nodes]
	fb.nodeVals = fb.nodeVals[:s.nodes]
	fb.scalars = fb.scalars[:s.scalars]
	fb.scalarOwner = fb.scalarOwner[:s.scalars]
	fb.scalarSrc = fb.scalarSrc[:s.scalars]
	fb.scalarDedup = s.scalarDedup
	fb.chaseUses = s.chaseUses
	fb.chaseCache = s.chaseCache
	fb.chaseReads = s.chaseReads
	fb.chaseExpanded = s.chaseExpanded
}

// chaseF32 resolves a float32 expression to a ClassF32 node index.
func (fb *fusedTreeBuilder) chaseF32(e ast.Expr) (int, bool) {
	switch x := e.(type) {
	case *ast.CallExpr:
		if n := helperName(x.Fun); (n == "F32_mul" || n == "f32_mul") && len(x.Args) == 2 {
			l, lok := fb.chaseF32(x.Args[0])
			if !lok {
				return 0, false
			}
			r, rok := fb.chaseF32(x.Args[1])
			if !rok {
				return 0, false
			}
			return fb.addScalarNode("scalar_f32_mul", []simdfuse.Arg{
				{Kind: simdfuse.ArgNode, Index: l},
				{Kind: simdfuse.ArgNode, Index: r},
			})
		}
		return 0, false
	case *ast.StarExpr:
		addr, is64, ok := matchMemDeref(x, "float32")
		if !ok {
			return 0, false
		}
		if is64 {
			fb.addr64 = true
		}
		aarg, ok := fb.chaseAddr(addr)
		if !ok {
			return 0, false
		}
		return fb.addScalarNode("scalar_f32_load", []simdfuse.Arg{aarg})
	case *ast.Ident:
		// f32 chains are NOT cached across uses: their terminals live in
		// low scratch registers only until the immediately-following
		// consumer, so a value needed twice is recomputed (pure, cheap)
		// with its own chain per consumer.
		if fb.interDef == nil {
			return 0, false
		}
		def, ok := fb.interDef[x.Name]
		if !ok {
			return 0, false
		}
		idx, ok := fb.chaseF32(def.Rhs[0])
		if !ok {
			return 0, false
		}
		if fb.chaseUses == nil {
			fb.chaseUses = map[string]int{}
		}
		fb.chaseUses[x.Name]++
		return idx, true
	}
	return 0, false
}

// chaseI32 resolves an int32/uint32 scalar expression to an Arg: a
// descriptor constant, a (deduplicated) scalar parameter, or a
// ClassI32 node. u32/i32 conversions are identities mod 2^32, exactly
// like the wasm ops the emitter lowered from.
func (fb *fusedTreeBuilder) chaseI32(e ast.Expr) (simdfuse.Arg, bool) {
	if fb.chaseTrace {
		a, ok := fb.chaseI32Inner(e)
		if !ok {
			fuseDebugf("chaseTRACE fail: %T %s", e, exprDebugString(e))
		}
		return a, ok
	}
	return fb.chaseI32Inner(e)
}

// chaseLoad16Deref matches a `*(*uint16)(...)` linear-memory read and
// registers it as a scalar_i32_load16_u node over the chased address.
func (fb *fusedTreeBuilder) chaseLoad16Deref(inner *ast.StarExpr) (simdfuse.Arg, bool) {
	addr, is64, mok := matchMemDeref(inner, "uint16")
	if !mok {
		if fb.chaseTrace {
			var buf bytes.Buffer
			if err := printer.Fprint(&buf, token.NewFileSet(), inner); err == nil {
				fuseDebugf("chaseTRACE load16 deref mismatch: %s", buf.String())
			}
		}
		return simdfuse.Arg{}, false
	}
	if is64 {
		fb.addr64 = true
	}
	aarg, aok := fb.chaseAddr(addr)
	if !aok {
		return simdfuse.Arg{}, false
	}
	if fb.chaseTrace {
		fuseDebugf("chaseTRACE load16 addr %s -> kind=%d idx=%d const=%d", exprDebugString(addr), aarg.Kind, aarg.Index, aarg.Const)
	}
	idx, nok := fb.addScalarNode("scalar_i32_load16_u", []simdfuse.Arg{aarg})
	if !nok {
		return simdfuse.Arg{}, false
	}
	return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
}

// chaseNarrowExtract16 rewrites `(wideload >> C) & 0xffff` (and the
// C==0 form `wideload & 0xffff`) into a scalar_i32_load16_u at the
// load's address plus C/8 bytes. Linear memory and every supported
// host are little-endian, so a 16-bit field of a wider aligned-free
// load is exactly the 16-bit load at the byte-shifted address. This
// is the form clang produces when it packs several adjacent f16
// scale reads into one 32/64-bit load.
func (fb *fusedTreeBuilder) chaseNarrowExtract16(x *ast.BinaryExpr) (simdfuse.Arg, bool) {
	if x.Op != token.AND {
		return simdfuse.Arg{}, false
	}
	// The mask constant arrives wrapped in the pointer-width
	// conversion (`int64(65535)`) on memory64; constValueOf
	// deliberately rejects 64-bit wrappers, so unwrap here where the
	// extract-width semantics make it safe.
	unwrapConv := func(e ast.Expr) ast.Expr {
		for {
			if c, ok := e.(*ast.CallExpr); ok && len(c.Args) == 1 {
				if id, ok := c.Fun.(*ast.Ident); ok &&
					(id.Name == "int32" || id.Name == "uint32" || id.Name == "int64" || id.Name == "uint64") {
					e = c.Args[0]
					continue
				}
			}
			return e
		}
	}
	valExpr, maskExpr := x.X, x.Y
	mask, mok := fb.constValueOf(unwrapConv(maskExpr))
	if !mok {
		valExpr, maskExpr = maskExpr, valExpr
		mask, mok = fb.constValueOf(unwrapConv(maskExpr))
	}
	if !mok || uint32(mask) != 0xffff {
		return simdfuse.Arg{}, false
	}
	shift := int32(0)
	if sh, ok := valExpr.(*ast.BinaryExpr); ok && sh.Op == token.SHR {
		s, sok := matchShiftConst(sh.Y, fb)
		if !sok {
			return simdfuse.Arg{}, false
		}
		shift = s
		valExpr = sh.X
	}
	if shift%8 != 0 || shift < 0 {
		return simdfuse.Arg{}, false
	}
	// Unwrap width conversions and single-def locals down to the
	// memory deref itself, remembering which locals the rewrite
	// consumes so intervener accounting sees them as absorbed.
	var consumed []string
	for {
		if conv, ok := valExpr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
			if id, ok := conv.Fun.(*ast.Ident); ok &&
				(id.Name == "int32" || id.Name == "uint32" || id.Name == "int64" || id.Name == "uint64") {
				valExpr = conv.Args[0]
				continue
			}
		}
		if id, ok := valExpr.(*ast.Ident); ok {
			def, dok := fb.interDef[id.Name]
			if !dok || len(def.Rhs) != 1 {
				return simdfuse.Arg{}, false
			}
			consumed = append(consumed, id.Name)
			valExpr = def.Rhs[0]
			continue
		}
		break
	}
	star, ok := valExpr.(*ast.StarExpr)
	if !ok {
		return simdfuse.Arg{}, false
	}
	var (
		addr ast.Expr
		is64 bool
		bits int32
	)
	for _, w := range []struct {
		typ  string
		bits int32
	}{{"uint64", 64}, {"int64", 64}, {"uint32", 32}, {"int32", 32}} {
		if a, i64, mok := matchMemDeref(star, w.typ); mok {
			addr, is64, bits = a, i64, w.bits
			break
		}
	}
	if addr == nil || shift+16 > bits {
		return simdfuse.Arg{}, false
	}
	aarg, aok := fb.chaseAddr(addr)
	if !aok {
		return simdfuse.Arg{}, false
	}
	if off := shift / 8; off != 0 {
		switch aarg.Kind {
		case simdfuse.ArgConst, simdfuse.ArgSum:
			aarg.Const += off
		case simdfuse.ArgScalar:
			aarg = simdfuse.Arg{Kind: simdfuse.ArgSum, Index: aarg.Index, Const: off}
		default:
			idx, ok := fb.addScalarNode("scalar_i32_add", []simdfuse.Arg{aarg, {Kind: simdfuse.ArgConst, Const: off}})
			if !ok {
				return simdfuse.Arg{}, false
			}
			aarg = simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}
		}
	}
	if is64 {
		fb.addr64 = true
	}
	idx, nok := fb.addScalarNode("scalar_i32_load16_u", []simdfuse.Arg{aarg})
	if !nok {
		return simdfuse.Arg{}, false
	}
	if fb.chaseUses == nil {
		fb.chaseUses = map[string]int{}
	}
	for _, name := range consumed {
		fb.chaseUses[name]++
	}
	if fb.chaseTrace {
		fuseDebugf("chaseTRACE narrow16: shift=%d bits=%d addr kind=%d idx=%d const=%d", shift, bits, aarg.Kind, aarg.Index, aarg.Const)
	}
	return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
}

func (fb *fusedTreeBuilder) chaseI32Inner(e ast.Expr) (simdfuse.Arg, bool) {
	if c, ok := fb.constValueOf(e); ok {
		return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: c}, true
	}
	switch x := e.(type) {
	case *ast.CallExpr:
		// int32/uint32 (and, on memory64, int64/uint64) conversions are
		// identities for chasing — the address arithmetic runs at
		// pointer width — and the u16 load form.
		if id, ok := x.Fun.(*ast.Ident); ok && len(x.Args) == 1 &&
			(id.Name == "int32" || id.Name == "uint32" || id.Name == "int64" || id.Name == "uint64") {
			if inner, ok := x.Args[0].(*ast.StarExpr); ok {
				if arg, lok := fb.chaseLoad16Deref(inner); lok {
					return arg, true
				}
			}
			return fb.chaseI32(x.Args[0])
		}
		// _consts[k] and other pure package-level reads ride as
		// deduplicated scalar parameters via the IndexExpr case below
		// once unwrapped; anything else is not chaseable.
		return simdfuse.Arg{}, false
	case *ast.StarExpr:
		// A bare u16 memory deref (no conversion wrapper): the guest
		// assigns `*(*uint16)(...)` straight to a wider local. Gated on
		// wideChase so ordinary fusion keeps its historical shapes.
		if !fb.wideChase {
			return simdfuse.Arg{}, false
		}
		return fb.chaseLoad16Deref(x)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.ADD:
			l, lok := fb.chaseI32(x.X)
			if !lok {
				return simdfuse.Arg{}, false
			}
			r, rok := fb.chaseI32(x.Y)
			if !rok {
				return simdfuse.Arg{}, false
			}
			// Const folding keeps shapes canonical and saves nodes.
			if l.Kind == simdfuse.ArgConst && r.Kind == simdfuse.ArgConst {
				return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: l.Const + r.Const}, true
			}
			if fb.wideChase {
				// The gather rewrite needs canonical base+const forms
				// to prove lane adjacency; gated so ordinary fusion
				// keeps its historical shapes byte-identical.
				if l.Kind == simdfuse.ArgConst {
					l, r = r, l
				}
				if r.Kind == simdfuse.ArgConst {
					switch l.Kind {
					case simdfuse.ArgScalar:
						return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: r.Const}, true
					case simdfuse.ArgSum:
						return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: l.Const + r.Const}, true
					}
				}
			}
			idx, ok := fb.addScalarNode("scalar_i32_add", []simdfuse.Arg{l, r})
			if !ok {
				return simdfuse.Arg{}, false
			}
			return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
		case token.SHL:
			s, sok := matchShiftConst(x.Y, fb)
			if !sok {
				fuseDebugf("chaseI32 SHL: amount not const: %s", exprDebugString(x.Y))
				return simdfuse.Arg{}, false
			}
			v, vok := fb.chaseI32(x.X)
			if !vok {
				fuseDebugf("chaseI32 SHL: operand fail: %s", exprDebugString(x.X))
				return simdfuse.Arg{}, false
			}
			idx, ok := fb.addScalarNode("scalar_i32_shl", []simdfuse.Arg{v, {Kind: simdfuse.ArgConst, Const: s}})
			if !ok {
				fuseDebugf("chaseI32 SHL: node cap")
				return simdfuse.Arg{}, false
			}
			return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
		case token.AND:
			if !fb.wideChase {
				return simdfuse.Arg{}, false
			}
			if arg, ok := fb.chaseNarrowExtract16(x); ok {
				return arg, true
			}
			// Identity-mask elimination for the f16 gather chase: the
			// guest masks a load16_u result before shifting it into a
			// table index, but the load's value range is [0, 0xffff], so
			// any mask whose low 16 bits are all ones leaves the value
			// unchanged. Gated on wideChase so ordinary fusion keeps its
			// historical shapes.
			l, lok := fb.chaseI32(x.X)
			if !lok {
				return simdfuse.Arg{}, false
			}
			r, rok := fb.chaseI32(x.Y)
			if !rok {
				return simdfuse.Arg{}, false
			}
			if l.Kind == simdfuse.ArgConst {
				l, r = r, l
			}
			if r.Kind == simdfuse.ArgConst && l.Kind == simdfuse.ArgNode &&
				fb.nodes[l.Index].Op == "scalar_i32_load16_u" &&
				uint32(r.Const)&0xffff == 0xffff {
				return l, true
			}
			return simdfuse.Arg{}, false
		}
		return simdfuse.Arg{}, false
	case *ast.IndexExpr:
		// A package-level constant-table read (`_consts[k]`): passes as
		// one deduplicated scalar parameter, evaluated at the call site.
		if base, ok := x.X.(*ast.Ident); ok && strings.HasPrefix(base.Name, "_") {
			if _, isLit := x.Index.(*ast.BasicLit); isLit {
				return fb.addChaseScalarArg(&ast.CallExpr{Fun: newID("int32"), Args: []ast.Expr{x}}, "x:"+exprKeyString(x))
			}
		}
		return simdfuse.Arg{}, false
	case *ast.Ident:
		if fb.wideChase && (fb.interDef == nil || fb.interDef[x.Name] == nil) {
			// Not an intervener: recompute a function-wide
			// single-assignment definition in-region. No consumption
			// bookkeeping — the original definition stays (it may have
			// other readers); the chase grammar only admits pure
			// shapes, so recomputation is safe under the runtime's
			// no-concurrent-writer contract the intervener chase
			// already relies on.
			if fb.sc != nil && fb.sc.defBind != nil && !fb.chaseVisiting[x.Name] {
				if def, isDef := fb.sc.defBind[x.Name]; isDef && len(def.Rhs) == 1 {
					if fb.chaseVisiting == nil {
						fb.chaseVisiting = map[string]bool{}
					}
					fb.chaseVisiting[x.Name] = true
					a, aok := fb.chaseI32(def.Rhs[0])
					delete(fb.chaseVisiting, x.Name)
					if aok {
						return a, true
					}
				}
			}
		}
		if fb.interDef != nil {
			if def, isDef := fb.interDef[x.Name]; isDef && !fb.chaseVisiting[x.Name] {
				// No caching across uses: every consumer gets its own
				// self-contained chain, so no scalar value ever has to
				// survive across an unrelated vector node body (whose
				// cores clobber the low scratch registers).
				//
				// The visiting mark breaks self-referential definitions
				// (a loop-carried `v = v + 4`), which would otherwise
				// recurse without bound; on re-entry the name is not
				// chaseable and stays an intervener.
				if fb.chaseVisiting == nil {
					fb.chaseVisiting = map[string]bool{}
				}
				fb.chaseVisiting[x.Name] = true
				a, aok := fb.chaseI32(def.Rhs[0])
				delete(fb.chaseVisiting, x.Name)
				if !aok || a.Kind != simdfuse.ArgNode {
					// Only node-producing definitions are worth
					// consuming; a plain alias stays an intervener.
					return simdfuse.Arg{}, false
				}
				// Count this definition's textual consumption ONCE
				// per trial: a def dropped at commit removes exactly
				// one occurrence of each name ITS body reads, no
				// matter how many consumers re-chased the same chain.
				// Counting per re-chase overcounted (two loads
				// chasing v311 bumped v309 twice), made the
				// fully-consumed proof hold spuriously, and dropped a
				// definition a loop-tail bump still read — leaving
				// the bump reading the variable's zero value.
				if fb.chaseExpanded == nil {
					fb.chaseExpanded = map[string]bool{}
				}
				if !fb.chaseExpanded[x.Name] {
					fb.chaseExpanded[x.Name] = true
					if fb.chaseUses == nil {
						fb.chaseUses = map[string]int{}
					}
					fb.chaseUses[x.Name]++
				}
				return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: a.Index}, true
			}
		}
		// A window-internal value (another candidate's result) must
		// never leak into a chained scalar argument: after fusion it
		// has no pre-call definition, so the argument would read
		// garbage. Address chains hit this shape routinely (an
		// extract_lane result feeding a load address); refusing here
		// lets the caller fall back to the pair/opaque forms with the
		// original semantics.
		if _, isCand := fb.varNode[x.Name]; isCand {
			return simdfuse.Arg{}, false
		}
		return fb.addChaseScalarArg(x, x.Name)
	}
	return simdfuse.Arg{}, false
}

// chaseAddr resolves a scalar-load address expression. Same grammar
// as chaseI32, plus the base+const fold into ArgSum that keeps a
// whole lookup chain at one scalar parameter. Each operand is chased
// exactly once — a re-chase would double-count consumptions and
// duplicate nodes.
func (fb *fusedTreeBuilder) chaseAddr(e ast.Expr) (simdfuse.Arg, bool) {
	// memory64 offsets often subtract a small struct-field constant
	// (`ptr - int64(2)`); fold it as an ArgSum with a negated const.
	// SUB never appears in a wasm32 address (the emitter folds negative
	// offsets into the memarg), so this is gated to keep the wasm32
	// path byte-identical.
	if bin, ok := e.(*ast.BinaryExpr); ok && fb.addr64 && bin.Op == token.SUB {
		if c, cok := fb.addrConstValue(bin.Y); cok {
			l, lok := fb.chaseI32(bin.X)
			if !lok {
				return simdfuse.Arg{}, false
			}
			switch l.Kind {
			case simdfuse.ArgScalar:
				return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: -c}, true
			case simdfuse.ArgConst:
				return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: l.Const - c}, true
			}
			idx, ok := fb.addScalarNode("scalar_i32_add", []simdfuse.Arg{l, {Kind: simdfuse.ArgConst, Const: -c}})
			if !ok {
				return simdfuse.Arg{}, false
			}
			return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
		}
	}
	if bin, ok := e.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		l, lok := fb.chaseI32(bin.X)
		if !lok {
			return simdfuse.Arg{}, false
		}
		// wasm32 keeps its exact original const matcher; memory64 needs
		// the int64-aware one for `int64(...)`-wrapped offsets.
		addrConst := func(e ast.Expr) (int32, bool) {
			if fb.addr64 {
				return fb.addrConstValue(e)
			}
			return fb.constValueOf(stripU32(e))
		}
		if c, cok := addrConst(bin.Y); cok {
			switch l.Kind {
			case simdfuse.ArgScalar:
				return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: c}, true
			case simdfuse.ArgConst:
				return simdfuse.Arg{Kind: simdfuse.ArgConst, Const: l.Const + c}, true
			case simdfuse.ArgSum:
				if fb.wideChase {
					return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: l.Const + c}, true
				}
			}
			idx, ok := fb.addScalarNode("scalar_i32_add", []simdfuse.Arg{l, {Kind: simdfuse.ArgConst, Const: c}})
			if !ok {
				return simdfuse.Arg{}, false
			}
			return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
		}
		r, rok := fb.chaseI32(bin.Y)
		if !rok {
			return simdfuse.Arg{}, false
		}
		if fb.wideChase {
			if l.Kind == simdfuse.ArgConst {
				l, r = r, l
			}
			if r.Kind == simdfuse.ArgConst {
				switch l.Kind {
				case simdfuse.ArgScalar:
					return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: r.Const}, true
				case simdfuse.ArgSum:
					return simdfuse.Arg{Kind: simdfuse.ArgSum, Index: l.Index, Const: l.Const + r.Const}, true
				}
			}
		}
		idx, ok := fb.addScalarNode("scalar_i32_add", []simdfuse.Arg{l, r})
		if !ok {
			return simdfuse.Arg{}, false
		}
		return simdfuse.Arg{Kind: simdfuse.ArgNode, Index: idx}, true
	}
	return fb.chaseI32(e)
}

// addScalarNode appends a scalar-class node, keyed like every other
// member.
func (fb *fusedTreeBuilder) addScalarNode(op string, args []simdfuse.Arg) (int, bool) {
	if len(fb.nodes) >= fusedMaxNodes {
		if fb.failWhy == "" {
			fb.failWhy = "node cap (scalar chain)"
		}
		return 0, false
	}
	for _, a := range args {
		switch a.Kind {
		case simdfuse.ArgNode:
			fmt.Fprintf(&fb.key, "n%d,", a.Index)
		case simdfuse.ArgScalar:
			fmt.Fprintf(&fb.key, "s%d,", a.Index)
		case simdfuse.ArgSum:
			fmt.Fprintf(&fb.key, "m%d+%d,", a.Index, a.Const)
		default:
			fmt.Fprintf(&fb.key, "c%d,", a.Const)
		}
	}
	fb.nodes = append(fb.nodes, simdfuse.Node{Op: op, Args: args})
	fb.nodeVals = append(fb.nodeVals, nil) // synthesized scalar-chain node
	fmt.Fprintf(&fb.key, "%s;", op)
	return len(fb.nodes) - 1, true
}

// addChaseScalarArg adds (or dedups) one scalar parameter sourced by a
// chased expression. Chased reads happen INSIDE the fused call, so
// they are recorded in chaseReads (checked against remaining
// intervener writes at commit) rather than candReads.
func (fb *fusedTreeBuilder) addChaseScalarArg(src ast.Expr, key string) (simdfuse.Arg, bool) {
	if fb.scalarDedup == nil {
		fb.scalarDedup = map[string]int{}
	}
	if idx, ok := fb.scalarDedup[key]; ok {
		fb.noteChaseRead(src)
		return simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: idx}, true
	}
	if !fb.capRelax && 1+len(fb.scalars)+1 > fusedMaxIntRegs {
		if fb.failWhy == "" {
			fb.failWhy = "int cap (chased scalar)"
		}
		return simdfuse.Arg{}, false
	}
	idx := len(fb.scalars)
	fb.scalarDedup[key] = idx
	if fb.chaseTrace {
		fuseDebugf("chaseTRACE opaque scalar s%d: %s", idx, exprDebugString(src))
	}
	fb.scalars = append(fb.scalars, src)
	fb.scalarOwner = append(fb.scalarOwner, fb.curCand)
	// Chased compound expression: no single-source SSA provenance —
	// a window carrying it stays on per-op splices in direct-asm.
	fb.scalarSrc = append(fb.scalarSrc, fusedParamSrc{})
	fb.noteChaseRead(src)
	return simdfuse.Arg{Kind: simdfuse.ArgScalar, Index: idx}, true
}

// noteChaseRead records identifiers a chased expression reads.
func (fb *fusedTreeBuilder) noteChaseRead(e ast.Expr) {
	if fb.chaseReads == nil {
		fb.chaseReads = map[string]bool{}
	}
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name != "_" {
			fb.chaseReads[id.Name] = true
		}
		return true
	})
}

// helperName extracts the bare helper name from `F32_mul` or
// `base.F32_mul` call targets.
func helperName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// matchMemDeref matches the emitter's unchecked scalar memory access
// `*(*T)(unsafe.Add(mBase, ADDR))` and returns ADDR. mBase is the
// emitter's function-local cache of m.M; no call can intervene inside
// a window, so the cached pointer cannot go stale relative to the
// fused call's own memory base.
func matchMemDeref(star *ast.StarExpr, typ string) (addr ast.Expr, is64 bool, ok bool) {
	conv, ok := star.X.(*ast.CallExpr)
	if !ok || len(conv.Args) != 1 {
		return nil, false, false
	}
	paren, ok := conv.Fun.(*ast.ParenExpr)
	if !ok {
		return nil, false, false
	}
	ptr, ok := paren.X.(*ast.StarExpr)
	if !ok {
		return nil, false, false
	}
	if id, ok := ptr.X.(*ast.Ident); !ok || id.Name != typ {
		return nil, false, false
	}
	add, ok := conv.Args[0].(*ast.CallExpr)
	if !ok || len(add.Args) != 2 {
		return nil, false, false
	}
	sel, ok := add.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Add" {
		return nil, false, false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "unsafe" {
		return nil, false, false
	}
	if base, ok := add.Args[0].(*ast.Ident); !ok || base.Name != "mBase" {
		return nil, false, false
	}
	// memory64 wraps the address in uint64(...) before unsafe.Add;
	// unwrap it so the address chase sees the raw arithmetic (wasm32
	// keeps whatever the emitter produced — usually a bare sum). The
	// returned is64 marks the whole tree Addr64 at the call site.
	addr = add.Args[1]
	if conv, ok := addr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if id, ok := conv.Fun.(*ast.Ident); ok && id.Name == "uint64" {
			addr, is64 = conv.Args[0], true
		}
	}
	return addr, is64, true
}

// matchShiftConst matches the emitter's masked shift count
// `uint(c) % 32` (or a bare constant) with c const-resolvable.
func matchShiftConst(e ast.Expr, fb *fusedTreeBuilder) (int32, bool) {
	// wasm32 spells its shift masks `% 32`; memory64 address chains run
	// at i64 and spell them `% 64`. Both reduce a constant amount the
	// same way for the in-range shifts the chase accepts.
	mod := int32(32)
	if bin, ok := e.(*ast.BinaryExpr); ok && bin.Op == token.REM {
		if m, mok := intConstValue(bin.Y); mok && (m == 32 || m == 64) {
			e = bin.X
			mod = m
		}
	}
	for {
		conv, ok := e.(*ast.CallExpr)
		if !ok || len(conv.Args) != 1 {
			break
		}
		id, ok := conv.Fun.(*ast.Ident)
		if !ok {
			break
		}
		switch id.Name {
		case "uint", "uint32", "uint64", "int32", "int64":
			// Integer conversions are identities for the small
			// non-negative shift amounts the chase accepts.
			e = conv.Args[0]
		default:
			return 0, false
		}
	}
	c, ok := fb.constValueOf(e)
	if !ok {
		if id, isID := e.(*ast.Ident); isID {
			cb, cbok := fb.sc.constBind[id.Name]
			fuseDebugf("matchShiftConst: ident %s constBind hit=%v val=%d (bindsize=%d)", id.Name, cbok, cb, len(fb.sc.constBind))
		} else {
			fuseDebugf("matchShiftConst: non-ident %T", e)
		}
		return 0, false
	}
	return c % mod, true
}

// stripU32 unwraps a `uint32(...)` conversion.
func stripU32(e ast.Expr) ast.Expr {
	if conv, ok := e.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if id, ok := conv.Fun.(*ast.Ident); ok && id.Name == "uint32" {
			return conv.Args[0]
		}
	}
	return e
}

// exprKeyString renders an expression as a stable dedup key.
func exprKeyString(e ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, token.NewFileSet(), e); err != nil {
		// An unprintable node cannot be keyed; make the key unique so
		// dedup never aliases two distinct expressions.
		return fmt.Sprintf("!badexpr:%d", badExprKeys.Add(1))
	}
	return b.String()
}

var badExprKeys atomic.Int64

// interReadsMem reports whether an intervener statement's RHS performs
// any memory read (an inline unsafe deref or a marked memory helper):
// such a statement may not move ahead of a fused window that contains
// stores it originally followed.
func interReadsMem(st ast.Stmt) bool {
	as, ok := st.(*ast.AssignStmt)
	if !ok {
		return true // unknown shape: assume the worst
	}
	reads := false
	ast.Inspect(as.Rhs[0], func(n ast.Node) bool {
		if _, isStar := n.(*ast.StarExpr); isStar {
			reads = true
			return false
		}
		return true
	})
	return reads
}
