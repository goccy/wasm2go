package pass

import (
	"github.com/goccy/wasm2go/internal/ssa"
)

// RecognizeF32ToF16 rewrites the software float32→float16 rounding
// idiom (ggml's inlined fp32→fp16 conversion, the Giesen algorithm)
// so the expensive arithmetic arm becomes one helper call that the
// asm backend can lower to a native convert instruction.
//
// The wasm idiom arrives as two branch diamonds:
//
//	w     = i32_reinterpret_f32(f)
//	shl1  = w << 1
//	bias  = phi(0x71000000, shl1)          // shl1 <= 0x71000000 ?
//	v     = i32_reinterpret_f32(
//	          f32_abs(f)*0x1p+112*0x1p-110 +
//	          f32_reinterpret_i32((bias>>1)&0x7F800000 + 0x07800000))
//	nons  = phi(0x7E00,                    // 0xFF000000 < shl1 (NaN)
//	            (v>>13)&0x7C00 + v&0xFFF)
//	res   = nons | (w>>16)&0x8000
//
// Only the non-NaN phi arm is replaced — with
// f32_to_f16_bits(f) & 0x7FFF — so the rewrite is bit-exact for
// every input: non-NaN values get the hardware-identical conversion
// (the helper and FCVT agree on all of them, denormals and infinity
// included), and NaN keeps taking the untouched 0x7E00 arm, where
// the helper's result is dead. The sign OR in the tail is untouched.
// The orphaned arithmetic chain and the bias diamond die in DCE.
func RecognizeF32ToF16(f *ssa.Func) bool {
	changed := false
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op != ssa.OpOr32 || len(v.Args) != 2 {
				continue
			}
			for i := 0; i < 2; i++ {
				phi, signChain := v.Args[i], v.Args[1-i]
				if rewriteF16Phi(f, phi, signChain) {
					changed = true
					break
				}
			}
		}
	}
	return changed
}

// rewriteF16Phi checks one Or32 operand pair (phi candidate + sign
// chain) and performs the arm replacement when the whole idiom
// matches. Conservative: any shape deviation means no rewrite.
func rewriteF16Phi(f *ssa.Func, phi, signChain *ssa.Value) bool {
	fv, ok := matchF16Idiom(phi, signChain)
	if !ok {
		return false
	}
	return rewriteF16NonNaNArm(f, phi, fv)
}

// matchF16Idiom checks one Or32 operand pair (phi candidate + sign
// chain) against the software fp32->fp16 idiom and returns the f32
// input value. Check-only: the f16 store vectorizer reuses it to
// find whole converted lanes.
func matchF16Idiom(phi, signChain *ssa.Value) (*ssa.Value, bool) {
	fv, _, ok := matchF16IdiomBits(phi, signChain)
	if !ok || fv == nil {
		return nil, false
	}
	return fv, true
}

// matchF16IdiomBits is the general matcher: the sign chain's source w
// is either i32_reinterpret_f32(f) — then fv = f — or the raw i32
// bits value itself (the wasm commonly extracts float lanes as i32
// bits); then fv is nil and the caller works from w. In the bits form
// the arithmetic arm references f32_reinterpret_i32(w) as the float.
func matchF16IdiomBits(phi, signChain *ssa.Value) (fvOut, wOut *ssa.Value, ok bool) {
	if phi.Op != ssa.OpPhi || len(phi.Args) != 2 {
		return nil, nil, false
	}
	// sign chain: (w >> 16) & 0x8000
	w := matchAndShr(signChain, 16, 0x8000)
	if w == nil {
		return nil, nil, false
	}
	var fv *ssa.Value
	if isHelper(w, "i32_reinterpret_f32") && len(w.Args) == 1 && w.Args[0].Type == ssa.TypeF32 {
		fv = w.Args[0]
	}
	floatOfW := func(x *ssa.Value) bool {
		if fv != nil {
			return x == fv
		}
		return isHelper(x, "f32_reinterpret_i32") && len(x.Args) == 1 && x.Args[0] == w
	}
	// phi arms: one 0x7E00 constant (NaN), one arithmetic chain.
	nanIdx := -1
	for i, a := range phi.Args {
		if isConst32(a, 0x7E00) {
			nanIdx = i
		}
	}
	if nanIdx == -1 {
		return nil, nil, false
	}
	nonsign := phi.Args[1-nanIdx]
	// nonsign = ((v>>13)&0x7C00) + (v&0xFFF), same v both sides.
	if nonsign.Op != ssa.OpAdd32 || len(nonsign.Args) != 2 {
		return nil, nil, false
	}
	var v *ssa.Value
	for i := 0; i < 2; i++ {
		hi, lo := nonsign.Args[i], nonsign.Args[1-i]
		if x := matchAndShr(hi, 13, 0x7C00); x != nil && matchAnd(lo, 0xFFF) == x {
			v = x
			break
		}
	}
	if v == nil || !isHelper(v, "i32_reinterpret_f32") || len(v.Args) != 1 {
		return nil, nil, false
	}
	// v reinterprets base = mul-chain + reinterpreted bias. Float
	// arithmetic lowers as helper calls (f32_add/f32_mul), not
	// first-class SSA float ops.
	base := v.Args[0]
	if !isHelper(base, "f32_add") || len(base.Args) != 2 {
		return nil, nil, false
	}
	okMul := func(m *ssa.Value) bool {
		// (f32_abs(f) * 0x1p+112) * 0x1p-110, factors commutative.
		if !isHelper(m, "f32_mul") || len(m.Args) != 2 {
			return false
		}
		inner, c2 := m.Args[0], m.Args[1]
		if isConstF32(inner, 0x08800000) {
			inner, c2 = c2, inner
		}
		if !isConstF32(c2, 0x08800000) || !isHelper(inner, "f32_mul") || len(inner.Args) != 2 {
			return false
		}
		abs, c1 := inner.Args[0], inner.Args[1]
		if isConstF32(abs, 0x77800000) {
			abs, c1 = c1, abs
		}
		// |f| arrives as f32_abs(f), or in the bits form as the sign
		// bit cleared integrally: f32_reinterpret_i32(w & 0x7FFFFFFF).
		absOK := isHelper(abs, "f32_abs") && len(abs.Args) == 1 && floatOfW(abs.Args[0])
		if !absOK && isHelper(abs, "f32_reinterpret_i32") && len(abs.Args) == 1 {
			absOK = matchAnd(abs.Args[0], 0x7FFFFFFF) == w
		}
		return isConstF32(c1, 0x77800000) && absOK
	}
	okBias := func(rb *ssa.Value) bool {
		// f32_reinterpret_i32(((bias>>1) & 0x7F800000) + 0x07800000)
		if !isHelper(rb, "f32_reinterpret_i32") || len(rb.Args) != 1 {
			return false
		}
		add := rb.Args[0]
		if add.Op != ssa.OpAdd32 || len(add.Args) != 2 {
			return false
		}
		masked, c := add.Args[0], add.Args[1]
		if isConst32(masked, 0x07800000) {
			masked, c = c, masked
		}
		bias := matchAndShr(masked, 1, 0x7F800000)
		if !isConst32(c, 0x07800000) || bias == nil {
			return false
		}
		// bias = phi(0x71000000, shl1) with shl1 = w << 1 for OUR w.
		if bias.Op != ssa.OpPhi || len(bias.Args) != 2 {
			return false
		}
		var shl1 *ssa.Value
		for i := 0; i < 2; i++ {
			if isConst32(bias.Args[i], 0x71000000) {
				shl1 = bias.Args[1-i]
			}
		}
		return shl1 != nil && shl1.Op == ssa.OpShl32 && len(shl1.Args) == 2 &&
			shl1.Args[0] == w && isConst32(shl1.Args[1], 1)
	}
	m0, m1 := base.Args[0], base.Args[1]
	matched := (okMul(m0) && okBias(m1)) || (okMul(m1) && okBias(m0))
	if !matched {
		return nil, nil, false
	}
	return fv, w, true
}

// rewriteF16NonNaNArm replaces the matched idiom's non-NaN arm with
// f32_to_f16_bits(f)&0x7FFF, inserted right before the old arm value
// so dominance holds.
func rewriteF16NonNaNArm(f *ssa.Func, phi, fv *ssa.Value) bool {
	nanIdx := -1
	for i, a := range phi.Args {
		if isConst32(a, 0x7E00) {
			nanIdx = i
		}
	}
	if nanIdx == -1 {
		return false
	}
	nonsign := phi.Args[1-nanIdx]
	nb := nonsign.Block
	at := -1
	for i, bv := range nb.Values {
		if bv == nonsign {
			at = i
			break
		}
	}
	if at == -1 {
		return false
	}
	h := nb.NewValueBefore(f, at, ssa.OpHelperCall, ssa.TypeI32, 0, "f32_to_f16_bits", fv)
	mask := nb.NewValueBefore(f, at+1, ssa.OpConst32, ssa.TypeI32, 0x7FFF, nil)
	and := nb.NewValueBefore(f, at+2, ssa.OpAnd32, ssa.TypeI32, 0, nil, h, mask)
	phi.Args[1-nanIdx] = and
	return true
}

func isConstF32(v *ssa.Value, bits int64) bool {
	return v.Op == ssa.OpConstF32 && v.AuxInt == bits
}

func isHelper(v *ssa.Value, name string) bool {
	if v.Op != ssa.OpHelperCall {
		return false
	}
	n, _ := v.Aux.(string)
	return n == name
}

// matchAndShr matches (x >> shift) & mask (operands commutative on
// the And) and returns x, or nil.
func matchAnd(v *ssa.Value, mask int64) *ssa.Value {
	if v.Op != ssa.OpAnd32 || len(v.Args) != 2 {
		return nil
	}
	a, c := v.Args[0], v.Args[1]
	if isConst32(a, mask) {
		a, c = c, a
	}
	if !isConst32(c, mask) {
		return nil
	}
	return a
}

func matchAndShr(v *ssa.Value, shift, mask int64) *ssa.Value {
	shr := matchAnd(v, mask)
	if shr == nil || shr.Op != ssa.OpShrU32 || len(shr.Args) != 2 || !isConst32(shr.Args[1], shift) {
		return nil
	}
	return shr.Args[0]
}
