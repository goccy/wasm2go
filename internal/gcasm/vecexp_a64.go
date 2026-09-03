package gcasm

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// vecExpConsts is the constant block the vector exp kernels load:
// sixteen 32-bit lanes (f32 unless noted), the ARM optimized-routines
// expf polynomial ggml_v_expf uses on every native ISA.
//
//	0 r = 0x1.8p23   1 log2e        2 c1 0x1.62e4p-1   3 c2 0x1.7f7d1cp-20
//	4 p0 0x1.0e4020p-7  5 p1 0x1.573e2ep-5  6 p2 0x1.555e66p-3  7 p3 0x1.fffdb6p-2
//	8 p4 0x1.ffffecp-1  9 126.0  10 192.0  11 1.0 (also the 0x3f800000 addend)
//	12 u32 0x82000000  13 u32 0x7f000000  14 abs mask 0x7fffffff  15 0
func vecExpConsts() []byte {
	f := []float32{
		0x1.8p23, 0x1.715476p+0, 0x1.62e4p-1, 0x1.7f7d1cp-20,
		0x1.0e4020p-7, 0x1.573e2ep-5, 0x1.555e66p-3, 0x1.fffdb6p-2,
		0x1.ffffecp-1, 126, 192, 1,
	}
	blob := make([]byte, 64)
	for i, v := range f {
		binary.LittleEndian.PutUint32(blob[4*i:], math.Float32bits(v))
	}
	binary.LittleEndian.PutUint32(blob[48:], 0x82000000)
	binary.LittleEndian.PutUint32(blob[52:], 0x7f000000)
	binary.LittleEndian.PutUint32(blob[56:], 0x7fffffff)
	return blob
}

// vecExpArgs returns the ABI0 offsets of the exp kernels' arguments.
// soft_max(n int32, y, x ptr, max f32) -> f64; swiglu(n int32, y, x, g
// ptr). Pointers follow the module's width; the f64 result sits after
// the last argument, 8-aligned.
func vecExpArgs(wide bool) (softmax map[string]int, softmaxArgBytes int, swiglu map[string]int, swigluArgBytes int) {
	if wide {
		return map[string]int{"l0": 8, "l1": 16, "l2": 24, "l3": 32, "r0": 40}, 48,
			map[string]int{"l0": 8, "l1": 16, "l2": 24, "l3": 32}, 40
	}
	return map[string]int{"l0": 8, "l1": 12, "l2": 16, "l3": 20, "r0": 24}, 32,
		map[string]int{"l0": 8, "l1": 12, "l2": 16, "l3": 20}, 24
}

// a64VecExp holds the NEON emitters shared by the arm64 exp kernels.
// Constant registers after a64VecExpLoadConsts: v28..v31 = the 16
// lanes of vecExpConsts (by-element operands), v27 = dup 126, v26 =
// dup 192, v25 = dup 1.0 (bits 0x3f800000), v24 = dup 0x82000000,
// v23 = dup 0x7f000000, v22 = dup r, v21 = dup p1, v20 = dup p3.
type a64VecExp struct {
	w    func(format string, args ...any)
	word func(enc uint32, dis string)
}

func (e *a64VecExp) fmlaV(d, n, m int) {
	e.word(0x4E20CC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecExp) fmlaLane(d, n, m, idx int) {
	e.word(0x4F801000|uint32(idx&1)<<21|uint32(idx>>1)<<11|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
}

func (e *a64VecExp) fmlsLane(d, n, m, idx int) {
	e.word(0x4F805000|uint32(idx&1)<<21|uint32(idx>>1)<<11|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmls v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
}

func (e *a64VecExp) fmulLane(d, n, m, idx int) {
	e.word(0x4F809000|uint32(idx&1)<<21|uint32(idx>>1)<<11|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
}

func (e *a64VecExp) fmulV(d, n, m int) {
	e.word(0x6E20DC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecExp) faddV(d, n, m int) {
	e.word(0x4E20D400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fadd v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecExp) fsubV(d, n, m int) {
	e.word(0x4EA0D400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fsub v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecExp) fdivV(d, n, m int) {
	e.word(0x6E20FC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fdiv v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecExp) mov(d, n int) {
	e.word(0x4EA01C00|uint32(n)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("mov v%d.16b, v%d.16b", d, n))
}

func (e *a64VecExp) dupLane(d, n, idx int) {
	e.word(0x4E000400|uint32((idx<<3)|4)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("dup v%d.4s, v%d.s[%d]", d, n, idx))
}

func (e *a64VecExp) ldurQ(rt, rn, imm int) {
	e.word(0x3CC00000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur q%d, [x%d, #%d]", rt, rn, imm))
}

func (e *a64VecExp) sturQ(rt, rn, imm int) {
	e.word(0x3C800000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("stur q%d, [x%d, #%d]", rt, rn, imm))
}

// loadConsts materializes the constant registers from the pool blob.
func (e *a64VecExp) loadConsts(sym string, reg int) {
	e.w("\tMOVD\t$·%s(SB), R%d", sym, reg)
	e.w("\tVLD1\t(R%d), [V28.S4, V29.S4, V30.S4, V31.S4]", reg)
	e.dupLane(27, 30, 1) // 126
	e.dupLane(26, 30, 2) // 192
	e.dupLane(25, 30, 3) // 1.0
	e.dupLane(24, 31, 0) // 0x82000000
	e.dupLane(23, 31, 1) // 0x7f000000
	e.dupLane(22, 28, 0) // r
	e.dupLane(21, 29, 1) // p1
	e.dupLane(20, 29, 3) // p3
}

// exp computes v(out) = expf(v(x)) lane-wise, clobbering v0..v11
// except x/out. x may equal out. The arithmetic is ggml_v_expf's
// (fused multiply-adds, the special-range select computed branch-free):
// numbers above 88.38 flush to +inf, beneath -103.97 to zero.
func (e *a64VecExp) exp(out, x int) {
	const (
		z  = 1
		n  = 2
		b  = 3
		ee = 4
		k  = 5
		an = 6
		c  = 7
		u  = 8
		t1 = 9
		t2 = 10
		m  = 11
	)
	// z = r + x*log2e ; n = z - r
	e.mov(z, 22)
	e.fmlaLane(z, x, 28, 1)
	e.fsubV(n, z, 22)
	// b = x - n*c1 - n*c2
	e.mov(b, x)
	e.fmlsLane(b, n, 28, 2)
	e.fmlsLane(b, n, 28, 3)
	// e = bits(z) << 23 ; k = e + 1.0bits
	e.word(0x4F375400|uint32(z)<<5|uint32(ee), fmt.Sprintf("shl v%d.4s, v%d.4s, #23", ee, z))
	e.word(0x4EA08400|uint32(25)<<16|uint32(ee)<<5|uint32(k), fmt.Sprintf("add v%d.4s, v%d.4s, v25.4s", k, ee))
	// an = |n| ; c = an > 126
	e.word(0x4EA0F800|uint32(n)<<5|uint32(an), fmt.Sprintf("fabs v%d.4s, v%d.4s", an, n))
	e.word(0x6EA0E400|uint32(27)<<16|uint32(an)<<5|uint32(c), fmt.Sprintf("fcmgt v%d.4s, v%d.4s, v27.4s", c, an))
	// u = b*b ; t1 = p1 + b*p0 ; t2 = p3 + b*p2 ; j = (p4*b) + (t2 + t1*u)*u
	e.fmulV(u, b, b)
	e.mov(t1, 21)
	e.fmlaLane(t1, b, 29, 0)
	e.mov(t2, 20)
	e.fmlaLane(t2, b, 29, 2)
	e.fmlaV(t2, t1, u)
	e.fmulLane(m, b, 30, 0)
	e.fmlaV(m, t2, u) // m = j
	// res(t1) = k + j*k
	e.mov(t1, k)
	e.fmlaV(t1, m, k)
	// d(z) = (n <= 0) & 0x82000000 ; s1(b) = d + 0x7f000000 ; s2(u) = e - d
	e.word(0x6EA0D800|uint32(n)<<5|uint32(z), fmt.Sprintf("fcmle v%d.4s, v%d.4s, #0.0", z, n))
	e.word(0x4E201C00|uint32(24)<<16|uint32(z)<<5|uint32(z), fmt.Sprintf("and v%d.16b, v%d.16b, v24.16b", z, z))
	e.word(0x4EA08400|uint32(23)<<16|uint32(z)<<5|uint32(b), fmt.Sprintf("add v%d.4s, v%d.4s, v23.4s", b, z))
	e.word(0x6EA08400|uint32(z)<<16|uint32(ee)<<5|uint32(u), fmt.Sprintf("sub v%d.4s, v%d.4s, v%d.4s", u, ee, z))
	// alt(t2) = (s2 + s2*j) * s1 ; big(k) = s1*s1 ; cbig(n) = an > 192
	e.mov(t2, u)
	e.fmlaV(t2, u, m)
	e.fmulV(t2, t2, b)
	e.fmulV(k, b, b)
	e.word(0x6EA0E400|uint32(26)<<16|uint32(an)<<5|uint32(n), fmt.Sprintf("fcmgt v%d.4s, v%d.4s, v26.4s", n, an))
	// out = cbig ? big : (c ? alt : res)
	e.word(0x6E601C00|uint32(t1)<<16|uint32(t2)<<5|uint32(c), fmt.Sprintf("bsl v%d.16b, v%d.16b, v%d.16b", c, t2, t1))
	e.word(0x6E601C00|uint32(c)<<16|uint32(k)<<5|uint32(n), fmt.Sprintf("bsl v%d.16b, v%d.16b, v%d.16b", n, k, c))
	e.mov(out, n)
}

// a64VecSoftMaxKernel emits ggml_vec_soft_max_f32 under sym:
// y[i] = expf(x[i] - max), returns the f64 sum of y. Four lanes per
// step, then one lane at a time for the tail; each step's lane sum is
// added to the f64 accumulator (as the native ggml loops do).
func a64VecSoftMaxKernel(sym, trapSym string, offs *ModuleOffsets, pool *ConstPool, wide bool) string {
	var sb strings.Builder
	e := &a64VecExp{}
	e.w = func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	e.word = func(enc uint32, dis string) { e.w("\tWORD $0x%08x // %s", enc, dis) }
	cSym := pool.addBlob(vecExpConsts())
	args, argBytes, _, _ := vecExpArgs(wide)
	movPtr := "MOVWU"
	if wide {
		movPtr = "MOVD"
	}
	w := e.w
	w("// %s: y = expf(x - max), returns sum(y) (f64).", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tFMOVD\tZR, F15")
	w("\tMOVW\tl0+%d(FP), R1", args["l0"])
	w("\tCMPW\t$1, R1")
	w("\tBLT\tsmdone")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\t%s\tl1+%d(FP), R2", movPtr, args["l1"])
	w("\t%s\tl2+%d(FP), R3", movPtr, args["l2"])
	w("\tLSL\t$2, R1, R26")
	w("\tADD\tR2, R26, R27")
	w("\tCMP\tR27, R21")
	w("\tBLO\tsmoob")
	w("\tADD\tR3, R26, R27")
	w("\tCMP\tR27, R21")
	w("\tBLO\tsmoob")
	w("\tADD\tR20, R2, R2")
	w("\tADD\tR20, R3, R3")
	e.loadConsts(cSym, 4)
	w("\tFMOVS\tl3+%d(FP), F14", args["l3"])
	e.dupLane(14, 14, 0)
	w("smloop4:")
	w("\tCMPW\t$4, R1")
	w("\tBLT\tsmtail")
	e.ldurQ(0, 3, 0)
	e.fsubV(0, 0, 14)
	e.exp(0, 0)
	e.sturQ(0, 2, 0)
	// lane sum -> f64 accumulator
	e.word(0x6E20D400|uint32(0)<<16|uint32(0)<<5|uint32(1), "faddp v1.4s, v0.4s, v0.4s")
	e.word(0x7E30D800|uint32(1)<<5|uint32(1), "faddp s1, v1.2s")
	w("\tFCVTSD\tF1, F1")
	w("\tFADDD\tF1, F15, F15")
	w("\tADD\t$16, R2, R2")
	w("\tADD\t$16, R3, R3")
	w("\tSUBW\t$4, R1, R1")
	w("\tB\tsmloop4")
	w("smtail:")
	w("\tCBZW\tR1, smdone")
	w("\tFMOVS\t(R3), F0")
	e.fsubV(0, 0, 14)
	e.exp(0, 0)
	w("\tFMOVS\tF0, (R2)")
	w("\tFCVTSD\tF0, F1")
	w("\tFADDD\tF1, F15, F15")
	w("\tADD\t$4, R2, R2")
	w("\tADD\t$4, R3, R3")
	w("\tSUBW\t$1, R1, R1")
	w("\tB\tsmtail")
	w("smdone:")
	w("\tFMOVD\tF15, r0+%d(FP)", args["r0"])
	w("\tRET")
	w("smoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}

// a64VecSwigluKernel emits ggml_vec_swiglu_f32 under sym:
// y[i] = x[i] / (1 + expf(-x[i])) * g[i].
func a64VecSwigluKernel(sym, trapSym string, offs *ModuleOffsets, pool *ConstPool, wide bool) string {
	var sb strings.Builder
	e := &a64VecExp{}
	e.w = func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	e.word = func(enc uint32, dis string) { e.w("\tWORD $0x%08x // %s", enc, dis) }
	cSym := pool.addBlob(vecExpConsts())
	_, _, args, argBytes := vecExpArgs(wide)
	movPtr := "MOVWU"
	if wide {
		movPtr = "MOVD"
	}
	w := e.w
	fneg := func(d, n int) {
		e.word(0x6EA0F800|uint32(n)<<5|uint32(d), fmt.Sprintf("fneg v%d.4s, v%d.4s", d, n))
	}
	w("// %s: y = x / (1 + expf(-x)) * g.", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVW\tl0+%d(FP), R1", args["l0"])
	w("\tCMPW\t$1, R1")
	w("\tBLT\tswdone")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\t%s\tl1+%d(FP), R2", movPtr, args["l1"])
	w("\t%s\tl2+%d(FP), R3", movPtr, args["l2"])
	w("\t%s\tl3+%d(FP), R4", movPtr, args["l3"])
	w("\tLSL\t$2, R1, R26")
	for _, r := range []int{2, 3, 4} {
		w("\tADD\tR%d, R26, R27", r)
		w("\tCMP\tR27, R21")
		w("\tBLO\tswoob")
	}
	w("\tADD\tR20, R2, R2")
	w("\tADD\tR20, R3, R3")
	w("\tADD\tR20, R4, R4")
	e.loadConsts(cSym, 5)
	// v13 keeps x across the exp, v12 the gate.
	w("swloop4:")
	w("\tCMPW\t$4, R1")
	w("\tBLT\tswtail")
	e.ldurQ(13, 3, 0)
	e.ldurQ(12, 4, 0)
	fneg(0, 13)
	e.exp(0, 0)
	e.faddV(0, 0, 25)
	e.fdivV(0, 13, 0)
	e.fmulV(0, 0, 12)
	e.sturQ(0, 2, 0)
	w("\tADD\t$16, R2, R2")
	w("\tADD\t$16, R3, R3")
	w("\tADD\t$16, R4, R4")
	w("\tSUBW\t$4, R1, R1")
	w("\tB\tswloop4")
	w("swtail:")
	w("\tCBZW\tR1, swdone")
	w("\tFMOVS\t(R3), F13")
	w("\tFMOVS\t(R4), F12")
	fneg(0, 13)
	e.exp(0, 0)
	e.faddV(0, 0, 25)
	e.fdivV(0, 13, 0)
	e.fmulV(0, 0, 12)
	w("\tFMOVS\tF0, (R2)")
	w("\tADD\t$4, R2, R2")
	w("\tADD\t$4, R3, R3")
	w("\tADD\t$4, R4, R4")
	w("\tSUBW\t$1, R1, R1")
	w("\tB\tswtail")
	w("swdone:")
	w("\tRET")
	w("swoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}
