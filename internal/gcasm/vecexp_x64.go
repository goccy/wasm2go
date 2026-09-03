package gcasm

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// x64VecExp holds the AVX2 emitters shared by the amd64 exp kernels.
// Constants come from 32-byte replicated pool blobs used as memory
// operands, so no register holds them; the kernels run in ymm for the
// bulk and reuse the same emitter at xmm width for the tails.
type x64VecExp struct {
	w    func(format string, args ...any)
	c    map[string]string // constant name -> pool symbol
	pool *ConstPool
}

func newX64VecExp(w func(string, ...any), pool *ConstPool) *x64VecExp {
	e := &x64VecExp{w: w, c: map[string]string{}, pool: pool}
	rep := func(name string, bits uint32) {
		blob := make([]byte, 32)
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint32(blob[4*i:], bits)
		}
		e.c[name] = pool.addBlob(blob)
	}
	f := func(name string, v float32) { rep(name, math.Float32bits(v)) }
	f("r", 0x1.8p23)
	f("log2e", 0x1.715476p+0)
	f("c1", 0x1.62e4p-1)
	f("c2", 0x1.7f7d1cp-20)
	f("p0", 0x1.0e4020p-7)
	f("p1", 0x1.573e2ep-5)
	f("p2", 0x1.555e66p-3)
	f("p3", 0x1.fffdb6p-2)
	f("p4", 0x1.ffffecp-1)
	f("c126", 126)
	f("c192", 192)
	f("one", 1)
	rep("m82", 0x82000000)
	rep("m7f", 0x7f000000)
	rep("abs", 0x7fffffff)
	rep("zero", 0)
	return e
}

func (e *x64VecExp) sym(name string) string { return "·" + e.c[name] + "(SB)" }

// exp computes W(out) = expf(W(x)) lane-wise at width W ("Y" or "X"),
// clobbering registers 1..11 except x/out. Same arithmetic as the
// arm64 twin (ggml_v_expf with fused multiply-adds; the special-range
// select is computed branch-free).
func (e *x64VecExp) exp(W string, out, x int) {
	r := func(i int) string { return fmt.Sprintf("%s%d", W, i) }
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
	w := e.w
	// z = r + x*log2e ; n = z - r
	w("\tVMOVUPS\t%s, %s", e.sym("r"), r(z))
	w("\tVFMADD231PS\t%s, %s, %s", e.sym("log2e"), r(x), r(z))
	w("\tVSUBPS\t%s, %s, %s", e.sym("r"), r(z), r(n))
	// b = x - n*c1 - n*c2
	w("\tVMOVAPS\t%s, %s", r(x), r(b))
	w("\tVFNMADD231PS\t%s, %s, %s", e.sym("c1"), r(n), r(b))
	w("\tVFNMADD231PS\t%s, %s, %s", e.sym("c2"), r(n), r(b))
	// e = bits(z) << 23 ; k = e + 1.0bits
	w("\tVPSLLD\t$23, %s, %s", r(z), r(ee))
	w("\tVPADDD\t%s, %s, %s", e.sym("one"), r(ee), r(k))
	// an = |n| ; c = an > 126
	w("\tVANDPS\t%s, %s, %s", e.sym("abs"), r(n), r(an))
	w("\tVCMPPS\t$0x1e, %s, %s, %s", e.sym("c126"), r(an), r(c))
	// u = b*b ; t1 = p1 + b*p0 ; t2 = p3 + b*p2 ; j(m) = p4*b + (t2 + t1*u)*u
	w("\tVMULPS\t%s, %s, %s", r(b), r(b), r(u))
	w("\tVMOVUPS\t%s, %s", e.sym("p1"), r(t1))
	w("\tVFMADD231PS\t%s, %s, %s", e.sym("p0"), r(b), r(t1))
	w("\tVMOVUPS\t%s, %s", e.sym("p3"), r(t2))
	w("\tVFMADD231PS\t%s, %s, %s", e.sym("p2"), r(b), r(t2))
	w("\tVFMADD231PS\t%s, %s, %s", r(u), r(t1), r(t2))
	w("\tVMULPS\t%s, %s, %s", e.sym("p4"), r(b), r(m))
	w("\tVFMADD231PS\t%s, %s, %s", r(u), r(t2), r(m))
	// res(t1) = k + j*k
	w("\tVMOVAPS\t%s, %s", r(k), r(t1))
	w("\tVFMADD231PS\t%s, %s, %s", r(k), r(m), r(t1))
	// d(z) = (n <= 0) & 0x82000000 ; s1(b) = d + 0x7f000000 ; s2(u) = e - d
	w("\tVCMPPS\t$0x12, %s, %s, %s", e.sym("zero"), r(n), r(z))
	w("\tVANDPS\t%s, %s, %s", e.sym("m82"), r(z), r(z))
	w("\tVPADDD\t%s, %s, %s", e.sym("m7f"), r(z), r(b))
	w("\tVPSUBD\t%s, %s, %s", r(z), r(ee), r(u))
	// alt(t2) = (s2 + s2*j) * s1 ; big(k) = s1*s1 ; cbig(n) = an > 192
	w("\tVMOVAPS\t%s, %s", r(u), r(t2))
	w("\tVFMADD231PS\t%s, %s, %s", r(m), r(u), r(t2))
	w("\tVMULPS\t%s, %s, %s", r(b), r(t2), r(t2))
	w("\tVMULPS\t%s, %s, %s", r(b), r(b), r(k))
	w("\tVCMPPS\t$0x1e, %s, %s, %s", e.sym("c192"), r(an), r(n))
	// out = cbig ? big : (c ? alt : res)
	w("\tVBLENDVPS\t%s, %s, %s, %s", r(c), r(t2), r(t1), r(c))
	w("\tVBLENDVPS\t%s, %s, %s, %s", r(n), r(k), r(c), r(out))
}

// x64VecSoftMaxKernel emits ggml_vec_soft_max_f32 under sym (AVX2):
// y[i] = expf(x[i] - max), returns the f64 sum of y. Eight lanes per
// step, four for the first tail, one for the last; each step's lane
// sum joins the f64 accumulator in X15.
func x64VecSoftMaxKernel(sym, trapSym string, offs *ModuleOffsets, pool *ConstPool, wide bool) string {
	var sb strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	e := newX64VecExp(w, pool)
	args, argBytes, _, _ := vecExpArgs(wide)
	movPtr := "MOVL"
	if wide {
		movPtr = "MOVQ"
	}
	w("// %s: y = expf(x - max), returns sum(y) (f64).", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tVXORPS\tX15, X15, X15")
	w("\tMOVLQSX\tl0+%d(FP), CX", args["l0"])
	w("\tTESTQ\tCX, CX")
	w("\tJLE\tsmdone")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R11", offs.MemSize)
	w("\tMOVQ\t(R11), R11")
	w("\tMOVQ\t%d(AX), R10", offs.M)
	w("\t%s\tl1+%d(FP), DI", movPtr, args["l1"])
	w("\t%s\tl2+%d(FP), SI", movPtr, args["l2"])
	w("\tLEAQ\t(DI)(CX*4), R8")
	w("\tCMPQ\tR11, R8")
	w("\tJCS\tsmoob")
	w("\tLEAQ\t(SI)(CX*4), R8")
	w("\tCMPQ\tR11, R8")
	w("\tJCS\tsmoob")
	w("\tADDQ\tR10, DI")
	w("\tADDQ\tR10, SI")
	w("\tVBROADCASTSS\tl3+%d(FP), Y14", args["l3"])
	lanesum := func(W string) {
		if W == "Y" {
			w("\tVEXTRACTF128\t$1, Y0, X1")
			w("\tVADDPS\tX1, X0, X0")
		}
		w("\tVHADDPS\tX0, X0, X0")
		w("\tVHADDPS\tX0, X0, X0")
		w("\tVCVTSS2SD\tX0, X0, X0")
		w("\tVADDSD\tX0, X15, X15")
	}
	w("smloop8:")
	w("\tCMPQ\tCX, $8")
	w("\tJLT\tsmloop4")
	w("\tVMOVUPS\t(SI), Y0")
	w("\tVSUBPS\tY14, Y0, Y0")
	e.exp("Y", 0, 0)
	w("\tVMOVUPS\tY0, (DI)")
	lanesum("Y")
	w("\tADDQ\t$32, DI")
	w("\tADDQ\t$32, SI")
	w("\tSUBQ\t$8, CX")
	w("\tJMP\tsmloop8")
	w("smloop4:")
	w("\tCMPQ\tCX, $4")
	w("\tJLT\tsmtail")
	w("\tVMOVUPS\t(SI), X0")
	w("\tVSUBPS\tX14, X0, X0")
	e.exp("X", 0, 0)
	w("\tVMOVUPS\tX0, (DI)")
	lanesum("X")
	w("\tADDQ\t$16, DI")
	w("\tADDQ\t$16, SI")
	w("\tSUBQ\t$4, CX")
	w("\tJMP\tsmloop4")
	w("smtail:")
	w("\tTESTQ\tCX, CX")
	w("\tJZ\tsmdone")
	w("\tVMOVSS\t(SI), X0")
	w("\tVSUBPS\tX14, X0, X0")
	e.exp("X", 0, 0)
	w("\tVMOVSS\tX0, (DI)")
	w("\tVCVTSS2SD\tX0, X0, X0")
	w("\tVADDSD\tX0, X15, X15")
	w("\tADDQ\t$4, DI")
	w("\tADDQ\t$4, SI")
	w("\tSUBQ\t$1, CX")
	w("\tJMP\tsmtail")
	w("smdone:")
	w("\tVMOVSD\tX15, r0+%d(FP)", args["r0"])
	w("\tVZEROUPPER")
	w("\tRET")
	w("smoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}

// x64VecSwigluKernel emits ggml_vec_swiglu_f32 under sym (AVX2):
// y[i] = x[i] / (1 + expf(-x[i])) * g[i].
func x64VecSwigluKernel(sym, trapSym string, offs *ModuleOffsets, pool *ConstPool, wide bool) string {
	var sb strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&sb, format+"\n", args...) }
	e := newX64VecExp(w, pool)
	_, _, args, argBytes := vecExpArgs(wide)
	movPtr := "MOVL"
	if wide {
		movPtr = "MOVQ"
	}
	w("// %s: y = x / (1 + expf(-x)) * g.", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVLQSX\tl0+%d(FP), CX", args["l0"])
	w("\tTESTQ\tCX, CX")
	w("\tJLE\tswdone")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R11", offs.MemSize)
	w("\tMOVQ\t(R11), R11")
	w("\tMOVQ\t%d(AX), R10", offs.M)
	w("\t%s\tl1+%d(FP), DI", movPtr, args["l1"])
	w("\t%s\tl2+%d(FP), SI", movPtr, args["l2"])
	w("\t%s\tl3+%d(FP), DX", movPtr, args["l3"])
	for _, reg := range []string{"DI", "SI", "DX"} {
		w("\tLEAQ\t(%s)(CX*4), R8", reg)
		w("\tCMPQ\tR11, R8")
		w("\tJCS\tswoob")
	}
	w("\tADDQ\tR10, DI")
	w("\tADDQ\tR10, SI")
	w("\tADDQ\tR10, DX")
	// 13 keeps x across the exp, 12 the gate.
	body := func(W string, load, store string, step int, next string, lbl string) {
		w("%s:", lbl)
		if step > 1 {
			w("\tCMPQ\tCX, $%d", step)
			w("\tJLT\t%s", next)
		} else {
			w("\tTESTQ\tCX, CX")
			w("\tJZ\t%s", next)
		}
		w("\t%s\t(SI), %s13", load, W)
		w("\t%s\t(DX), %s12", load, W)
		w("\tVXORPS\t%s0, %s0, %s0", W, W, W)
		w("\tVSUBPS\t%s13, %s0, %s0", W, W, W)
		e.exp(W, 0, 0)
		w("\tVADDPS\t%s, %s0, %s0", e.sym("one"), W, W)
		w("\tVDIVPS\t%s0, %s13, %s0", W, W, W)
		w("\tVMULPS\t%s12, %s0, %s0", W, W, W)
		w("\t%s\t%s0, (DI)", store, W)
		w("\tADDQ\t$%d, DI", 4*step)
		w("\tADDQ\t$%d, SI", 4*step)
		w("\tADDQ\t$%d, DX", 4*step)
		w("\tSUBQ\t$%d, CX", step)
		w("\tJMP\t%s", lbl)
	}
	body("Y", "VMOVUPS", "VMOVUPS", 8, "swloop4", "swloop8")
	body("X", "VMOVUPS", "VMOVUPS", 4, "swtail", "swloop4")
	body("X", "VMOVSS", "VMOVSS", 1, "swdone", "swtail")
	w("swdone:")
	w("\tVZEROUPPER")
	w("\tRET")
	w("swoob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}
