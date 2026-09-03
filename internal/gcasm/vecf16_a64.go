package gcasm

import (
	"fmt"
	"strings"
)

// The f16 attention vectors: llama-wasm exports ggml's f16 dot
// (dbg_vec_dot_f16) and the f16-by-f32 multiply-add it uses for the V
// accumulate on wasm (dbg_vec_mad_f16_f32). Both run once per KV
// position in the single-query flash-attention path, so at long
// contexts they are the decode step; the wasm versions widen every f16
// through a table lookup, the kernels here use the hardware conversion
// (FCVTL / VCVTPH2PS) and fused multiply-add. FastMath only: the sums
// are f32 with fused rounding where the wasm keeps double partials.

// vecDotF16Args is the frame of
//
//	ggml_vec_dot_f16(int n, float *s, size_t bs, ggml_fp16_t *x, size_t bx, ggml_fp16_t *y, size_t by, int nrc)
//
// nrc is 1 by contract; bs / bx / by are unused there and here.
func vecDotF16Args(wide bool) (map[string]int, int) {
	if wide {
		return map[string]int{"l0": 8, "l1": 16, "l2": 24, "l3": 32, "l4": 40, "l5": 48, "l6": 56, "l7": 64}, 68
	}
	return map[string]int{"l0": 8, "l1": 12, "l2": 16, "l3": 20, "l4": 24, "l5": 28, "l6": 32, "l7": 36}, 40
}

// vecMadF16F32Args is the frame of
//
//	ggml_vec_mad_f16_f32(int n, float *y, const ggml_fp16_t *x, float v)   // y += v * x
func vecMadF16F32Args(wide bool) (map[string]int, int) {
	if wide {
		return map[string]int{"l0": 8, "l1": 16, "l2": 24, "l3": 32}, 36
	}
	return map[string]int{"l0": 8, "l1": 12, "l2": 16, "l3": 20}, 24
}

// a64VecF16 holds the NEON emitters shared by the arm64 f16 kernels.
type a64VecF16 struct {
	w    func(format string, args ...any)
	word func(enc uint32, dis string)
}

func newA64VecF16(sb *strings.Builder) *a64VecF16 {
	e := &a64VecF16{}
	e.w = func(format string, args ...any) { fmt.Fprintf(sb, format+"\n", args...) }
	e.word = func(enc uint32, dis string) { e.w("\tWORD $0x%08x // %s", enc, dis) }
	return e
}

func (e *a64VecF16) ldurQ(rt, rn, imm int) {
	e.word(0x3CC00000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur q%d, [x%d, #%d]", rt, rn, imm))
}

func (e *a64VecF16) sturQ(rt, rn, imm int) {
	e.word(0x3C800000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("stur q%d, [x%d, #%d]", rt, rn, imm))
}

func (e *a64VecF16) ldurD(rt, rn, imm int) {
	e.word(0xFC400000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur d%d, [x%d, #%d]", rt, rn, imm))
}

func (e *a64VecF16) ldurH(rt, rn, imm int) {
	e.word(0x7C400000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur h%d, [x%d, #%d]", rt, rn, imm))
}

// fcvtl widens the low four halves of n; fcvtl2 the high four.
func (e *a64VecF16) fcvtl(d, n int) {
	e.word(0x0E217800|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvtl v%d.4s, v%d.4h", d, n))
}

func (e *a64VecF16) fcvtl2(d, n int) {
	e.word(0x4E217800|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvtl2 v%d.4s, v%d.8h", d, n))
}

func (e *a64VecF16) fcvtSH(d, n int) {
	e.word(0x1EE24000|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvt s%d, h%d", d, n))
}

func (e *a64VecF16) fmlaV(d, n, m int) {
	e.word(0x4E20CC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecF16) fmlaLane(d, n, m, idx int) {
	e.word(0x4F801000|uint32(idx&1)<<21|uint32(idx>>1)<<11|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
}

// fmaddS: sd = sa + sn * sm.
func (e *a64VecF16) fmaddS(d, n, m, a int) {
	e.word(0x1F000000|uint32(m)<<16|uint32(a)<<10|uint32(n)<<5|uint32(d), fmt.Sprintf("fmadd s%d, s%d, s%d, s%d", d, n, m, a))
}

func (e *a64VecF16) faddV(d, n, m int) {
	e.word(0x4E20D400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fadd v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecF16) faddpV(d, n, m int) {
	e.word(0x6E20D400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("faddp v%d.4s, v%d.4s, v%d.4s", d, n, m))
}

func (e *a64VecF16) faddpS(d, n int) {
	e.word(0x7E30D800|uint32(n)<<5|uint32(d), fmt.Sprintf("faddp s%d, v%d.2s", d, n))
}

func (e *a64VecF16) movi0(d int) {
	e.word(0x4F000400|uint32(d), fmt.Sprintf("movi v%d.4s, #0", d))
}

// a64VecDotF16Kernel emits *s = sum(x[i] * y[i]) over n f16 pairs under
// sym: four f32 accumulators over 16 elements per step (the wasm
// version's own 4 x 4 arrangement), a 4-wide tail and a scalar tail,
// then a tree reduce. Bounds: s + 4, x + 2n, y + 2n against memSize.
func a64VecDotF16Kernel(sym, trapSym string, offs *ModuleOffsets, _ *ConstPool, wide bool) string {
	var sb strings.Builder
	e := newA64VecF16(&sb)
	w := e.w
	args, argBytes := vecDotF16Args(wide)
	movPtr := "MOVWU"
	if wide {
		movPtr = "MOVD"
	}
	w("// %s: f16 dot product, f32 accumulate.", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\tMOVW\tl0+%d(FP), R1", args["l0"])
	w("\t%s\tl1+%d(FP), R2", movPtr, args["l1"])
	w("\t%s\tl3+%d(FP), R3", movPtr, args["l3"])
	w("\t%s\tl5+%d(FP), R4", movPtr, args["l5"])
	w("\tADD\t$4, R2, R27")
	w("\tCMP\tR27, R21")
	w("\tBLO\tvdoob")
	w("\tADD\tR20, R2, R2")
	for i := 0; i < 4; i++ {
		e.movi0(i)
	}
	w("\tFMOVS\t$0.0, F24")
	w("\tCMPW\t$1, R1")
	w("\tBLT\tvdreduce")
	w("\tLSL\t$1, R1, R26")
	for _, r := range []int{3, 4} {
		w("\tADD\tR%d, R26, R27", r)
		w("\tCMP\tR27, R21")
		w("\tBLO\tvdoob")
	}
	w("\tADD\tR20, R3, R3")
	w("\tADD\tR20, R4, R4")
	w("vdloop16:")
	w("\tCMPW\t$16, R1")
	w("\tBLT\tvdtail4")
	e.ldurQ(4, 3, 0)
	e.ldurQ(5, 3, 16)
	e.ldurQ(6, 4, 0)
	e.ldurQ(7, 4, 16)
	e.fcvtl(16, 4)
	e.fcvtl2(17, 4)
	e.fcvtl(18, 5)
	e.fcvtl2(19, 5)
	e.fcvtl(20, 6)
	e.fcvtl2(21, 6)
	e.fcvtl(22, 7)
	e.fcvtl2(23, 7)
	for i := 0; i < 4; i++ {
		e.fmlaV(i, 16+i, 20+i)
	}
	w("\tADD\t$32, R3, R3")
	w("\tADD\t$32, R4, R4")
	w("\tSUBW\t$16, R1, R1")
	w("\tB\tvdloop16")
	w("vdtail4:")
	w("\tCMPW\t$4, R1")
	w("\tBLT\tvdtail1")
	e.ldurD(4, 3, 0)
	e.ldurD(6, 4, 0)
	e.fcvtl(16, 4)
	e.fcvtl(20, 6)
	e.fmlaV(0, 16, 20)
	w("\tADD\t$8, R3, R3")
	w("\tADD\t$8, R4, R4")
	w("\tSUBW\t$4, R1, R1")
	w("\tB\tvdtail4")
	w("vdtail1:")
	w("\tCBZW\tR1, vdreduce")
	e.ldurH(4, 3, 0)
	e.ldurH(6, 4, 0)
	e.fcvtSH(4, 4)
	e.fcvtSH(6, 6)
	e.fmaddS(24, 4, 6, 24)
	w("\tADD\t$2, R3, R3")
	w("\tADD\t$2, R4, R4")
	w("\tSUBW\t$1, R1, R1")
	w("\tB\tvdtail1")
	w("vdreduce:")
	e.faddV(0, 0, 1)
	e.faddV(2, 2, 3)
	e.faddV(0, 0, 2)
	e.faddpV(0, 0, 0)
	e.faddpS(0, 0)
	w("\tFADDS\tF24, F0, F0")
	w("\tFMOVS\tF0, (R2)")
	w("\tRET")
	w("vdoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}

// a64VecMadF16F32Kernel emits y[i] += v * x[i] (y f32, x f16) under
// sym: 16 elements per step, a 4-wide tail and a scalar tail. Bounds:
// y + 4n, x + 2n against memSize.
func a64VecMadF16F32Kernel(sym, trapSym string, offs *ModuleOffsets, _ *ConstPool, wide bool) string {
	var sb strings.Builder
	e := newA64VecF16(&sb)
	w := e.w
	args, argBytes := vecMadF16F32Args(wide)
	movPtr := "MOVWU"
	if wide {
		movPtr = "MOVD"
	}
	w("// %s: y += v * x (x f16, y f32).", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVW\tl0+%d(FP), R1", args["l0"])
	w("\tCMPW\t$1, R1")
	w("\tBLT\tvmdone")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\t%s\tl1+%d(FP), R2", movPtr, args["l1"])
	w("\t%s\tl2+%d(FP), R3", movPtr, args["l2"])
	w("\tFMOVS\tl3+%d(FP), F8", args["l3"])
	w("\tLSL\t$2, R1, R26")
	w("\tADD\tR2, R26, R27")
	w("\tCMP\tR27, R21")
	w("\tBLO\tvmoob")
	w("\tLSL\t$1, R1, R26")
	w("\tADD\tR3, R26, R27")
	w("\tCMP\tR27, R21")
	w("\tBLO\tvmoob")
	w("\tADD\tR20, R2, R2")
	w("\tADD\tR20, R3, R3")
	w("vmloop16:")
	w("\tCMPW\t$16, R1")
	w("\tBLT\tvmtail4")
	e.ldurQ(4, 3, 0)
	e.ldurQ(5, 3, 16)
	e.fcvtl(16, 4)
	e.fcvtl2(17, 4)
	e.fcvtl(18, 5)
	e.fcvtl2(19, 5)
	for i := 0; i < 4; i++ {
		e.ldurQ(20+i, 2, 16*i)
	}
	for i := 0; i < 4; i++ {
		e.fmlaLane(20+i, 16+i, 8, 0)
	}
	for i := 0; i < 4; i++ {
		e.sturQ(20+i, 2, 16*i)
	}
	w("\tADD\t$32, R3, R3")
	w("\tADD\t$64, R2, R2")
	w("\tSUBW\t$16, R1, R1")
	w("\tB\tvmloop16")
	w("vmtail4:")
	w("\tCMPW\t$4, R1")
	w("\tBLT\tvmtail1")
	e.ldurD(4, 3, 0)
	e.fcvtl(16, 4)
	e.ldurQ(20, 2, 0)
	e.fmlaLane(20, 16, 8, 0)
	e.sturQ(20, 2, 0)
	w("\tADD\t$8, R3, R3")
	w("\tADD\t$16, R2, R2")
	w("\tSUBW\t$4, R1, R1")
	w("\tB\tvmtail4")
	w("vmtail1:")
	w("\tCBZW\tR1, vmdone")
	e.ldurH(4, 3, 0)
	e.fcvtSH(4, 4)
	w("\tFMOVS\t(R2), F5")
	e.fmaddS(5, 4, 8, 5)
	w("\tFMOVS\tF5, (R2)")
	w("\tADD\t$2, R3, R3")
	w("\tADD\t$4, R2, R2")
	w("\tSUBW\t$1, R1, R1")
	w("\tB\tvmtail1")
	w("vmdone:")
	w("\tRET")
	w("vmoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return sb.String()
}
