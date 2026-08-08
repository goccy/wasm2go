package gcasm

import (
	"fmt"
	"strings"
)

// Nrc2Spec names the ggml q8_0 vec_dot and its paired-tile companion
// (see codegen's traits recognition): under fast-math the arm64
// feature body's companion call is retargeted to a native 2x2 SMMLA
// tile kernel emitted by a64Nrc2Kernel.
type Nrc2Spec struct {
	VecDot    string
	Companion string
}

// a64Nrc2Kernel emits the q8_0 2x2 tile kernel under sym, following
// native ggml's __ARM_FEATURE_MATMUL_INT8 shape: per 34-byte block,
// both rows'/columns' quant halves are zipped into 2x8 matrices, the
// 2x2 tile accumulates through four SMMLA, and the f16 d-product
// vector scales it into a single f32 accumulator via vector FMLA.
// ABI0 stack args mirror the Go companion: m+0, l0(n)+8, l1(s)+12,
// l2(bs, floats)+16, l3(x)+20, l4(bx)+24, l5(y)+28, l6(by)+32.
// Results: s[0]=x0y0 s[1]=x1y0 s[bs]=x0y1 s[bs+1]=x1y1.
//
// Requires FEAT_I8MM; callers gate the retarget on the same dotprod
// feature dispatch that guards the SDOT bodies (see the bundle).
func a64Nrc2Kernel(sym, trapSym string, offs *ModuleOffsets) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	word := func(enc uint32, dis string) { w("\tWORD $0x%08x // %s", enc, dis) }
	ldurQ := func(rt, rn, imm int) {
		word(0x3CC00000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur q%d, [x%d, #%d]", rt, rn, imm))
	}
	ldurH := func(t, n, imm int) {
		word(0x7C400000|uint32(imm&0x1FF)<<12|uint32(n)<<5|uint32(t), fmt.Sprintf("ldur h%d, [x%d, #%d]", t, n, imm))
	}
	fcvtSH := func(d, n int) { word(0x1EE24000|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvt s%d, h%d", d, n)) }
	fmulS := func(d, n, m int) {
		word(0x1E200800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmul s%d, s%d, s%d", d, n, m))
	}
	zip1 := func(d, n, m int) {
		word(0x4EC03800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("zip1 v%d.2d, v%d.2d, v%d.2d", d, n, m))
	}
	zip2 := func(d, n, m int) {
		word(0x4EC07800|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("zip2 v%d.2d, v%d.2d, v%d.2d", d, n, m))
	}
	movi0 := func(d int) { word(0x4F000400|uint32(d), fmt.Sprintf("movi v%d.4s, #0", d)) }
	smmla := func(d, n, m int) {
		word(0x4E80A400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("smmla v%d.4s, v%d.16b, v%d.16b", d, n, m))
	}
	scvtf := func(d, n int) { word(0x4E21D800|uint32(n)<<5|uint32(d), fmt.Sprintf("scvtf v%d.4s, v%d.4s", d, n)) }
	fmlaV := func(d, n, m int) {
		word(0x4E20CC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmla v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	insS := func(d, i, n int) {
		word(0x6E000400|uint32((i<<3)|4)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("mov v%d.s[%d], v%d.s[0]", d, i, n))
	}
	umovW := func(d, n, i int) {
		word(0x0E003C00|uint32((i<<3)|4)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("mov w%d, v%d.s[%d]", d, n, i))
	}

	w("// %s: q8_0 vec_dot 2x2 tile (rows x0/x1, cols y0/y1) via SMMLA.", sym)
	w("TEXT ·%s(SB), $16-36", sym)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	w("\tMOVW\tl0+8(FP), R8")
	w("\tLSRW\t$5, R8, R8")
	// span = nb*34
	w("\tLSL\t$5, R8, R27")
	w("\tADD\tR8<<1, R27, R27")
	// x0 / x1 spans
	w("\tMOVWU\tl3+20(FP), R4")
	w("\tADD\tR4, R27, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tnrc2oob")
	w("\tMOVWU\tl4+24(FP), R9")
	w("\tADD\tR4, R9, R10")
	w("\tADD\tR10, R27, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tnrc2oob")
	// y0 / y1 spans
	w("\tMOVWU\tl5+28(FP), R6")
	w("\tADD\tR6, R27, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tnrc2oob")
	w("\tMOVWU\tl6+32(FP), R12")
	w("\tADD\tR6, R12, R13")
	w("\tADD\tR13, R27, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tnrc2oob")
	// s spans: col0 [s, s+8), col1 [s+bs*4, s+bs*4+8)
	w("\tMOVWU\tl1+12(FP), R11")
	w("\tMOVWU\tl2+16(FP), R14")
	w("\tLSL\t$2, R14, R14")
	w("\tADD\t$8, R11, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tnrc2oob")
	w("\tADD\tR11, R14, R26")
	w("\tADD\t$8, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tnrc2oob")
	// pointers (quant cursors +2 past the block base; d scale at -2)
	w("\tADD\tR4, R20, R4")
	w("\tADD\t$2, R4, R4")
	w("\tADD\tR10, R20, R5")
	w("\tADD\t$2, R5, R5")
	w("\tADD\tR6, R20, R6")
	w("\tADD\t$2, R6, R6")
	w("\tADD\tR13, R20, R7")
	w("\tADD\t$2, R7, R7")
	w("\tADD\tR11, R20, R11")
	movi0(30)
	w("\tCBZW\tR8, nrc2done")
	w("nrc2loop:")
	ldurQ(16, 4, 0)
	ldurQ(17, 4, 16)
	ldurQ(18, 5, 0)
	ldurQ(19, 5, 16)
	ldurQ(20, 6, 0)
	ldurQ(21, 6, 16)
	ldurQ(22, 7, 0)
	ldurQ(23, 7, 16)
	zip1(24, 16, 18)
	zip2(25, 16, 18)
	zip1(26, 17, 19)
	zip2(27, 17, 19)
	zip1(0, 20, 22)
	zip2(1, 20, 22)
	zip1(2, 21, 23)
	zip2(3, 21, 23)
	movi0(4)
	smmla(4, 24, 0)
	smmla(4, 25, 1)
	smmla(4, 26, 2)
	smmla(4, 27, 3)
	scvtf(4, 4)
	ldurH(5, 4, -2)
	fcvtSH(5, 5)
	ldurH(6, 5, -2)
	fcvtSH(6, 6)
	ldurH(7, 6, -2)
	fcvtSH(7, 7)
	ldurH(16, 7, -2)
	fcvtSH(16, 16)
	fmulS(17, 5, 7)
	fmulS(18, 5, 16)
	fmulS(19, 6, 7)
	fmulS(20, 6, 16)
	insS(17, 1, 18)
	insS(17, 2, 19)
	insS(17, 3, 20)
	fmlaV(30, 4, 17)
	w("\tADD\t$34, R4, R4")
	w("\tADD\t$34, R5, R5")
	w("\tADD\t$34, R6, R6")
	w("\tADD\t$34, R7, R7")
	w("\tSUBS\t$1, R8, R8")
	w("\tBNE\tnrc2loop")
	w("nrc2done:")
	// acc lanes [x0y0, x0y1, x1y0, x1y1]
	umovW(13, 30, 0)
	w("\tMOVW\tR13, (R11)")
	umovW(13, 30, 2)
	w("\tMOVW\tR13, 4(R11)")
	w("\tADD\tR11, R14, R15")
	umovW(13, 30, 1)
	w("\tMOVW\tR13, (R15)")
	umovW(13, 30, 3)
	w("\tMOVW\tR13, 4(R15)")
	w("\tRET")
	w("nrc2oob:")
	w("\tCALL ·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
