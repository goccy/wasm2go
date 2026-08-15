package gcasm

import (
	"fmt"
	"strings"
)

// x64Nrc2Kernel emits the q8_0 2x2 tile kernel under sym for amd64,
// with an entry-time branch to a VNNI loop (VPDPBUSD, the
// single-instruction int8 dot; s8*s8 via the exact +128 bias identity)
// on CPUs reporting AVX-512 VNNI at 256-bit width —
// the AVX2 analog of a64Nrc2Kernel. Per 34-byte block the four quant
// vectors (rows x0/x1, columns y0/y1) load ONCE and feed all four dot
// products: sign-extend each 32-byte vector into two i16x16 ymm
// halves, VPMADDWD the four row/column pairs, and collapse the four
// i32x8 sums into one xmm holding the 2x2 tile [x0y0, x0y1, x1y0,
// x1y1] with three VPHADDD and a 128-fold — the AVX2 stand-in for
// SMMLA. The four f16 d scales gather through VPINSRW, convert with
// VCVTPH2PS (F16C), spread into the matching product matrix with two
// VPERMILPS, and accumulate via VFMADD231PS.
//
// The body is entirely VEX-encoded; ymm uppers are cleared with
// VZEROUPPER on every exit path (Intel dirty-upper false dependencies
// serialize legacy-SSE callers otherwise). Like the arm64 kernel this
// regroups float accumulation (FMA, single rounding), so the retarget
// is fast-math-only; the integer tile itself is exact. Callers gate on
// HasAVX2, whose detection also requires FMA and F16C.
//
// ABI0 stack args mirror the Go companion. ILP32: m+0, l0(n)+8,
// l1(s)+12, l2(bs, floats)+16, l3(x)+20, l4(bx)+24, l5(y)+28,
// l6(by)+32. LP64 (memory64): l1..l6 are int64, 8-aligned — l0+8,
// l1+16 .. l6+56. Results: s[0]=x0y0 s[1]=x1y0 s[bs]=x0y1 s[bs+1]=x1y1.
func x64Nrc2Kernel(sym, trapSym string, offs *ModuleOffsets, wide bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	argOff := map[string]int{"l1": 12, "l2": 16, "l3": 20, "l4": 24, "l5": 28, "l6": 32}
	movArg, argBytes := "MOVL", 36
	if wide {
		argOff = map[string]int{"l1": 16, "l2": 24, "l3": 32, "l4": 40, "l5": 48, "l6": 56}
		movArg, argBytes = "MOVQ", 64
	}
	arg := func(name, reg string) {
		w("\t%s\t%s+%d(FP), %s", movArg, name, argOff[name], reg)
	}
	// bounds emits: trap when memSize (R15) < end (endReg).
	bounds := func(endReg string) {
		w("\tCMPQ\tR15, %s", endReg)
		w("\tJCS\tnrc2x64oob")
	}

	w("// %s: q8_0 vec_dot 2x2 tile (rows x0/x1, cols y0/y1) via AVX2.", sym)
	w("TEXT ·%s(SB), $8-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVQ\tm+0(FP), AX")
	w("\tMOVQ\t%d(AX), R15", offs.MemSize)
	w("\tMOVQ\t(R15), R15")
	w("\tMOVQ\t%d(AX), R14", offs.M)
	w("\tMOVL\tl0+8(FP), R8")
	w("\tSHRL\t$5, R8")
	// span = nb*34 = nb*32 + nb*2
	w("\tMOVQ\tR8, R9")
	w("\tSHLQ\t$5, R9")
	w("\tLEAQ\t(R9)(R8*2), R9")
	// x0 / x1 spans against memSize
	arg("l3", "BX")
	w("\tLEAQ\t(BX)(R9*1), CX")
	bounds("CX")
	arg("l4", "DX")
	w("\tADDQ\tBX, DX") // x1 base = l3 + l4
	w("\tLEAQ\t(DX)(R9*1), CX")
	bounds("CX")
	// y0 / y1 spans
	arg("l5", "SI")
	w("\tLEAQ\t(SI)(R9*1), CX")
	bounds("CX")
	arg("l6", "DI")
	w("\tADDQ\tSI, DI") // y1 base = l5 + l6
	w("\tLEAQ\t(DI)(R9*1), CX")
	bounds("CX")
	// s spans: col0 [s, s+8), col1 [s+bs*4, s+bs*4+8)
	arg("l1", "R12")
	arg("l2", "R13")
	w("\tSHLQ\t$2, R13")
	w("\tLEAQ\t8(R12), CX")
	bounds("CX")
	w("\tLEAQ\t8(R12)(R13*1), CX")
	bounds("CX")
	// quant cursors: +2 past each block base (the f16 d scale sits at -2)
	w("\tLEAQ\t2(R14)(BX*1), BX")
	w("\tLEAQ\t2(R14)(DX*1), DX")
	w("\tLEAQ\t2(R14)(SI*1), SI")
	w("\tLEAQ\t2(R14)(DI*1), DI")
	w("\tVXORPS\tX8, X8, X8") // f32x4 tile accumulator
	w("\tTESTL\tR8, R8")
	w("\tJZ\tnrc2x64done")
	// tileTail emits the shared per-block finish: collapse the four
	// i32x8 sums (S00=Y13 S01=Y14 S10=Y15 S11=Y0) to the 2x2 tile in
	// one xmm, apply the f16 d-scale product matrix, FMA into the
	// accumulator, and advance the cursors.
	tileTail := func(loop string) {
		w("\tVPHADDD\tY14, Y13, Y1")
		w("\tVPHADDD\tY0, Y15, Y2")
		w("\tVPHADDD\tY2, Y1, Y1")
		w("\tVEXTRACTI128\t$1, Y1, X2")
		w("\tVPADDD\tX2, X1, X1")
		w("\tVCVTDQ2PS\tX1, X1")
		// Scales: [dx0, dx1, dy0, dy1] f16 -> f32, spread into the
		// product matrix [dx0dy0, dx0dy1, dx1dy0, dx1dy1] matching the
		// tile lanes.
		w("\tVPINSRW\t$0, -2(BX), X2, X2")
		w("\tVPINSRW\t$1, -2(DX), X2, X2")
		w("\tVPINSRW\t$2, -2(SI), X2, X2")
		w("\tVPINSRW\t$3, -2(DI), X2, X2")
		w("\tVCVTPH2PS\tX2, X2")
		w("\tVPERMILPS\t$0x50, X2, X3") // [dx0, dx0, dx1, dx1]
		w("\tVPERMILPS\t$0xEE, X2, X2") // [dy0, dy1, dy0, dy1]
		w("\tVMULPS\tX2, X3, X2")
		w("\tVFMADD231PS\tX2, X1, X8") // acc += tile * scales
		w("\tADDQ\t$34, BX")
		w("\tADDQ\t$34, DX")
		w("\tADDQ\t$34, SI")
		w("\tADDQ\t$34, DI")
		w("\tSUBL\t$1, R8")
		w("\tJNZ\t%s", loop)
		w("\tJMP\tnrc2x64done")
	}
	// Three of the four runner-pool CPU families carry AVX-512 VNNI at
	// 256-bit width (VL): VPDPBUSD is the single-instruction int8 dot
	// (the amd64 SDOT). One entry branch picks the loop; the s8*s8
	// products ride the exact bias identity
	// dot(x, y) = dot_u8s8(x^0x80, y) - 128*sum(y).
	w("\tCMPB\t·gcasmHasAVX512VNNI(SB), $0")
	w("\tJNE\tnrc2x64vnni")
	w("nrc2x64loop:")
	// Load the four 32-byte quant vectors once.
	w("\tVMOVDQU\t(BX), Y0")
	w("\tVMOVDQU\t(DX), Y1")
	w("\tVMOVDQU\t(SI), Y2")
	w("\tVMOVDQU\t(DI), Y3")
	// Sign-extend each into low/high i16x16 halves.
	w("\tVPMOVSXBW\tX0, Y4") // x0 lo
	w("\tVEXTRACTI128\t$1, Y0, X5")
	w("\tVPMOVSXBW\tX5, Y5") // x0 hi
	w("\tVPMOVSXBW\tX1, Y6") // x1 lo
	w("\tVEXTRACTI128\t$1, Y1, X7")
	w("\tVPMOVSXBW\tX7, Y7") // x1 hi
	w("\tVPMOVSXBW\tX2, Y9") // y0 lo
	w("\tVEXTRACTI128\t$1, Y2, X10")
	w("\tVPMOVSXBW\tX10, Y10") // y0 hi
	w("\tVPMOVSXBW\tX3, Y11")  // y1 lo
	w("\tVEXTRACTI128\t$1, Y3, X12")
	w("\tVPMOVSXBW\tX12, Y12") // y1 hi
	// Four dot products, each summing both halves.
	w("\tVPMADDWD\tY9, Y4, Y13")
	w("\tVPMADDWD\tY10, Y5, Y14")
	w("\tVPADDD\tY14, Y13, Y13") // S00
	w("\tVPMADDWD\tY11, Y4, Y14")
	w("\tVPMADDWD\tY12, Y5, Y15")
	w("\tVPADDD\tY15, Y14, Y14") // S01
	w("\tVPMADDWD\tY9, Y6, Y15")
	w("\tVPMADDWD\tY10, Y7, Y0")
	w("\tVPADDD\tY0, Y15, Y15") // S10
	w("\tVPMADDWD\tY11, Y6, Y0")
	w("\tVPMADDWD\tY12, Y7, Y1")
	w("\tVPADDD\tY1, Y0, Y0") // S11
	tileTail("nrc2x64loop")
	// VNNI loop: constants — u8 ones for sum(y), 0x80 bytes for the
	// sign-flip bias (0x01010101 << 7 per 32-bit lane = 0x80808080).
	w("nrc2x64vnni:")
	w("\tVPCMPEQD\tY4, Y4, Y4")
	w("\tVPABSB\tY4, Y4")     // 0x01 bytes
	w("\tVPSLLD\t$7, Y4, Y5") // 0x80 bytes
	w("nrc2x64vnniloop:")
	w("\tVMOVDQU\t(BX), Y0")
	w("\tVMOVDQU\t(DX), Y1")
	w("\tVMOVDQU\t(SI), Y2")
	w("\tVMOVDQU\t(DI), Y3")
	w("\tVPXOR\tY5, Y0, Y0") // x0 + 128 as u8
	w("\tVPXOR\tY5, Y1, Y1") // x1 + 128 as u8
	// Per-4-byte-group sums of y0/y1 (for the bias correction).
	w("\tVPXOR\tY6, Y6, Y6")
	w("\tVPDPBUSD\tY2, Y4, Y6") // sum y0
	w("\tVPXOR\tY7, Y7, Y7")
	w("\tVPDPBUSD\tY3, Y4, Y7") // sum y1
	w("\tVPSLLD\t$7, Y6, Y6")   // 128*sum(y0)
	w("\tVPSLLD\t$7, Y7, Y7")   // 128*sum(y1)
	// The four u8*s8 dots, then subtract the bias.
	w("\tVPXOR\tY13, Y13, Y13")
	w("\tVPDPBUSD\tY2, Y0, Y13")
	w("\tVPSUBD\tY6, Y13, Y13") // S00
	w("\tVPXOR\tY14, Y14, Y14")
	w("\tVPDPBUSD\tY3, Y0, Y14")
	w("\tVPSUBD\tY7, Y14, Y14") // S01
	w("\tVPXOR\tY15, Y15, Y15")
	w("\tVPDPBUSD\tY2, Y1, Y15")
	w("\tVPSUBD\tY6, Y15, Y15") // S10
	w("\tVPXOR\tY0, Y0, Y0")
	w("\tVPDPBUSD\tY3, Y1, Y0")
	w("\tVPSUBD\tY7, Y0, Y0") // S11
	tileTail("nrc2x64vnniloop")
	w("nrc2x64done:")
	// acc lanes [x0y0, x0y1, x1y0, x1y1]:
	// s[0]=lane0, s[1]=lane2, s[bs]=lane1, s[bs+1]=lane3.
	w("\tLEAQ\t(R12)(R13*1), CX")
	w("\tVEXTRACTPS\t$0, X8, (R14)(R12*1)")
	w("\tVEXTRACTPS\t$2, X8, 4(R14)(R12*1)")
	w("\tVEXTRACTPS\t$1, X8, (R14)(CX*1)")
	w("\tVEXTRACTPS\t$3, X8, 4(R14)(CX*1)")
	w("\tVZEROUPPER")
	w("\tRET")
	w("nrc2x64oob:")
	w("\tVZEROUPPER")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
