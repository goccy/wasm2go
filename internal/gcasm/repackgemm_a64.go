package gcasm

import (
	"fmt"
	"strings"
)

// a64RepackGemmKernel emits the q8_0x4 repack GEMM under sym: the
// 4-rows x 4-columns tile the native q8_0_4x4 dotprod path computes,
// replacing the engine's four sequential gemv-shaped passes. The wasm
// activation block (block_q8_0x4) already interleaves the four rows'
// 4-byte groups contiguously, so each 16-byte weight group pairs with
// ONE 16-byte activation load and four BY-ELEMENT SDOTs:
//
//	sdot vAcc_r.4s, vWeights.16b, vActs.4b[r]
//
// — one instruction per (weight group, row), the native kernel's own
// shape. Per block the four per-row i32x4 column sums convert once,
// scale by d_col[4]*d_row (FMUL by element + vector FMLA), and
// accumulate into four f32x4 row accumulators that store once per
// column group. Integer arithmetic is exact, and the f32 tail keeps
// the wasm gemm's own multiply/multiply/add sequence and rounding —
// the same sequence the fused GEMV loops execute — so the batched
// and single-row paths stay as close as the wasm semantics themselves
// (prompt batch-size invariance depends on it). FastMath-gated only
// because the retarget replaces the verified wasm lowering wholesale.
//
// C signature (see llama-wasm's arch/wasm/repack.cpp):
//
//	gemm(int n, float *s, size_t bs, void *vx, void *vy, int nr, int nc)
//
// with n%32==0, nr%4==0, nc%4==0 by the caller's contract; memory
// safety does not rely on that contract — every span the loops will
// touch is bounds-checked against memSize at entry.
//
// ABI0 stack args mirror the transformed Go body. ILP32: m+0,
// l0(n)+8, l1(s)+12, l2(bs)+16, l3(vx)+20, l4(vy)+24, l5(nr)+28,
// l6(nc)+32. LP64: l1..l4 are int64, 8-aligned — l0+8, l1+16, l2+24,
// l3+32, l4+40, l5(nr)+48, l6(nc)+52.
//
// Requires FEAT_DotProd; callers gate the retarget on the dotprod
// feature dispatch that guards the SDOT bodies.
func a64RepackGemmKernel(sym, trapSym string, offs *ModuleOffsets, wide bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	word := func(enc uint32, dis string) { w("\tWORD $0x%08x // %s", enc, dis) }
	ldurQ := func(rt, rn, imm int) {
		word(0x3CC00000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur q%d, [x%d, #%d]", rt, rn, imm))
	}
	sturQ := func(rt, rn, imm int) {
		word(0x3C800000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("stur q%d, [x%d, #%d]", rt, rn, imm))
	}
	ldurD := func(rt, rn, imm int) {
		word(0xFC400000|uint32(imm&0x1FF)<<12|uint32(rn)<<5|uint32(rt), fmt.Sprintf("ldur d%d, [x%d, #%d]", rt, rn, imm))
	}
	movi0 := func(d int) { word(0x4F000400|uint32(d), fmt.Sprintf("movi v%d.4s, #0", d)) }
	// SDOT (by element, 4S): acc.4s += dot4(weights.16b per lane,
	// acts.4b[idx]).
	sdotLane := func(d, n, m, idx int) {
		enc := 0x4F80E000 | uint32(idx&1)<<21 | uint32(idx>>1)<<11 | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
		word(enc, fmt.Sprintf("sdot v%d.4s, v%d.16b, v%d.4b[%d]", d, n, m, idx))
	}
	fcvtl := func(d, n int) { word(0x0E217800|uint32(n)<<5|uint32(d), fmt.Sprintf("fcvtl v%d.4s, v%d.4h", d, n)) }
	scvtf := func(d, n int) { word(0x4E21D800|uint32(n)<<5|uint32(d), fmt.Sprintf("scvtf v%d.4s, v%d.4s", d, n)) }
	fmulLane := func(d, n, m, idx int) {
		enc := 0x4F809000 | uint32(idx&1)<<21 | uint32(idx>>1)<<11 | uint32(m)<<16 | uint32(n)<<5 | uint32(d)
		word(enc, fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.s[%d]", d, n, m, idx))
	}
	fmulV := func(d, n, m int) {
		word(0x6E20DC00|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fmul v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}
	faddV := func(d, n, m int) {
		word(0x4E20D400|uint32(m)<<16|uint32(n)<<5|uint32(d), fmt.Sprintf("fadd v%d.4s, v%d.4s, v%d.4s", d, n, m))
	}

	argOff := map[string]int{"l1": 12, "l2": 16, "l3": 20, "l4": 24, "l5": 28, "l6": 32}
	movArg, argBytes := "MOVWU", 36
	if wide {
		argOff = map[string]int{"l1": 16, "l2": 24, "l3": 32, "l4": 40, "l5": 48, "l6": 52}
		movArg, argBytes = "MOVD", 56
	}
	arg := func(name string, reg int) {
		mv := movArg
		if name == "l5" || name == "l6" {
			mv = "MOVWU" // nr/nc stay int32 at either width
		}
		w("\t%s\t%s+%d(FP), R%d", mv, name, argOff[name], reg)
	}

	w("// %s: q8_0x4 repack GEMM, 4x4 tile via by-element SDOT.", sym)
	w("TEXT ·%s(SB), $16-%d", sym, argBytes)
	w("\tNO_LOCAL_POINTERS")
	w("\tMOVD\tm+0(FP), R0")
	w("\tMOVD\t%d(R0), R21", offs.MemSize)
	w("\tMOVD\t(R21), R21")
	w("\tMOVD\t%d(R0), R20", offs.M)
	// nb = n >> 5; xtotal = nb*136 (the per-column-group byte span:
	// nb interleaved blocks of 8-byte scales + 128-byte quants).
	w("\tMOVW\tl0+8(FP), R1")
	w("\tLSRW\t$5, R1, R1")
	w("\tMOVD\t$136, R8")
	w("\tMUL\tR1, R8, R8")
	arg("l5", 6)
	w("\tLSRW\t$2, R6, R6") // nr/4
	arg("l6", 7)
	w("\tLSRW\t$2, R7, R7") // nc/4
	// Empty problem: nothing is read or written.
	w("\tCBZW\tR6, gemmdone")
	w("\tCBZW\tR7, gemmdone")
	// Bounds: vx + nc4*xtotal, vy + nr4*xtotal, and the last store
	// byte s + ((nr-1)*bs + nc)*4 must all sit inside memSize.
	arg("l3", 4)
	w("\tMUL\tR7, R8, R26")
	w("\tADD\tR4, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgemmoob")
	arg("l4", 5)
	w("\tMUL\tR6, R8, R26")
	w("\tADD\tR5, R26, R26")
	w("\tCMP\tR26, R21")
	w("\tBLO\tgemmoob")
	arg("l1", 2)
	arg("l2", 3)
	w("\tLSL\t$2, R3, R3") // bs in bytes
	w("\tLSL\t$2, R6, R9")
	w("\tSUB\t$1, R9, R9") // nr-1
	w("\tMUL\tR3, R9, R26")
	w("\tADD\tR2, R26, R26")
	w("\tLSL\t$4, R7, R9")
	w("\tADD\tR9, R26, R26") // + nc*4 bytes
	w("\tCMP\tR26, R21")
	w("\tBLO\tgemmoob")
	// Host pointers: activations row-group cursor, output row cursor.
	w("\tADD\tR20, R5, R10") // a base (host)
	w("\tADD\tR20, R2, R11") // s row base (host)
	w("\tADD\tR20, R4, R22") // vx base (host)
	w("\tLSL\t$2, R3, R23")  // 4*bs bytes: s row-group stride
	w("gemmy:")
	w("\tMOVD\tR22, R13") // b column-group cursor
	w("\tMOVD\tR11, R14") // s column cursor
	w("\tMOVD\tR7, R12")  // x counter
	w("gemmx:")
	movi0(28)
	movi0(29)
	movi0(30)
	movi0(31)
	w("\tMOVD\tR13, R16") // bp
	w("\tMOVD\tR10, R17") // ap
	w("\tMOVD\tR1, R15")  // block counter
	w("\tCBZW\tR15, gemmstore")
	w("gemmblk:")
	movi0(24)
	movi0(25)
	movi0(26)
	movi0(27)
	for k := 0; k < 8; k++ {
		ldurQ(0, 16, 8+16*k)
		ldurQ(1, 17, 8+16*k)
		sdotLane(24, 0, 1, 0)
		sdotLane(25, 0, 1, 1)
		sdotLane(26, 0, 1, 2)
		sdotLane(27, 0, 1, 3)
	}
	// Scales: column d[4] and row d[4] (f16 -> f32), then per row
	// sumv_r += f32(acc_r) * (dcol * drow[r]).
	ldurD(2, 16, 0)
	fcvtl(2, 2)
	ldurD(3, 17, 0)
	fcvtl(3, 3)
	scvtf(24, 24)
	scvtf(25, 25)
	scvtf(26, 26)
	scvtf(27, 27)
	fmulLane(4, 2, 3, 0)
	fmulV(5, 24, 4)
	faddV(28, 28, 5)
	fmulLane(4, 2, 3, 1)
	fmulV(5, 25, 4)
	faddV(29, 29, 5)
	fmulLane(4, 2, 3, 2)
	fmulV(5, 26, 4)
	faddV(30, 30, 5)
	fmulLane(4, 2, 3, 3)
	fmulV(5, 27, 4)
	faddV(31, 31, 5)
	w("\tADD\t$136, R16, R16")
	w("\tADD\t$136, R17, R17")
	w("\tSUBW\t$1, R15, R15")
	w("\tCBNZW\tR15, gemmblk")
	w("gemmstore:")
	sturQ(28, 14, 0)
	w("\tADD\tR14, R3, R26")
	sturQ(29, 26, 0)
	w("\tADD\tR26, R3, R26")
	sturQ(30, 26, 0)
	w("\tADD\tR26, R3, R26")
	sturQ(31, 26, 0)
	w("\tADD\tR8, R13, R13")  // next column group's weights
	w("\tADD\t$16, R14, R14") // next 4 output floats
	w("\tSUBW\t$1, R12, R12")
	w("\tCBNZW\tR12, gemmx")
	w("\tADD\tR8, R10, R10")  // next activation row group
	w("\tADD\tR23, R11, R11") // next 4 output rows
	w("\tSUBW\t$1, R6, R6")
	w("\tCBNZW\tR6, gemmy")
	w("gemmdone:")
	w("\tRET")
	w("gemmoob:")
	w("\tCALL\t·%s(SB)", trapSym)
	w("\tRET")
	return b.String()
}
